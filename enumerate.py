#!/usr/bin/env python3
"""
enumerate.py — Auxiliary-based service enumeration.

Reads the services of a Metasploit workspace, and for each one runs the mapped
enumeration auxiliary modules (read-only scanners, no brute-force). The clean
output of each module is stored in our SQLite database (db.py).

Usage:
    python3 enumerate.py <workspace>              # run enumeration
    python3 enumerate.py <workspace> --dry-run    # just show what WOULD run

Requires: scan_import.py run first (so the workspace has services),
          and the msgrpc server running.

Legal note: only against systems you own or have written authorization to test.
"""

import os
import sys
import time

import yaml
from dotenv import load_dotenv
from pymetasploit3.msfrpc import MsfRpcClient

import db  # our storage layer


# ---------------------------------------------------------------------------
# Module map is loaded from enum_modules.yaml (data, not code) so you can edit
# which auxiliaries run without touching this script.
# ---------------------------------------------------------------------------
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "enum_modules.yaml")


def load_config():
    """Loads the service -> modules map from the YAML file.

    Returns:
        enum_modules: {service: [module, ...]}
        no_rport:     set of services whose modules reject RPORT
    """
    try:
        with open(CONFIG_FILE) as f:
            cfg = yaml.safe_load(f) or {}
    except FileNotFoundError:
        sys.exit(f"[!] Config not found: {CONFIG_FILE}")
    except yaml.YAMLError as e:
        sys.exit(f"[!] Invalid YAML in {CONFIG_FILE}:\n{e}")

    enum_modules = {}
    no_rport = set()
    for service, spec in cfg.items():
        if not isinstance(spec, dict):
            continue
        enum_modules[service] = spec.get("modules", []) or []
        if spec.get("no_rport"):
            no_rport.add(service)
    return enum_modules, no_rport


# Loaded once at import
ENUM_MODULES, NO_RPORT_SERVICES = load_config()


# Special cases: raw nmap names that don't match a YAML key directly.
# Everything else falls through to a direct match against the YAML keys below,
# so adding a simple service (ftp, mysql, smtp...) needs only a YAML entry.
SERVICE_ALIASES = {
    "netbios-ssn": "smb",
    "microsoft-ds": "smb",
    "ssl/https": "https",
    "ssl/http": "https",
}


def normalize_service(name):
    """Maps a raw msf service name to a YAML key (or None if unmapped).

    1. Known aliases first (netbios-ssn -> smb, ssl/https -> https).
    2. Then "https"/"http" substrings (covers http-proxy, http-alt, etc).
    3. Finally, a direct match: if the raw name IS a key in the YAML config
       (ftp, ssh, mysql, smtp...), use it as-is. This means most services
       work by just adding them to enum_modules.yaml — no code change.
    """
    if not name:
        return None
    n = name.lower()

    if n in SERVICE_ALIASES:
        return SERVICE_ALIASES[n]
    if "https" in n:
        return "https"
    if "http" in n:
        return "http"
    if n in ENUM_MODULES:        # direct match against YAML keys
        return n
    return None


# ---------------------------------------------------------------------------
# msf connection + console execution
# ---------------------------------------------------------------------------
def connect_msf():
    load_dotenv()
    try:
        return MsfRpcClient(
            os.getenv("MSF_RPC_PASS"),
            server=os.getenv("MSF_RPC_HOST", "127.0.0.1"),
            port=int(os.getenv("MSF_RPC_PORT", "55552")),
            ssl=os.getenv("MSF_RPC_SSL", "true").lower() == "true",
        )
    except Exception as e:
        sys.exit(f"[!] Failed to connect to the RPC API: {e}\n"
                 f"    Is msgrpc running? (load msgrpc in msfconsole)")


def get_services(client, workspace):
    result = client.call("db.services", [{"workspace": workspace}])
    if isinstance(result, dict) and result.get("error"):
        sys.exit(f"[!] Could not read services: {result.get('error_message')}")
    return result.get("services", [])


def _drain(console):
    """Reads and discards whatever is currently in the console buffer."""
    time.sleep(0.5)
    while True:
        r = console.read()
        if not r.get("data") and not r.get("busy"):
            break
        time.sleep(0.3)


def _clean_output(raw):
    """Keeps only useful module lines, dropping banner/prompt/echo noise."""
    useful = []
    for line in raw.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith(("[*]", "[+]", "[-]", "[!]")):
            useful.append(s)
        elif "=>" in s:          # "RHOSTS => ..." echo — skip
            continue
        else:
            useful.append(line.rstrip())  # table rows / detail lines
    return "\n".join(useful)


# Service names that our own auxiliaries add to the msf DB as noise, not real
# nmap results. When deduping ports we prefer a real name over these.
JUNK_NAMES = {"", "tcp", "udp", "?", "dcerpc", "smb"}


def dedup_services(services):
    """Keeps ONE row per port, preferring the most informative one.

    The msf DB often holds several rows for the same port: the real nmap entry
    (e.g. "netbios-ssn") plus artifacts our own modules added ("dcerpc", "smb",
    "tcp", blank). We keep, per port, the row with a real service name and the
    most info — so the ports table shows each port once, correctly.
    """
    best = {}  # port -> chosen svc dict

    def score(svc):
        name = (svc.get("name") or "").lower()
        info = svc.get("info") or ""
        s = 0
        if name not in JUNK_NAMES:
            s += 10            # real service name is worth the most
        if info:
            s += 1             # having version/banner info breaks ties
        return s

    for svc in services:
        port = svc.get("port")
        if port not in best or score(svc) > score(best[port]):
            best[port] = svc

    # Return sorted by port for a tidy table
    return [best[p] for p in sorted(best, key=lambda x: (x is None, x))]


def run_module(client, module, rhosts, rport, service):
    """Runs one auxiliary in a fresh console, returns its CLEAN output.

    RPORT is set only when the service's modules actually use it. SMB modules,
    for example, reject RPORT and handle 139/445 themselves.
    """
    console = client.consoles.console()
    _drain(console)  # clear the welcome banner first

    cmds = f"use auxiliary/{module}\nset RHOSTS {rhosts}\n"
    if service not in NO_RPORT_SERVICES:
        cmds += f"set RPORT {rport}\n"
    cmds += "run\n"

    console.write(cmds)

    raw = ""
    for _ in range(90):  # up to ~90s (dir_scanner can take a while)
        time.sleep(1)
        r = console.read()
        raw += r.get("data", "")
        if not r.get("busy", False):
            time.sleep(1)
            raw += console.read().get("data", "")
            break

    console.destroy()
    return _clean_output(raw)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    if len(args) != 1:
        sys.exit("Usage: python3 enumerate.py <workspace> [--dry-run]")
    workspace = args[0]

    client = connect_msf()
    services = get_services(client, workspace)
    if not services:
        sys.exit(f"[!] No services in workspace '{workspace}'. Run scan_import.py first.")

    # Build the work list: (host, port, normalized_service, module)
    # For port-agnostic services (SMB), the same host+module on 139 and 445
    # gives identical results, so we run it once. We dedupe on a key that
    # ignores the port for those services.
    plan = []
    seen = set()
    for svc in services:
        host = svc.get("host", "?")
        port = svc.get("port", "?")
        raw_name = svc.get("name", "")
        norm = normalize_service(raw_name)
        if not (norm and norm in ENUM_MODULES):
            continue
        for module in ENUM_MODULES[norm]:
            # For SMB, key ignores port (139/445 are the same target)
            key_port = "*" if norm in NO_RPORT_SERVICES else port
            key = (host, key_port, module)
            if key in seen:
                continue
            seen.add(key)
            plan.append((host, port, norm, module))

    if not plan:
        sys.exit(f"[!] No enumeration modules matched the services in '{workspace}'.")

    print(f"[*] Workspace '{workspace}': {len(plan)} module execution(s) planned.\n")

    # --- Dry run: just show the plan ---
    if dry_run:
        for host, port, norm, module in plan:
            print(f"  would run auxiliary/{module}  ->  {host}:{port} ({norm})")
        print(f"\n[*] Dry run. Nothing was executed.")
        return

    # --- Real run: execute each module, collect findings ---
    db.init_db()
    db.clear_workspace(workspace)  # replace strategy: wipe old findings first

    # Save the target's services (one clean row per port) so the viewer can
    # show the full port picture. Mark which ports we actually enumerate.
    enum_ports = {(h, p) for (h, p, _, _) in plan}
    svc_rows = []
    for svc in dedup_services(services):
        host = svc.get("host", "?")
        port = svc.get("port")
        svc_rows.append({
            "workspace": workspace,
            "target": host,
            "port": port,
            "proto": svc.get("proto", "tcp"),
            "name": svc.get("name", ""),
            "info": svc.get("info", ""),
            "enumerated": 1 if (host, port) in enum_ports else 0,
        })
    db.clear_services(workspace)
    db.save_services(svc_rows)

    findings = []
    for i, (host, port, norm, module) in enumerate(plan, 1):
        short = module.split("/")[-1]
        print(f"[{i}/{len(plan)}] {short} -> {host}:{port} ...", flush=True)
        try:
            output = run_module(client, module, host, port, norm)
        except Exception as e:
            output = f"[!] module error: {e}"

        findings.append({
            "workspace": workspace,
            "target": host,
            "port": port,
            "service": norm,
            "module": short,
            "finding_type": "raw",      # structured parsing comes later
            "value": output[:200],      # short preview for quick listing
            "raw_output": output,       # full clean output
        })

    db.save_findings(findings)
    print(f"\n[+] Done. {len(findings)} result(s) saved to the database.")
    print(f"    View them in the browser:  python3 app.py  "
          f"(then open http://127.0.0.1:5000)")


if __name__ == "__main__":
    main()