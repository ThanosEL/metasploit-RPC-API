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

from dotenv import load_dotenv
from pymetasploit3.msfrpc import MsfRpcClient

import db  # our storage layer


# ---------------------------------------------------------------------------
# Module map: normalized service -> ENUMERATION auxiliaries (read-only only).
# Expand as needed.
# ---------------------------------------------------------------------------
ENUM_MODULES = {
    "smb": [
        "scanner/smb/smb_version",
        "scanner/smb/smb_enumshares",
        "scanner/smb/smb_enumusers",
    ],
    "http": [
        "scanner/http/http_version",
        "scanner/http/http_header",
        "scanner/http/robots_txt",
        "scanner/http/dir_scanner",
    ],
    "https": [
        "scanner/http/http_version",
        "scanner/http/http_header",
        "scanner/http/robots_txt",
        "scanner/http/dir_scanner",
    ],
    "ssh": [
        "scanner/ssh/ssh_version",
    ],
}


def normalize_service(name):
    """Maps a raw msf service name to a normalized key (or None if unknown)."""
    if not name:
        return None
    n = name.lower()
    if "netbios" in n or "microsoft-ds" in n or n == "smb":
        return "smb"
    if "https" in n or n == "ssl/http":
        return "https"
    if "http" in n:
        return "http"
    if "ssh" in n:
        return "ssh"
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


def run_module(client, module, rhosts, rport):
    """Runs one auxiliary in a fresh console, returns its CLEAN output."""
    console = client.consoles.console()
    _drain(console)  # clear the welcome banner first

    console.write(
        f"use auxiliary/{module}\n"
        f"set RHOSTS {rhosts}\n"
        f"set RPORT {rport}\n"
        f"run\n"
    )

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
    plan = []
    for svc in services:
        host = svc.get("host", "?")
        port = svc.get("port", "?")
        raw_name = svc.get("name", "")
        norm = normalize_service(raw_name)
        if norm and norm in ENUM_MODULES:
            for module in ENUM_MODULES[norm]:
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
    db.clear_workspace(workspace)  # replace strategy: wipe old rows first

    findings = []
    for i, (host, port, norm, module) in enumerate(plan, 1):
        short = module.split("/")[-1]
        print(f"[{i}/{len(plan)}] {short} -> {host}:{port} ...", flush=True)
        try:
            output = run_module(client, module, host, port)
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
    print(f"    View them with:  python3 view.py {workspace}")


if __name__ == "__main__":
    main()