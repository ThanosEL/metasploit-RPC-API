#!/usr/bin/env python3
"""
scan_import.py — Automation: fast Go port scan -> nmap -sV -> Metasploit

Usage:
    python scan_import.py <target_ip_or_domain> [--full]

    Accepts an IP or a domain name (domains are resolved to an IP).
    --full          Go scanner sweeps all ports 1-65535 (default is 1-1024)
    --name <name>   Workspace name (default: the target IP/domain)

What it does, in order:
    0. Resolves the target if it's a domain (workspace keeps the readable name)
    1. Runs the fast Go port scanner to find OPEN ports (e.g. 22,80,443)
    2. Runs nmap -sV ONLY on those open ports (much faster than scanning all)
    3. Creates (or reuses) a workspace named after the target IP
    4. Imports the nmap XML into the database, inside that workspace
    5. Sets RHOSTS = target (global) so the next modules have it ready
    6. Prints a short summary of the hosts/services found

Requires the Go scanner built as ./portscan (go build -o portscan portscan.go)

Legal note: only against systems you own or have written authorization to test.
"""

import os
import sys
import time
import socket
import ipaddress
import subprocess
import tempfile
import threading

from tqdm import tqdm
from dotenv import load_dotenv
from pymetasploit3.msfrpc import MsfRpcClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_target(target):
    """Accepts an IP or a domain name and returns (label, ip).

    - label: the original input (IP or domain), used for the workspace name
      so it stays human-readable.
    - ip: the resolved IP address, used for scanning and RHOSTS, since some
      Metasploit modules prefer an IP and it avoids repeated DNS lookups.
    """
    # Already a valid IP? Use it as-is for both.
    try:
        ipaddress.ip_address(target)
        return target, target
    except ValueError:
        pass

    # Otherwise treat it as a hostname and resolve it.
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit(f"[!] '{target}' is not a valid IP and could not be resolved.")

    print(f"[*] Resolved {target} -> {ip}")
    return target, ip


def fast_port_scan(target, full=False):
    """Runs the Go port scanner and returns the open ports as a string.

    The Go binary does a fast concurrent sweep and prints the open ports on
    stdout as a comma-separated line (e.g. "22,80,443"). Progress messages go
    to stderr, so we only read stdout here. Returns e.g. "22,80,443", or None
    if nothing was found.
    """
    # The binary lives next to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary = os.path.join(script_dir, "portscan")

    if not os.path.exists(binary):
        sys.exit("[!] portscan binary not found. Build it first:\n"
                 "    go build -o portscan portscan.go")

    cmd = [binary, target]
    if full:
        cmd += ["1", "65535"]   # full range
    # else: the Go scanner defaults to 1-1024

    print(f"[*] Fast port scan on {target} "
          f"({'full 1-65535' if full else 'ports 1-1024'}) ...")

    try:
        # stderr is inherited (so you see the Go progress live);
        # stdout is captured (that's the port list we need)
        proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                              text=True, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] Port scan failed (exit {e.returncode}).")

    ports = proc.stdout.strip()
    if not ports:
        return None

    print(f"[+] Open ports: {ports}")
    return ports


def run_nmap(target, xml_path, ports=None):
    """Runs nmap service detection, showing a live spinner while it works.

    If `ports` is given (e.g. "22,80,443"), nmap only deep-scans those ports,
    which is much faster than scanning the whole range — this is the payoff of
    the fast Go pre-scan. Otherwise nmap uses its own defaults.

    nmap doesn't report a total, so instead of a percentage bar we animate a
    bar that sweeps back and forth while the scan runs, so you can see it's
    alive and how long it's taken.
    """
    nmap_cmd = ["nmap", "-sV", "-T4"]
    if ports:
        nmap_cmd += ["-p", ports]
    nmap_cmd += ["-oX", xml_path, target]

    scope = f"ports {ports}" if ports else "default ports"
    print(f"[*] Running nmap -sV against {target} ({scope}) ...")

    # Holds the finished process (or an exception) from the worker thread
    result = {}

    def worker():
        try:
            result["proc"] = subprocess.run(
                nmap_cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except Exception as e:  # noqa: BLE001 - re-raised in main thread below
            result["error"] = e

    t = threading.Thread(target=worker)
    t.start()

    # nmap gives no total, so we animate a bar that sweeps back and forth
    # (like a loading indicator) while the scan runs. The count is cosmetic.
    width = 30          # how many "cells" the bar has
    pos = 0
    direction = 1
    with tqdm(total=width, desc="    nmap scanning",
              bar_format="{desc} [{elapsed}] |{bar}|",
              leave=False) as bar:
        while t.is_alive():
            time.sleep(0.2)
            pos += direction
            if pos >= width or pos <= 0:
                direction *= -1   # bounce back at the edges
            bar.n = pos
            bar.refresh()

    t.join()

    # Surface any error that happened inside the thread
    err = result.get("error")
    if isinstance(err, FileNotFoundError):
        sys.exit("[!] nmap not found. Install it: sudo apt install nmap")
    if isinstance(err, subprocess.CalledProcessError):
        sys.exit(f"[!] nmap failed:\n{err.stderr}")
    if err is not None:
        sys.exit(f"[!] nmap error: {err}")

    print("[+] nmap finished.")


def connect_msf():
    """Connects to the RPC API, reading credentials from .env."""
    load_dotenv()
    try:
        client = MsfRpcClient(
            os.getenv("MSF_RPC_PASS"),
            server=os.getenv("MSF_RPC_HOST", "127.0.0.1"),
            port=int(os.getenv("MSF_RPC_PORT", "55552")),
            ssl=os.getenv("MSF_RPC_SSL", "true").lower() == "true",
        )
        return client
    except Exception as e:
        sys.exit(f"[!] Failed to connect to the RPC API: {e}\n"
                 f"    Is msgrpc running? (load msgrpc in msfconsole)")


def ensure_workspace(client, name):
    """Creates the workspace if it doesn't exist, then switches to it."""
    existing = client.call("db.workspaces", [])
    names = [w["name"] for w in existing.get("workspaces", [])]

    if name in names:
        print(f"[*] Workspace '{name}' already exists — reusing it.")
    else:
        client.call("db.add_workspace", [name])
        print(f"[+] Created workspace '{name}'.")

    client.call("db.set_workspace", [name])


def import_scan(client, name, xml_path):
    """Reads the XML and imports it into the given workspace."""
    with open(xml_path, "r") as f:
        xml_data = f.read()

    client.call("db.import_data", [{"workspace": name, "data": xml_data}])
    print("[+] Scan imported into the database.")


def set_rhosts(client, target):
    """Sets RHOSTS global = target, for the next modules."""
    client.call("core.setg", ["RHOSTS", target])
    print(f"[+] RHOSTS = {target} (global).")


def summarize(client, name):
    """Prints a short summary: hosts and open services."""
    hosts = client.call("db.hosts", [{"workspace": name}])
    services = client.call("db.services", [{"workspace": name}])

    print("\n===== Summary =====")
    print(f"Workspace: {name}")

    host_list = hosts.get("hosts", [])
    print(f"Hosts: {len(host_list)}")
    for h in host_list:
        addr = h.get("address", "?")
        os_name = h.get("os_name", "unknown")
        print(f"  - {addr}  ({os_name})")

    svc_list = services.get("services", [])
    print(f"Open services: {len(svc_list)}")
    for s in svc_list:
        port = s.get("port", "?")
        proto = s.get("proto", "")
        sname = s.get("name", "")
        info = s.get("info", "")
        print(f"  - {port}/{proto}  {sname}  {info}".rstrip())
    print("===================\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

USAGE = "Usage: python scan_import.py <target_ip_or_domain> [--full] [--name <workspace>]"


def main():
    # Arg handling: <target> [--full] [--name/-n <workspace>]
    args = sys.argv[1:]

    full = "--full" in args
    args = [a for a in args if a != "--full"]

    # Pull out --name / -n and its value, if present
    ws_name = None
    for flag in ("--name", "-n"):
        if flag in args:
            i = args.index(flag)
            if i + 1 >= len(args):
                sys.exit(f"[!] {flag} needs a value.\n{USAGE}")
            ws_name = args[i + 1]
            del args[i:i + 2]   # remove the flag and its value
            break

    if len(args) != 1:
        sys.exit(USAGE)

    # label = original input; ip = resolved (for scanning/RHOSTS)
    label, ip = resolve_target(args[0])

    # Workspace: custom name if given, otherwise the target label (IP/domain)
    workspace = ws_name if ws_name else label

    # Step 1: fast Go pre-scan to find which ports are open
    ports = fast_port_scan(ip, full=full)
    if ports is None:
        sys.exit("[!] No open ports found — nothing to deep-scan. Stopping.")

    # Temporary file for the XML — cleaned up at the end
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        # Step 2: nmap -sV ONLY on the open ports (fast)
        run_nmap(ip, xml_path, ports=ports)
        # Steps 3-6: into Metasploit
        client = connect_msf()
        ensure_workspace(client, workspace)
        import_scan(client, workspace, xml_path)
        set_rhosts(client, ip)                # RHOSTS uses the resolved IP
        summarize(client, workspace)
        print(f"[✓] Done. You're in workspace '{workspace}' with RHOSTS set to {ip}.")
    finally:
        if os.path.exists(xml_path):
            os.remove(xml_path)


if __name__ == "__main__":
    main()