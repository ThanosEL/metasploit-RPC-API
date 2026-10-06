#!/usr/bin/env python3
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


def resolve_target(target):
    """Accepts an IP or a domain and returns (label, ip)."""
    try:
        ipaddress.ip_address(target)
        return target, target
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit(f"[!] '{target}' is not a valid IP and could not be resolved.")
    print(f"[*] Resolved {target} -> {ip}")
    return target, ip


def fast_port_scan(target, full=False):
    """Runs the Go port scanner, returns open ports as '22,80,443' or None."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary = os.path.join(script_dir, "portscan")
    if not os.path.exists(binary):
        sys.exit("[!] portscan binary not found. Build it first:\n"
                 "    go build -o portscan portscan.go")
    cmd = [binary, target]
    if full:
        cmd += ["1", "65535"]
    print(f"[*] Fast port scan on {target} "
          f"({'full 1-65535' if full else 'ports 1-65535'}) ...")
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, text=True, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] Port scan failed (exit {e.returncode}).")
    ports = proc.stdout.strip()
    if not ports:
        return None
    print(f"[+] Open ports: {ports}")
    return ports


def run_nmap(target, xml_path, ports=None):
    """Runs nmap -sV (only on `ports` if given), with an animated bar."""
    nmap_cmd = ["nmap", "-sV", "-T4"]
    if ports:
        nmap_cmd += ["-p", ports]
    nmap_cmd += ["-oX", xml_path, target]

    scope = f"ports {ports}" if ports else "default ports"
    print(f"[*] Running nmap -sV against {target} ({scope}) ...")

    result = {}

    def worker():
        try:
            result["proc"] = subprocess.run(nmap_cmd, check=True,
                                             capture_output=True, text=True)
        except Exception as e:
            result["error"] = e

    t = threading.Thread(target=worker)
    t.start()

    width = 30
    pos = 0
    direction = 1
    with tqdm(total=width, desc="    nmap scanning",
              bar_format="{desc} [{elapsed}] |{bar}|", leave=False) as bar:
        while t.is_alive():
            time.sleep(0.2)
            pos += direction
            if pos >= width or pos <= 0:
                direction *= -1
            bar.n = pos
            bar.refresh()

    t.join()

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
        return MsfRpcClient(
            os.getenv("MSF_RPC_PASS"),
            server=os.getenv("MSF_RPC_HOST", "127.0.0.1"),
            port=int(os.getenv("MSF_RPC_PORT", "55552")),
            ssl=os.getenv("MSF_RPC_SSL", "true").lower() == "true",
        )
    except Exception as e:
        sys.exit(f"[!] Failed to connect to the RPC API: {e}\n"
                 f"    Is msgrpc running? (load msgrpc in msfconsole)")


def ensure_workspace(client, name):
    """Creates the workspace if needed, then switches to it."""
    existing = client.call("db.workspaces", [])
    names = [w["name"] for w in existing.get("workspaces", [])]
    if name in names:
        print(f"[*] Workspace '{name}' already exists — reusing it.")
    else:
        client.call("db.add_workspace", [name])
        print(f"[+] Created workspace '{name}'.")
    client.call("db.set_workspace", [name])


def import_scan(client, name, xml_path):
    """Imports the nmap XML into the given workspace."""
    with open(xml_path, "r") as f:
        xml_data = f.read()
    client.call("db.import_data", [{"workspace": name, "data": xml_data}])
    print("[+] Scan imported into the database.")


def set_rhosts(client, target):
    """Sets RHOSTS global = target."""
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
        print(f"  - {h.get('address', '?')}  ({h.get('os_name', 'unknown')})")
    svc_list = services.get("services", [])
    print(f"Open services: {len(svc_list)}")
    for s in svc_list:
        line = f"  - {s.get('port','?')}/{s.get('proto','')}  {s.get('name','')}  {s.get('info','')}"
        print(line.rstrip())
    print("===================\n")


def main():
    args = sys.argv[1:]
    full = "--full" in args
    args = [a for a in args if a != "--full"]
    if len(args) != 1:
        sys.exit("Usage: python scan_import.py <target_ip_or_domain> [--full]")

    label, ip = resolve_target(args[0])

    ports = fast_port_scan(ip, full=full)
    if ports is None:
        sys.exit("[!] No open ports found — nothing to deep-scan. Stopping.")

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name

    try:
        run_nmap(ip, xml_path, ports=ports)
        client = connect_msf()
        ensure_workspace(client, label)
        import_scan(client, label, xml_path)
        set_rhosts(client, ip)
        summarize(client, label)
        print(f"[✓] Done. You're in workspace '{label}' with RHOSTS set to {ip}.")
    finally:
        if os.path.exists(xml_path):
            os.remove(xml_path)


if __name__ == "__main__":
    main()
