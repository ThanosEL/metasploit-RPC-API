#!/usr/bin/env python3
"""
view.py — Terminal viewer for enumeration results.

A quick way to see a workspace's findings without opening the web viewer.
Reads only from the local database (db.py) — never touches msf.

Usage:
    python3 view.py                 # list all workspaces
    python3 view.py <workspace>     # show that workspace's ports + findings
"""

import sys
import db

# Simple ANSI colors
C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "green": "\033[32m", "yellow": "\033[33m", "blue": "\033[34m",
    "cyan": "\033[36m", "magenta": "\033[35m",
}


def show_all():
    """Lists every workspace with its finding count."""
    workspaces = db.list_workspaces()
    if not workspaces:
        print("No results yet. Run enumerate.py <workspace> first.")
        return
    print(f"\n{C['bold']}Workspaces{C['reset']}")
    for w in workspaces:
        print(f"  {C['cyan']}{w['workspace']}{C['reset']}  "
              f"{C['dim']}({w['n']} findings){C['reset']}")
    print(f"\nUse: python3 view.py <workspace>\n")


def show_workspace(name):
    """Shows ports and findings for one workspace."""
    services = db.get_services(name)
    findings = db.get_findings(name)

    if not services and not findings:
        print(f"[!] Nothing found for workspace '{name}'.")
        return

    print(f"\n{C['bold']}=== {name} ==={C['reset']}")

    # --- Ports table ---
    if services:
        print(f"\n{C['bold']}Open Ports{C['reset']} ({len(services)})")
        for s in services:
            mark = (f"{C['green']}●{C['reset']}" if s["enumerated"]
                    else f"{C['dim']}○{C['reset']}")
            port = f"{s['port']}/{s['proto']}"
            info = s["info"] or ""
            print(f"  {mark} {port:<11} {C['cyan']}{s['name'] or '?':<14}{C['reset']} "
                  f"{C['dim']}{info}{C['reset']}")
        print(f"\n  {C['green']}●{C['reset']} enumerated   "
              f"{C['dim']}○ not enumerated{C['reset']}")

    # --- Findings ---
    if findings:
        print(f"\n{C['bold']}Enumeration Results{C['reset']} ({len(findings)})")
        for f in findings:
            print(f"\n{C['yellow']}▸ {f['module']}{C['reset']} "
                  f"{C['dim']}@ {f['target']}:{f['port']} ({f['service']}){C['reset']}")
            # indent the raw output
            for line in (f["raw_output"] or "").splitlines():
                print(f"    {line}")
    print()


def main():
    if len(sys.argv) == 1:
        show_all()
    elif len(sys.argv) == 2:
        show_workspace(sys.argv[1])
    else:
        sys.exit("Usage: python3 view.py [workspace]")


if __name__ == "__main__":
    main()