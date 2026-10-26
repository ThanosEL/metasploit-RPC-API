#!/usr/bin/env python3
"""Quick probe: can the RPC server see our open session(s)?"""
import os
from dotenv import load_dotenv
from pymetasploit3.msfrpc import MsfRpcClient

load_dotenv()
client = MsfRpcClient(
    os.getenv("MSF_RPC_PASS"),
    server=os.getenv("MSF_RPC_HOST", "127.0.0.1"),
    port=int(os.getenv("MSF_RPC_PORT", "55552")),
    ssl=os.getenv("MSF_RPC_SSL", "true").lower() == "true",
)

print("[*] Asking the RPC server for sessions ...\n")
sessions = client.call("session.list", [])
if not sessions:
    print("[!] RPC sees NO sessions.")
    print("    -> The session is in a different msf instance than msgrpc.")
    print("    -> Load msgrpc in the SAME console that has the session.")
else:
    print(f"[+] RPC sees {len(sessions)} session(s):\n")
    for sid, info in sessions.items():
        print(f"  Session {sid}:")
        print(f"    type:   {info.get('type')}")
        print(f"    tunnel: {info.get('tunnel_peer')}")
        print(f"    info:   {info.get('info')}")
        print(f"    via:    {info.get('via_exploit')}")
        print()