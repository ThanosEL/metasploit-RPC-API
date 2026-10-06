# Metasploit RPC API — Automation

Drive the Metasploit Framework programmatically through its RPC API (msgrpc).
This repo contains a small automation pipeline: a fast Go port scanner feeds
nmap, and the results are pushed straight into Metasploit over the RPC API.

---

## Prerequisites

| Tool | Check | Install (Kali / Debian) |
|---|---|---|
| Metasploit Framework | `msfconsole --version` | preinstalled on Kali |
| PostgreSQL | `sudo msfdb status` | preinstalled on Kali |
| Nmap | `nmap --version` | `sudo apt install nmap` |
| Go | `go version` | `sudo apt install golang-go` |
| Python 3 | `python3 --version` | preinstalled |

---

## Setup
### 1. Database

Initialize (the first time):
```bash
sudo msfdb init
```

Status check:
```bash
sudo msfdb status
```

Start / enable PostgreSQL (on Kali the real instance is versioned):
```bash
sudo systemctl start postgresql@18-main
sudo systemctl enable postgresql@18-main
```

> **Note:** `postgresql.service` on Kali is just a wrapper (runs `/bin/true`),
> so `systemctl status postgresql` can say `active (exited)` even when the DB is
> down. Always start/check `postgresql@18-main`. Find the exact name with:
> `sudo systemctl list-units | grep -i postgres`

If after an OS update you see a collation mismatch:
```
WARNING: database "msf" has a collation version mismatch
```
Clear it with:
```bash
sudo -u postgres psql -d msf -c "ALTER DATABASE msf REFRESH COLLATION VERSION;"
```

### 2. Connection verification
```bash
msfconsole -q
```
Inside the console:
```
msf > db_status
```
It should print:
```
[*] Connected to msf. Connection type: postgresql.
```
If it shows `postgresql selected, no connection`, connect it:
```
msf > db_connect -y /usr/share/metasploit-framework/config/database.yml
msf > db_status
```

### 3. Start the RPC server
Inside msfconsole:
```
msf > load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<YOUR_PASSWORD> SSL=true
```
Verify it's listening (in another terminal):
```bash
ss -tlnp | grep 55552
```

> **Note:** the RPC server does **not** start automatically. You must run
> `load msgrpc` every time you open a new msfconsole (or use the .rc file below).

#### (Optional) Resource script for automatic load
Create a `.rc` file that connects the DB **and** loads the RPC server:
```bash
cat > ~/.msf_rpc.rc <<'EOF'
db_connect -y /usr/share/metasploit-framework/config/database.yml
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<YOUR_PASSWORD> SSL=true
EOF
```
Start msfconsole with it (use this instead of plain `msfconsole`):
```bash
msfconsole -q -r ~/.msf_rpc.rc
```

> Connecting the DB **before** loading msgrpc avoids the "Database Not Loaded"
> error from the RPC server (see Troubleshooting).

### 4. Python environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file with your RPC credentials (kept out of git):
```bash
cat > .env <<'EOF'
MSF_RPC_HOST=127.0.0.1
MSF_RPC_PORT=55552
MSF_RPC_USER=msf
MSF_RPC_PASS=<YOUR_PASSWORD>
MSF_RPC_SSL=true
EOF
```

### 5. Build the Go scanner
```bash
go build -o portscan portscan.go
```

### 6. Smoke test
```bash
python3 smoke_test.py
```
If it prints the Metasploit version, everything works: DB up, RPC listening,
credentials correct, and the library can talk to the API.

---

## Quick Start Checklist
| # | Check | Command | Expected |
|---|-------|---------|----------|
| 1 | PostgreSQL up | `ss -tlnp \| grep 5432` | LISTEN on 5432 |
| 2 | DB connected | `db_status` (in console) | Connected (postgresql) |
| 3 | RPC listening | `ss -tlnp \| grep 55552` | LISTEN on 55552 |
| 4 | Python deps | `pip show pymetasploit3` | installed |
| 5 | Scanner built | `ls portscan` | binary exists |
| 6 | API reachable | `python3 smoke_test.py` | prints version |

---

## Metasploit Commands
**Database & Workspaces**
```
db_status                // Show whether the DB is connected
db_connect -y <path>     // Connect to the DB from a YAML file
db_disconnect            // Disconnect the current DB
workspace                // List all workspaces (current marked with *)
workspace <name>         // Switch to a workspace
workspace -a <name>      // Add a new workspace
workspace -d <name>      // Delete a workspace
hosts                    // List hosts in the current workspace
services                 // List services (open ports) found
vulns                    // List known vulnerabilities
creds                    // List collected credentials
loot                     // List collected loot (files, hashes)
```

**Importing & Scanning**
```
db_import <file.xml>     // Import an nmap XML into the DB
db_nmap <args> <target>  // Run nmap from inside msf and auto-import
hosts -R                 // Set RHOSTS from the hosts in the workspace
```

**Modules**
```
search <term>            // Search for modules
use <module>             // Load a module
info                     // Show info about the loaded module
show options             // Show the module's options
set <OPT> <value>        // Set an option (this session only)
setg <OPT> <value>       // Set a GLOBAL option (all modules)
unset <OPT> / unsetg     // Clear an option / global option
run  (or exploit)        // Execute the loaded module
back                     // Unload the current module
```

**Sessions**
```
sessions                 // List active sessions
sessions -i <id>         // Interact with a session
sessions -k <id>         // Kill a session
background               // Send the current session to the background
```

**Plugins & RPC**
```
load <plugin>            // Load a plugin (e.g. load msgrpc)
unload <plugin>          // Unload a plugin
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<PW> SSL=true
```

---

## Scripts
### smoke_test.py
Connects to the RPC API (reading credentials from `.env`) and prints the
Metasploit version. The quickest way to confirm the whole chain works. Run it
first whenever something feels off.
```bash
python3 smoke_test.py
```

### portscan.go & scan_import.py — the main pipeline
Give it one target (IP **or** domain) and it runs everything end to end, with no
manual steps. It combines a fast Go port scanner with nmap and Metasploit.

- **portscan.go** — a fast concurrent TCP scanner. It sweeps the ports with many
  goroutines in parallel and prints the open ones as a comma-separated line
  (e.g. `22,80,443`). This is the quick "where to look" step.
- **scan_import.py** — orchestrates everything: calls the Go scanner, runs nmap
  only on the open ports, and pushes the result into Metasploit.

Why two tools: scanning all 65535 ports with nmap is slow. The Go scanner finds
the open ports in seconds, so nmap only has to deep-scan a handful.

**Run:**
```bash
python3 -u scan_import.py <target_ip_or_domain>          # ports 1-1024
python3 -u scan_import.py <target_ip_or_domain> --full   # all ports 1-65535
```

**What it does, in order:**
0. If the target is a domain, resolves it to an IP (the workspace keeps the
   readable name; scanning/RHOSTS use the IP).
1. Runs **portscan** to find the OPEN ports (e.g. `22,80,443`).
2. Runs **nmap -sV** ONLY on those open ports, writing XML to a temp file. A live
   animated bar sweeps back and forth while it runs.
3. Creates (or reuses) a workspace named after the target, and switches into it.
   An existing workspace is reused, so repeated scans build on the same data
   (findings are merged, not duplicated).
4. Imports the nmap XML into that workspace (`db.import_data`).
5. Sets RHOSTS = target globally (`core.setg`), so the next module already has
   the target set.
6. Prints a summary of the hosts and open services found.

