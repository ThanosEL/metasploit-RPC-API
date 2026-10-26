# Metasploit RPC API — Automation
A small, hands-on toolkit that drives the Metasploit Framework programmatically
(through its RPC API and CLI tools) to automate a full workflow: from finding
open ports on a target, to enumerating its services, to generating a payload
and catching the session — all as simple, composable Python scripts.

Each tool does one job and hands off to the next, so you can run the whole
chain or just the piece you need. Results are stored in a local database and
browsed in the terminal or a small web viewer.

## Overview
```
 ┌─────────┐   ┌───────────┐   ┌──────────┐   ┌──────────────────┐
 │  SCAN   │──▶│ ENUMERATE │──▶│   VIEW   │   │     EXPLOIT      │
 └─────────┘   └───────────┘   └──────────┘   └──────────────────┘
 ports +       read-only        terminal /     payload generation
 services      auxiliaries      web viewer      + session handler
 into msf      into SQLite
```

| Stage | What it does | Tools |
|---|---|---|
| **Scan** | Fast port scan → nmap service detection → Metasploit workspace | `portscan.go`, `scan_import.py` |
| **Enumerate** | Run read-only auxiliary modules per service, store clean output | `enumerate.py`, `enum_modules.yaml`, `db.py` |
| **View** | Browse the findings (ports, modules, output) | `view.py`, `app.py` |
| **Exploit** | Interactive payload builder + matching handler | `payload_gen.py`, `handler.py` |

**Data flow:**
```
portscan.go + scan_import.py    ─▶  msf workspace (ports + services)
enum_modules.yaml + enumerate.py ─▶ enum_results.db (findings + services)
view.py / app.py                ─▶  read the database
payload_gen.py ─▶ .last_payload.json ─▶ handler.py (catches the session)
```

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
workspace -r <old> <new> // Rename a workspace
hosts                    // List hosts in the current workspace
services                 // List services (open ports) found
vulns                    // List known vulnerabilities
creds                    // List collected credentials
loot                     // List collected loot (files, hashes)
jons                     // List background Jobs
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

## Scan scripts
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
python3 -u scan_import.py <target_ip_or_domain>                 # ports 1-1024
python3 -u scan_import.py <target_ip_or_domain> --full          # all ports 1-65535
python3 -u scan_import.py <target_ip_or_domain> --name kioptrix # custom workspace name
```

**Flags:**
- `--full` — Go scanner sweeps all ports 1-65535 (default is 1-1024)
- `--name <name>` (or `-n`) — name the workspace (default: the target IP/domain)

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

The temp XML file is deleted automatically at the end (even if something fails).

**How portscan.go stays fast but reliable:**
- Runs ~150 workers (goroutines) in parallel instead of one port at a time.
- Each connect attempt has a timeout, so filtered ports don't hang the scan.
- A port that looks closed is retried twice before being given up — this cuts
  down false negatives (a single probe can miss an open port on a slow host).
- Open connections are closed immediately, to avoid running out of file
  descriptors.
- Progress goes to stderr, the port list to stdout — so `scan_import.py` reads
  the ports cleanly.

**Scope:** portscan does TCP connect scans only. Service/version detection, UDP,
and OS detection are left to nmap in step 2.

---

## Service Enumeration
Once `scan_import.py` has filled a workspace with services, `enumerate.py` runs
**read-only enumeration** auxiliary modules against each service and stores the
clean output in a local SQLite database (`enum_results.db`) — a stable,
queryable record of its own, independent of whatever Metasploit happens to save.

```
msf workspace (services)  ─▶  enumerate.py  ─▶  enum_results.db
```

Only enumeration modules are run (versions, shares, banners, headers). No
brute-force or `*_login` modules — those need credentials and are attacks, not
enumeration.

### Which modules run — enum_modules.yaml
The service → modules map lives in **`enum_modules.yaml`** (data, not code), so
you extend it without touching any script:

```yaml
smb:
  no_rport: true          # SMB uses 139/445 internally, rejects RPORT
  modules:
    - scanner/smb/smb_version
    - scanner/smb/smb_enumshares

http:
  modules:
    - scanner/http/http_version
    - scanner/http/http_header
    - scanner/http/robots_txt

ssh:
  modules:
    - scanner/ssh/ssh_version

ftp:
  modules:
    - scanner/ftp/ftp_version
    - scanner/ftp/ftp_anonymous   # anonymous-login CHECK (enum, not brute)
```

Each service key takes a `modules:` list and an optional `no_rport: true` (for
modules that manage their own port and reject a RPORT option, like SMB).

**Adding a service is usually just a YAML entry.** `enumerate.py` matches an
nmap service name to a YAML key in three steps: a few aliases for odd names
(`netbios-ssn → smb`, `ssl/https → https`), then `http`/`https` substrings,
then a **direct match** — if nmap's name is already a YAML key (`ftp`, `mysql`,
`smtp`, `telnet`, `vnc`…), it just works. Only genuinely odd names need a line
added to `SERVICE_ALIASES` in `enumerate.py`.

> ⚠️ **Verify a module exists before adding it.** List what's available with
> `ls /usr/share/metasploit-framework/modules/auxiliary/scanner/<service>/`.
> Keep `*_login` / brute-force modules out — enumeration only.

### How it decides what to scan
The **service name** (from `nmap -sV`), not the port number, decides which
modules run — so a web server on a non-standard port (e.g. Tomcat on 8180) is
still correctly enumerated as HTTP, and SMB on both 139 and 445 is run once
(identical result).

### Usage
```bash
# 0. (first) scan the target so the workspace has services
python3 -u scan_import.py <target> --full --name metasploitable2

# 1. dry run — show what WOULD run, execute nothing
python3 enumerate.py metasploitable2 --dry-run

# 2. real run — execute and store results in enum_results.db
python3 enumerate.py metasploitable2
```

To add a service, re-run the whole enumeration (replace strategy — see below);
it re-runs everything including the new modules.

### The database
One file, `enum_results.db`, holds **all** targets. Rows are separated by the
`workspace` column, so many targets live in the same tables (`findings` and
`services`):

```
workspace        target          port  service  module
metasploitable2  192.168.25.129  22    ssh      ssh_version
metasploitable2  192.168.25.129  139   smb      smb_enumshares
kioptrix         192.168.X.X     22    ssh      ssh_version
```

**Strategy: replace per workspace.** Re-running `enumerate.py <ws>` clears that
workspace's old rows first, then inserts fresh ones — always a clean current
picture, no duplicates. Other workspaces are untouched.

The database is created automatically on first run — no setup needed. Inspect
it directly if you like:

```bash
python3 db.py                                    # list workspaces + counts
sqlite3 enum_results.db \
  "SELECT module, port FROM findings WHERE workspace='metasploitable2';"
```

> **Note on msf vs this database.** The msf workspace keeps whatever each module
> decides to save (some vulns, creds, loot — inconsistent). `enum_results.db`
> keeps the **full clean output** of every module, in one place, under your
> control. They overlap but aren't the same.

---

## Viewing results
Two read-only viewers read `enum_results.db` (neither touches msf):

### view.py — terminal
Quick look without a browser. Colored ports table + each module's output.

```bash
python3 view.py                 # list all workspaces
python3 view.py metasploitable2 # ports + findings for one target
```

### app.py — web viewer
A small Flask app with a dark, terminal-style theme.

```bash
python3 app.py                  # then open http://127.0.0.1:5000
```

- **Home** — list of all targets (workspaces).
- **Target page** — a stats line (`N ports · N enumerated · N modules ·
  N found · N failed`), an **Open Ports** table marking which ports were
  enumerated (● / ○), and each module's result as a card you can expand.
- Each result is badged **found** / **failed** / **ok** from its output markers
  (`[+]` / `[-]`), so failures stand out at a glance.
- A live search box filters the result cards (service, module, port, or text).
- Service badges are colored automatically from the service name, so new
  services you add to the YAML get their own color with no CSS change.

---

## Payload & Handler
Two scripts for the exploitation side: generate a payload interactively, then
start a matching handler that catches the session when the payload runs. The
handler reads the payload's settings automatically, so you don't retype them.

```
payload_gen.py  ─▶  .last_payload.json  ─▶  handler.py
  (builds payload)    (saved settings)       (listens for the connection)
```

### payload_gen.py — interactive msfvenom
A menu-driven wizard that walks you through each choice and runs `msfvenom`
for you. Menu-based so you can't pick invalid combinations; LHOST/LPORT/filename
are validated free input.

```bash
python3 payload_gen.py
```

Steps: platform → payload (filtered by platform) → LHOST (your LAN IP is
suggested) → LPORT → format (filtered by platform) → optional encoder → output
file. Generated payloads are saved under `payloads/` (gitignored), and the
settings are written to `.last_payload.json` for the handler.

> **On encoders:** they help avoid bad characters, but they do **not** reliably
> evade modern antivirus — `shikata_ga_nai` in particular is heavily signatured.
> `none` is the sensible default.

### handler.py — matching listener
Reads `.last_payload.json`, builds a `multi/handler` resource script with the
matching payload/LHOST/LPORT, and launches an interactive msfconsole. When the
payload connects, the session opens right there.

```bash
python3 handler.py            # use the last payload's settings
python3 handler.py --show     # print the settings/resource script, don't launch
# override if needed:
python3 handler.py -p <payload> --lhost <ip> --lport <port>
```