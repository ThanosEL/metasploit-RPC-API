## Metasploit RPC API - Setup

### Database
Initialize (the first time):
```bash
sudo msfdb init
```

Status check:
```bash
sudo msfdb status
```

If it shows postgresql selected, no connection, connect it:
```msf
db_connect -y /usr/share/metasploit-framework/config/database.yml
db_status
```

Start/Enable postgres:
```bash
sudo systemctl start postgresql@18-main
sudo systemctl enable postgresql@18-main
```

If there is a message after an OS update, about collation missmatch like:
```
WARNING: database "msf" has a collation version mismatch
```

Clear with:
```bash
sudo -u postgres psql -d msf -c "ALTER DATABASE msf REFRESH COLLATION VERSION;"
```

### Connection Verification
```bash
msfconsole -q
```

Inside the console:
```msf
msf > db_status
```

It should print:
```
[*] Connected to msf. Connection type: postgresql.
```

### Start RPC Server
Inside metasploit:
```msf
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<YOUR_PASSWORD> SSL=true
```

Verify that the server listens:
```bash
ss -tlnp | grep 55552
```

**Note**: RPC server doesn't start automatically. Must load msgrpc command every time you open new msfconsole.

#### (Optional) Resource script for automatic load
Create a .rc file:
```bash
cat > ~/.msf_rpc.rc <<'EOF'
db_connect -y /usr/share/metasploit-framework/config/database.yml
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<YOUR_PASSWORD> SSL=true
EOF
```

Startup with automatic load (use this command instead of plain msfconsole — the RPC loads on its own):
```bash
msfconsole -q -r ~/.msf_rpc.rc
```

### Python environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pymetasploit3
```

Create a environment variable (.env):
```bash
cat > .env <<'EOF'
MSF_RPC_HOST=127.0.0.1
MSF_RPC_PORT=55552
MSF_RPC_USER=msf
MSF_RPC_PASS=<YOUR_PASSWORD>
MSF_RPC_SSL=true
EOF
```

#### Connection Test (smoke_test.py)
Install python-dotenv if you need to load the variables from .env
```bash
pip install python-dotenv
```

```bash
python smoke_test.py
```

If version printed, everything is OK

---

## Metasploit Commands
**Database & Workspaces**:
```
- db_status	            // Show whether the DB is connected
- db_connect -y <path>	// Connect to the DB from a YAML file
- db_disconnect	        // Disconnect the current DB
- workspace	            // List all workspaces (current one marked with *)
- workspace <name>	    // Switch to a workspace
- workspace -a <name>	// Add a new workspace
- workspace -d <name>	// Delete a workspace
- hosts	                // List hosts in the current workspace
- services	            // List services (open ports) found
- vulns	                // List known vulnerabilities
- creds	                // List collected credentials
- loot	                // List collected loot (files, hashes)
```

**Importing & Scanning**:
```
- db_import <file.xml>	    // Import an nmap XML into the DB
- db_nmap <args> <target>	// Run nmap from inside msf and auto-import
- hosts -R	                // Set RHOSTS from the hosts in the workspace
```

**Modules**:
```
- search <term>	                // Search for modules
- use <module>	                // Load a module
- info	                        // Show info about the loaded module
- show options	                // Show the module's options
- set <OPT> <value>	            // Set an option (this session only)
- setg <OPT> <value>	        // Set a GLOBAL option (all modules)
- unset <OPT> / unsetg <OPT>	// Clear an option / global option
- run or exploit	            // Execute the loaded module
- back	                        // Unload the current module
```

**Sessions**:
```
- sessions	                // List active sessions
- sessions -i <id>	        // Interact with a session
- sessions -k <id>	        // Kill a session
- background	            // Send the current session to the background
```

**Plugins & RPC**:
```
- load <plugin>	            // Load a plugin (e.g. load msgrpc)
- unload <plugin>	        // Unload a plugin
- load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=<PW> SSL=true
```

---

## Automation Scripts
#### portscan.go & scan_import.py
The main automation pipeline. Give it one target (IP or domain) and it runs everything end to end, with no manual steps. It combines a fast Go port scanner with nmap and Metasploit:

portscan.go — a fast concurrent TCP scanner. It sweeps the ports with many goroutines in parallel and prints the open ones as a comma-separated line (e.g. 22,80,443). This is the quick "where to look" step.
```bash
go build -o portscan portscan.go
```

scan_import.py — orchestrates everything: it calls the Go scanner, then runs nmap only on the open ports, and pushes the result into Metasploit.

What it does, in order: 0. If the target is a domain, resolves it to an IP (the workspace keeps the readable name, scanning/RHOSTS use the IP).

1. Runs portscan to find the OPEN ports (e.g. 22,80,443).
2. Runs nmap -sV ONLY on those open ports, writing XML to a temp file. A live animated bar sweeps back and forth while it  
   runs (nmap gives no total, so there's no percentage to fill).
3. Creates (or reuses) a workspace named after the target, and switches into it. An existing workspace is reused, so  
   repeated scans build on the same data (findings are merged, not duplicated).
4. Imports the nmap XML into that workspace (db.import_data).
   Sets RHOSTS = target globally (core.setg), so the next module already has the target set.
5. Prints a summary of the hosts and open services found.