#!/usr/bin/env python3
"""
db.py — SQLite storage layer for enumeration findings.

One database file (enum_results.db) holds findings for ALL targets. Rows are
separated by the `workspace` column, so many targets live in the same table.

Strategy: REPLACE. Re-running enum for a workspace clears that workspace's old
rows first, then inserts the fresh ones — always a clean current picture, no
history, no duplicates. Other workspaces are untouched.

All SQL lives here. enum.py and view.py just call these functions, so they
never have to write SQL themselves.
"""

import sqlite3

DB_FILE = "enum_results.db"


# The schema. "IF NOT EXISTS" means it's safe to call every run — it only
# creates the table the first time.
SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace    TEXT NOT NULL,     -- target group name, e.g. "kioptrix"
    target       TEXT NOT NULL,     -- the IP, e.g. "192.168.177.132"
    port         INTEGER,           -- e.g. 139
    service      TEXT,              -- normalized, e.g. "smb"
    module       TEXT,              -- which auxiliary found it
    finding_type TEXT,              -- "share" / "user" / "directory" / "version" ...
    value        TEXT,              -- the finding itself, e.g. "ADMIN$"
    raw_output   TEXT,              -- raw module output (safety net for unparsed data)
    timestamp    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace  TEXT NOT NULL,       -- same workspace key as findings
    target     TEXT NOT NULL,       -- the IP
    port       INTEGER,             -- open port, e.g. 80
    proto      TEXT,                -- tcp / udp
    name       TEXT,                -- raw service name from nmap, e.g. "netbios-ssn"
    info       TEXT,                -- version/banner, e.g. "Apache 2.2.8"
    enumerated INTEGER DEFAULT 0    -- 1 if we ran enumeration on this service
);
"""


def connect():
    """Opens a connection to the database file.

    row_factory = sqlite3.Row lets us read columns by name (row["value"])
    instead of by position (row[7]) — much clearer.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the tables if they don't exist yet. Safe to call every run.

    executescript (not execute) because SCHEMA now holds multiple statements.
    """
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def clear_workspace(workspace):
    """Deletes all rows for ONE workspace (the 'replace' strategy).

    Only this workspace's rows are removed — other targets in the DB stay.
    """
    conn = connect()
    conn.execute("DELETE FROM findings WHERE workspace = ?", (workspace,))
    conn.commit()
    conn.close()


def save_findings(rows):
    """Inserts many findings at once.

    `rows` is a list of dicts, each with keys:
        workspace, target, port, service, module, finding_type, value, raw_output
    Using executemany + one commit is faster than inserting one at a time.
    """
    conn = connect()
    conn.executemany(
        """
        INSERT INTO findings
            (workspace, target, port, service, module, finding_type, value, raw_output)
        VALUES
            (:workspace, :target, :port, :service, :module, :finding_type, :value, :raw_output)
        """,
        rows,
    )
    conn.commit()
    conn.close()


def clear_services(workspace):
    """Deletes all service rows for one workspace (replace strategy)."""
    conn = connect()
    conn.execute("DELETE FROM services WHERE workspace = ?", (workspace,))
    conn.commit()
    conn.close()


def save_services(rows):
    """Inserts many service rows at once.

    Each dict has keys: workspace, target, port, proto, name, info, enumerated
    """
    conn = connect()
    conn.executemany(
        """
        INSERT INTO services
            (workspace, target, port, proto, name, info, enumerated)
        VALUES
            (:workspace, :target, :port, :proto, :name, :info, :enumerated)
        """,
        rows,
    )
    conn.commit()
    conn.close()


def get_services(workspace):
    """Returns all services for a workspace, ordered by port."""
    conn = connect()
    cur = conn.execute(
        "SELECT * FROM services WHERE workspace = ? ORDER BY port",
        (workspace,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_findings(workspace):
    """Returns all findings for a workspace, ordered by port then type."""
    conn = connect()
    cur = conn.execute(
        "SELECT * FROM findings WHERE workspace = ? ORDER BY port, finding_type",
        (workspace,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def list_workspaces():
    """Returns each workspace in the DB with how many findings it has."""
    conn = connect()
    cur = conn.execute(
        "SELECT workspace, COUNT(*) AS n FROM findings GROUP BY workspace ORDER BY workspace"
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# Quick self-test: `python3 db.py` creates the DB and reports status.
if __name__ == "__main__":
    init_db()
    print(f"[+] Database ready: {DB_FILE}")
    wss = list_workspaces()
    if wss:
        print("Workspaces:")
        for w in wss:
            print(f"  - {w['workspace']}: {w['n']} findings")
    else:
        print("No findings yet.")