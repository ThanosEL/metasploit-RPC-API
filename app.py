#!/usr/bin/env python3
"""
app.py — Flask web viewer for enumeration results.

Read-only window into enum_results.db:
  /                      -> list of all workspaces (targets)
  /workspace/<name>      -> that target's modules and their output

Run:
    python3 app.py
    then open http://127.0.0.1:5000 in a browser

This does NOT run scans or change anything — it only displays the database.
"""

from flask import Flask, render_template_string, abort

import db

app = Flask(__name__)


def classify(raw_output):
    """Classifies a module result from its output markers.

    msf modules use [+] success/finding, [-] failure, [*] info, [!] warning.
    - "found"  : has at least one [+]  -> it found something
    - "failed" : has [-] and no [+]    -> it errored / found nothing useful
    - "ok"     : ran, nothing notable
    """
    out = raw_output or ""
    has_plus = "[+]" in out
    has_minus = "[-]" in out
    if has_plus:
        return "found"
    if has_minus:
        return "failed"
    return "ok"


def summarize(services, findings):
    """Builds the small stats line for the top of a workspace page."""
    ports = len(services)
    enumerated = sum(1 for s in services if s["enumerated"])
    modules = len(findings)
    failed = sum(1 for f in findings if classify(f["raw_output"]) == "failed")
    found = sum(1 for f in findings if classify(f["raw_output"]) == "found")
    return {"ports": ports, "enumerated": enumerated,
            "modules": modules, "found": found, "failed": failed}


# ---------------------------------------------------------------------------
# Templates (inline for now — one file, easy to follow)
# ---------------------------------------------------------------------------

BASE_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #080a0b; --panel: #0d1110; --border: #1c2a22;
    --text: #c9f0d8; --muted: #4f7a60; --accent: #00ff9c;
    --glow: 0 0 6px rgba(0,255,156,0.35);
    --smb: #ff7edb; --http: #00ff9c; --https: #39d0ff; --ssh: #ffe66d; --other: #7a88ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font-family: 'JetBrains Mono', ui-monospace, monospace; line-height: 1.5;
    background-image: repeating-linear-gradient(
      0deg, rgba(0,255,156,0.025) 0px, rgba(0,255,156,0.025) 1px,
      transparent 1px, transparent 3px);
  }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px 16px; }
  h1 {
    font-size: 1.4rem; margin: 0 0 4px; color: var(--accent);
    text-shadow: var(--glow); letter-spacing: 0.5px;
  }
  h1::before { content: "> "; opacity: 0.6; }
  h2 { color: var(--accent); }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-shadow: var(--glow); }
  .muted { color: var(--muted); font-size: 0.9rem; }
  .back { display: inline-block; margin-bottom: 16px; }

  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 4px; padding: 16px; margin: 12px 0;
    box-shadow: inset 0 0 20px rgba(0,255,156,0.02);
  }
  .card:hover { border-color: #2a4535; }
  .ws-row { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 3px;
    font-size: 0.72rem; font-weight: 700; color: #080a0b; text-transform: uppercase;
    background: var(--other);   /* fallback; JS assigns a per-service color */
  }

  details { margin: 8px 0 0; }
  summary {
    cursor: pointer; padding: 8px 10px; border-radius: 3px;
    background: #0a0e0c; border: 1px solid var(--border); color: var(--muted);
    font-size: 0.85rem;
  }
  summary::before { content: "$ cat "; color: var(--accent); opacity: 0.7; }
  summary:hover { border-color: var(--accent); color: var(--text); }
  pre {
    background: #050706; border: 1px solid var(--border); border-radius: 3px;
    padding: 12px; overflow-x: auto; font-size: 0.8rem; color: #9fe8bd;
    white-space: pre-wrap; word-break: break-word; margin: 6px 0 0;
  }
  .search {
    width: 100%; padding: 10px 12px; margin: 8px 0 16px;
    background: #0a0e0c; border: 1px solid var(--border);
    border-radius: 3px; color: var(--accent); font-size: 0.9rem;
    font-family: 'JetBrains Mono', monospace;
  }
  .search:focus { outline: none; border-color: var(--accent); box-shadow: var(--glow); }
  .search::placeholder { color: var(--muted); }
  .mono { font-family: 'JetBrains Mono', monospace; }

  table.ports { width: 100%; border-collapse: collapse; margin-top: 10px; }
  table.ports th {
    text-align: left; font-size: 0.72rem; text-transform: uppercase;
    color: var(--muted); padding: 6px 8px; border-bottom: 1px solid var(--border);
    letter-spacing: 0.5px;
  }
  table.ports td { padding: 6px 8px; border-bottom: 1px solid #10180f; font-size: 0.85rem; }
  table.ports tr:hover td { background: rgba(0,255,156,0.03); }
  table.ports td.info { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--muted); }
  .dot.on { color: var(--accent); text-shadow: var(--glow); }
  .dot.off { color: #2a3a30; }

  .stats { display: flex; flex-wrap: wrap; gap: 18px; margin: 10px 0 20px; color: var(--muted); font-size: 0.85rem; }
  .stats strong { color: var(--accent); font-weight: 700; }
  .stats .s-found strong { color: var(--accent); }
  .stats .s-failed strong { color: #ff5f56; }

  .status { font-size: 0.75rem; white-space: nowrap; text-transform: uppercase; letter-spacing: 0.5px; }
  .st-found { color: var(--accent); }
  .st-failed { color: #ff5f56; }
  .st-ok { color: var(--muted); }
</style>
"""

INDEX_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Enum Results</title>""" + BASE_CSS + """</head><body>
<div class="wrap">
  <h1>Enumeration Results</h1>
  <p class="muted">Targets scanned by the pipeline</p>

  {% if workspaces %}
    {% for w in workspaces %}
      <div class="card ws-row">
        <div>
          <a href="/workspace/{{ w['workspace'] }}"><strong>{{ w['workspace'] }}</strong></a>
        </div>
        <span class="muted">{{ w['n'] }} findings</span>
      </div>
    {% endfor %}
  {% else %}
    <div class="card">No results yet. Run <code>enumerate.py &lt;workspace&gt;</code> first.</div>
  {% endif %}
</div>
</body></html>
"""

WORKSPACE_HTML = """
<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ workspace }} — Enum Results</title>""" + BASE_CSS + """</head><body>
<div class="wrap">
  <a class="back" href="/">&larr; all targets</a>
  <h1>{{ workspace }}</h1>
  <div class="stats">
    <span><strong>{{ stats.ports }}</strong> ports</span>
    <span><strong>{{ stats.enumerated }}</strong> enumerated</span>
    <span><strong>{{ stats.modules }}</strong> modules</span>
    <span class="s-found"><strong>{{ stats.found }}</strong> found</span>
    {% if stats.failed %}<span class="s-failed"><strong>{{ stats.failed }}</strong> failed</span>{% endif %}
  </div>

  {% if services %}
  <div class="card">
    <strong>Open Ports</strong>
    <span class="muted">({{ services|length }})</span>
    <table class="ports">
      <tr><th>Port</th><th>Service</th><th>Info</th><th>Enum</th></tr>
      {% for s in services %}
      <tr>
        <td class="mono">{{ s['port'] }}/{{ s['proto'] }}</td>
        <td>{{ s['name'] or '?' }}</td>
        <td class="muted info">{{ s['info'] or '' }}</td>
        <td>{% if s['enumerated'] %}<span class="dot on" title="enumerated">&#9679;</span>{% else %}<span class="dot off" title="not enumerated">&#9675;</span>{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
    <p class="muted" style="margin:8px 0 0; font-size:0.8rem;">
      &#9679; enumerated &nbsp; &#9675; not enumerated
    </p>
  </div>
  {% endif %}

  <h2 style="font-size:1.1rem; margin:20px 0 4px;">Enumeration Results</h2>
  <input class="search" id="search" placeholder="Filter results (service, module, or text)..."
         onkeyup="filterCards()">

  {% for f in findings %}
    <div class="card finding"
         data-text="{{ (f['service'] ~ ' ' ~ f['module'] ~ ' ' ~ f['port'] ~ ' ' ~ f['raw_output'])|lower }}">
      <div class="ws-row">
        <div>
          <span class="badge" data-service="{{ f['service'] or '?' }}">{{ f['service'] or '?' }}</span>
          <strong>{{ f['module'] }}</strong>
          <span class="muted">@ {{ f['target'] }}:{{ f['port'] }}</span>
        </div>
        <span class="status st-{{ f['status'] }}">
          {% if f['status'] == 'found' %}&#9679; found
          {% elif f['status'] == 'failed' %}&#9679; failed
          {% else %}&#9679; ok{% endif %}
        </span>
      </div>
      <details>
        <summary>output</summary>
        <pre>{{ f['raw_output'] }}</pre>
      </details>
    </div>
  {% endfor %}
</div>

<script>
// Give each service a stable, unique color derived from its name.
// Same name -> same color every time, no CSS needed when you add a service.
function colorForService(name) {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash) % 360;
  // Fixed saturation/lightness keeps badges readable on the dark theme
  // and consistent with the neon palette (dark text sits on top).
  return `hsl(${hue}, 70%, 62%)`;
}

// Paint every badge (findings cards + ports table) by its service name.
document.querySelectorAll('[data-service]').forEach(el => {
  const svc = el.getAttribute('data-service');
  if (svc && svc !== '?') el.style.background = colorForService(svc);
});

function filterCards() {
  const q = document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.finding').forEach(card => {
    const text = card.getAttribute('data-text');
    card.style.display = text.includes(q) ? '' : 'none';
  });
}
</script>
</body></html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    workspaces = db.list_workspaces()
    return render_template_string(INDEX_HTML, workspaces=workspaces)


@app.route("/workspace/<name>")
def workspace(name):
    findings = db.get_findings(name)
    services = db.get_services(name)
    if not findings and not services:
        abort(404)
    # Attach a status to each finding so the template can badge it
    findings = [dict(f, status=classify(f["raw_output"])) for f in findings]
    stats = summarize(services, findings)
    return render_template_string(
        WORKSPACE_HTML, workspace=name, findings=findings,
        services=services, stats=stats
    )


if __name__ == "__main__":
    db.init_db()  # make sure the DB/table exists
    print("[*] Open http://127.0.0.1:5000 in your browser")
    app.run(debug=True, host="127.0.0.1", port=5000)