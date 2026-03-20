#!/usr/bin/env python3
"""
generate_well_architected_report.py

Generates a self-contained, filterable HTML report from a
Powerpipe AWS Well-Architected JSON benchmark result file.

Usage:
    python generate_well_architected_report.py <path-to-result.json> [--output report.html]
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a styled HTML report from a Well-Architected benchmark JSON."
    )
    parser.add_argument("input", help="Path to the benchmark result JSON file.")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output HTML file path. Defaults to <input-stem>_report.html alongside the input file.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------

STATUS_ORDER = ["alarm", "error", "ok", "info", "skip"]

# Canonical display names for Well-Architected pillar IDs.
PILLAR_NAMES = {
    "operationalExcellence": "Operational Excellence",
    "reliability":           "Reliability",
    "security":              "Security",
    "performance":           "Performance Efficiency",
    "costOptimization":      "Cost Optimization",
    "sustainability":        "Sustainability",
}

def extract_controls(node, pillar="", question="", best_practice="", controls=None):
    """Recursively walk the group tree and collect all controls into a flat list."""
    if controls is None:
        controls = []

    depth = node.get("_depth", 0)
    title = node.get("title", "")
    tags  = node.get("tags", {}) or {}

    # Use pillar_id tag to identify the pillar level unambiguously.
    # pillar_id appears on both pillar groups and question groups, so we
    # only update the pillar label when we first encounter it (depth 2).
    pillar_id = tags.get("pillar_id", "")
    if pillar_id and depth == 2:
        pillar = PILLAR_NAMES.get(pillar_id, title)
    elif depth == 3:
        question = title
    elif depth == 4:
        best_practice = title

    for group in (node.get("groups") or []):
        group["_depth"] = depth + 1
        extract_controls(group, pillar, question, best_practice, controls)

    for ctrl in (node.get("controls") or []):
        summary = ctrl.get("summary") or {}
        results = ctrl.get("results") or []
        service = (ctrl.get("tags") or {}).get("service", "Unknown")
        severity = ctrl.get("severity") or ""

        total = sum(summary.get(s, 0) for s in STATUS_ORDER)
        alarm = summary.get("alarm", 0)
        ok    = summary.get("ok", 0)
        error = summary.get("error", 0)
        info  = summary.get("info", 0)
        skip  = summary.get("skip", 0)

        if total > 0:
            pass_pct = round((ok / total) * 100)
        else:
            pass_pct = None

        # Determine overall status for the control
        if error > 0:
            status = "error"
        elif alarm > 0:
            status = "alarm"
        elif ok > 0:
            status = "ok"
        elif info > 0:
            status = "info"
        else:
            status = "skip"

        controls.append({
            "id":           ctrl.get("control_id", ""),
            "title":        ctrl.get("title", ""),
            "description":  ctrl.get("description", ""),
            "pillar":       pillar,
            "question":     question,
            "best_practice":best_practice,
            "service":      service,
            "severity":     severity,
            "status":       status,
            "alarm":        alarm,
            "ok":           ok,
            "error":        error,
            "info":         info,
            "skip":         skip,
            "total":        total,
            "pass_pct":     pass_pct,
            "results":      results,
            "account_ids":  sorted(set(
                d["value"]
                for r in results
                for d in (r.get("dimensions") or [])
                if d.get("key") == "account_id" and d.get("value")
            )),
        })

    return controls


def extract_pillars(data):
    """Return top-level pillar summaries."""
    try:
        return data["groups"][0]["groups"]
    except (KeyError, IndexError):
        return []


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{title} — Audit Report</title>
<style>
/* ── Reset & base ─────────────────────────────────────────── */
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0f1117;
  --surface:#1a1d27;
  --surface2:#22263a;
  --border:#2e3250;
  --accent:#4f9cf9;
  --accent2:#818cf8;
  --text:#e2e8f0;
  --muted:#64748b;
  --alarm:#ef4444;
  --alarm-bg:rgba(239,68,68,.12);
  --ok:#22c55e;
  --ok-bg:rgba(34,197,94,.12);
  --error:#f97316;
  --error-bg:rgba(249,115,22,.12);
  --info:#38bdf8;
  --info-bg:rgba(56,189,248,.12);
  --skip:#94a3b8;
  --skip-bg:rgba(148,163,184,.1);
  --radius:8px;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  --mono:"SF Mono","Fira Code",Consolas,monospace;
}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6;min-height:100vh}}

/* ── Layout ───────────────────────────────────────────────── */
.page{{max-width:1400px;margin:0 auto;padding:24px 16px}}
header{{margin-bottom:32px}}
header h1{{font-size:1.6rem;font-weight:700;color:var(--accent);margin-bottom:4px}}
header p{{color:var(--muted);font-size:.875rem}}

/* ── Pillar cards ─────────────────────────────────────────── */
.pillars{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;margin-bottom:32px}}
.pillar-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px}}
.pillar-card h3{{font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:10px}}
.pillar-card .pillar-title{{font-size:.95rem;font-weight:600;color:var(--text);margin-bottom:12px}}
.pillar-bar{{height:6px;border-radius:99px;background:var(--surface2);overflow:hidden;margin-bottom:8px}}
.pillar-bar-fill{{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--ok),var(--accent))}}
.pillar-stats{{display:flex;gap:10px;flex-wrap:wrap}}
.pill{{display:inline-flex;align-items:center;gap:4px;font-size:.72rem;font-weight:600;padding:2px 8px;border-radius:99px}}
.pill.alarm{{background:var(--alarm-bg);color:var(--alarm)}}
.pill.ok{{background:var(--ok-bg);color:var(--ok)}}
.pill.error{{background:var(--error-bg);color:var(--error)}}
.pill.info{{background:var(--info-bg);color:var(--info)}}
.pill.skip{{background:var(--skip-bg);color:var(--skip)}}

/* ── Summary row ──────────────────────────────────────────── */
.summary-row{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
.summary-card{{flex:1;min-width:120px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;text-align:center}}
.summary-card .val{{font-size:1.8rem;font-weight:700;line-height:1}}
.summary-card .lbl{{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-top:4px}}
.summary-card.alarm .val{{color:var(--alarm)}}
.summary-card.ok    .val{{color:var(--ok)}}
.summary-card.error .val{{color:var(--error)}}
.summary-card.info  .val{{color:var(--info)}}
.summary-card.skip  .val{{color:var(--skip)}}
.summary-card.total .val{{color:var(--accent)}}

/* ── Filters ──────────────────────────────────────────────── */
.filters{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:20px;display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}}
.filter-group{{display:flex;flex-direction:column;gap:4px;min-width:160px;flex:1}}
.filter-group label{{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}}
.filter-group input,
.filter-group select{{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.85rem;padding:7px 10px;outline:none;transition:border-color .15s;width:100%}}
.filter-group input:focus,
.filter-group select:focus{{border-color:var(--accent)}}
.filter-group select option{{background:var(--surface2)}}
.btn-reset{{padding:7px 16px;background:transparent;border:1px solid var(--border);border-radius:6px;color:var(--muted);font-size:.85rem;cursor:pointer;transition:border-color .15s,color .15s;white-space:nowrap;align-self:flex-end}}
.btn-reset:hover{{border-color:var(--accent);color:var(--accent)}}

/* ── Results count ────────────────────────────────────────── */
#results-count{{font-size:.8rem;color:var(--muted);margin-bottom:12px}}

/* ── Controls table ───────────────────────────────────────── */
.table-wrap{{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius)}}
table{{width:100%;border-collapse:collapse;font-size:.82rem}}
thead tr{{background:var(--surface2)}}
th{{text-align:left;padding:10px 14px;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);white-space:nowrap;border-bottom:1px solid var(--border);cursor:pointer;user-select:none}}
th:hover{{color:var(--accent)}}
th .sort-icon{{opacity:.4;margin-left:4px}}
th.sorted .sort-icon{{opacity:1;color:var(--accent)}}
td{{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:rgba(79,156,249,.04)}}
tr.expanded td{{background:rgba(79,156,249,.06)}}
td.status-cell{{white-space:nowrap}}
td.title-cell{{max-width:360px}}
td.title-cell .ctrl-title{{font-weight:500;color:var(--text);cursor:pointer}}
td.title-cell .ctrl-title:hover{{color:var(--accent)}}
td.title-cell .ctrl-id{{font-family:var(--mono);font-size:.68rem;color:var(--muted);margin-top:2px}}
td.bar-cell{{min-width:100px}}
.mini-bar{{height:4px;background:var(--surface2);border-radius:99px;overflow:hidden;margin-top:4px}}
.mini-bar-fill{{height:100%;background:linear-gradient(90deg,var(--ok),var(--accent));border-radius:99px}}
.pct{{font-size:.75rem;color:var(--muted)}}
td.service-cell{{white-space:nowrap;color:var(--muted)}}
td.pillar-cell{{white-space:nowrap;color:var(--muted);font-size:.78rem}}

/* ── Status badge ─────────────────────────────────────────── */
.badge{{display:inline-flex;align-items:center;gap:4px;font-size:.72rem;font-weight:600;padding:2px 8px;border-radius:99px;white-space:nowrap}}
.badge::before{{content:'';width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}}
.badge.alarm{{background:var(--alarm-bg);color:var(--alarm)}}
.badge.ok{{background:var(--ok-bg);color:var(--ok)}}
.badge.error{{background:var(--error-bg);color:var(--error)}}
.badge.info{{background:var(--info-bg);color:var(--info)}}
.badge.skip{{background:var(--skip-bg);color:var(--skip)}}

/* ── Expanded row detail ──────────────────────────────────── */
.detail-row td{{padding:0}}
.detail-row.hidden{{display:none}}
.detail-inner{{padding:14px 20px 20px;background:var(--surface);border-top:1px solid var(--border)}}
.detail-desc{{color:var(--muted);font-size:.82rem;margin-bottom:14px;line-height:1.6}}
.detail-heading{{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:8px;margin-top:14px}}
.results-table{{width:100%;border-collapse:collapse;font-size:.78rem}}
.results-table th{{background:var(--surface2);padding:6px 10px;text-align:left;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em}}
.results-table td{{padding:6px 10px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:.72rem;vertical-align:top}}
.results-table tr:last-child td{{border-bottom:none}}
.results-table .reason{{font-family:var(--font);font-size:.78rem;color:var(--text)}}
.results-table .resource{{color:var(--muted);word-break:break-all}}
.no-results{{color:var(--muted);font-size:.82rem;font-style:italic}}

/* ── Pagination ───────────────────────────────────────────── */
.pagination{{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:16px;flex-wrap:wrap}}
.pagination button{{background:var(--surface);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:.8rem;padding:5px 12px;cursor:pointer;transition:border-color .15s,color .15s}}
.pagination button:hover:not(:disabled){{border-color:var(--accent);color:var(--accent)}}
.pagination button:disabled{{opacity:.35;cursor:not-allowed}}
.pagination button.active{{border-color:var(--accent);color:var(--accent);background:rgba(79,156,249,.1)}}
.pagination .page-info{{font-size:.78rem;color:var(--muted)}}

/* ── Footer ───────────────────────────────────────────────── */
footer{{margin-top:48px;padding-top:20px;border-top:1px solid var(--border);color:var(--muted);font-size:.78rem;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}}

/* ── Responsive ───────────────────────────────────────────── */
@media(max-width:768px){{
  .pillar-card h3{{font-size:.7rem}}
  th,td{{padding:8px 10px}}
  td.pillar-cell,td.service-cell{{display:none}}
}}
</style>
</head>
<body>
<div class="page">

<header>
  <h1>{title}</h1>
  <p>Generated {generated} &nbsp;·&nbsp; Account <strong>{account_id}</strong></p>
</header>

<!-- Summary cards -->
<div class="summary-row">
  <div class="summary-card total"><div class="val">{total_controls}</div><div class="lbl">Controls</div></div>
  <div class="summary-card alarm"><div class="val">{total_alarm}</div><div class="lbl">Alarm</div></div>
  <div class="summary-card ok">   <div class="val">{total_ok}</div>   <div class="lbl">OK</div></div>
  <div class="summary-card error"><div class="val">{total_error}</div><div class="lbl">Error</div></div>
  <div class="summary-card info"> <div class="val">{total_info}</div> <div class="lbl">Info</div></div>
  <div class="summary-card skip"> <div class="val">{total_skip}</div> <div class="lbl">Skip</div></div>
</div>

<!-- Pillar cards -->
<div class="pillars" id="pillar-cards">
{pillar_cards}
</div>

<!-- Filters -->
<div class="filters">
  <div class="filter-group" style="flex:2;min-width:200px">
    <label>Search</label>
    <input type="text" id="f-search" placeholder="Title, control ID, description…"/>
  </div>
  <div class="filter-group">
    <label>Status</label>
    <select id="f-status">
      <option value="">All statuses</option>
      <option value="alarm">Alarm</option>
      <option value="ok">OK</option>
      <option value="error">Error</option>
      <option value="info">Info</option>
      <option value="skip">Skip</option>
    </select>
  </div>
  <div class="filter-group">
    <label>Pillar</label>
    <select id="f-pillar">
      <option value="">All pillars</option>
      {pillar_options}
    </select>
  </div>
  <div class="filter-group">
    <label>Service</label>
    <select id="f-service">
      <option value="">All services</option>
      {service_options}
    </select>
  </div>
  <div class="filter-group">
    <label>Account ID</label>
    <select id="f-account">
      <option value="">All accounts</option>
      {account_options}
    </select>
  </div>
  <div class="filter-group">
    <label>Show</label>
    <select id="f-pagesize">
      <option value="25">25 / page</option>
      <option value="50">50 / page</option>
      <option value="100">100 / page</option>
      <option value="0">All</option>
    </select>
  </div>
  <button class="btn-reset" onclick="resetFilters()">Reset</button>
</div>

<div id="results-count"></div>

<!-- Table -->
<div class="table-wrap">
<table id="controls-table">
  <thead>
    <tr>
      <th data-col="status"  class="sorted" data-dir="asc">Status <span class="sort-icon">↕</span></th>
      <th data-col="title">Control <span class="sort-icon">↕</span></th>
      <th data-col="pillar">Pillar <span class="sort-icon">↕</span></th>
      <th data-col="service">Service <span class="sort-icon">↕</span></th>
      <th data-col="alarm">Alarm <span class="sort-icon">↕</span></th>
      <th data-col="ok">OK <span class="sort-icon">↕</span></th>
      <th data-col="pass_pct">Pass % <span class="sort-icon">↕</span></th>
    </tr>
  </thead>
  <tbody id="table-body"></tbody>
</table>
</div>

<div class="pagination" id="pagination"></div>

<footer>
  <span>AWS Well-Architected Audit Report</span>
  <span>Steampipe &amp; Powerpipe</span>
</footer>

</div><!-- .page -->

<script>
// ── Embedded data ─────────────────────────────────────────────────────────
const CONTROLS = {controls_json};

// ── State ─────────────────────────────────────────────────────────────────
let filtered   = [...CONTROLS];
let sortCol    = 'status';
let sortDir    = 'asc';
let currentPage = 1;
let pageSize   = 25;
const STATUS_ORDER = {{alarm:0,error:1,ok:2,info:3,skip:4}};

// ── Pillar card click filter ──────────────────────────────────────────────
document.querySelectorAll('.pillar-card[data-pillar]').forEach(card => {{
  card.style.cursor = 'pointer';
  card.addEventListener('click', () => {{
    const sel = document.getElementById('f-pillar');
    const val = card.dataset.pillar;
    sel.value = (sel.value === val) ? '' : val;
    applyFilters();
  }});
}});

// ── Sort ──────────────────────────────────────────────────────────────────
document.querySelectorAll('th[data-col]').forEach(th => {{
  th.addEventListener('click', () => {{
    const col = th.dataset.col;
    if (sortCol === col) {{ sortDir = sortDir === 'asc' ? 'desc' : 'asc'; }}
    else {{ sortCol = col; sortDir = 'asc'; }}
    document.querySelectorAll('th').forEach(t => t.classList.remove('sorted'));
    th.classList.add('sorted');
    th.querySelector('.sort-icon').textContent = sortDir === 'asc' ? '↑' : '↓';
    currentPage = 1;
    render();
  }});
}});

// ── Filters ───────────────────────────────────────────────────────────────
['f-search','f-status','f-pillar','f-service','f-account','f-pagesize'].forEach(id => {{
  const el = document.getElementById(id);
  el.addEventListener(id === 'f-search' ? 'input' : 'change', applyFilters);
}});

function applyFilters() {{
  const search  = document.getElementById('f-search').value.toLowerCase().trim();
  const status  = document.getElementById('f-status').value;
  const pillar  = document.getElementById('f-pillar').value;
  const service = document.getElementById('f-service').value;
  const account = document.getElementById('f-account').value;
  pageSize      = parseInt(document.getElementById('f-pagesize').value) || 0;
  currentPage   = 1;

  filtered = CONTROLS.filter(c => {{
    if (status  && c.status  !== status)  return false;
    if (pillar  && c.pillar  !== pillar)  return false;
    if (service && c.service !== service) return false;
    if (account && !c.account_ids.includes(account)) return false;
    if (search) {{
      const hay = (c.title + ' ' + c.id + ' ' + c.description + ' ' + c.question).toLowerCase();
      if (!hay.includes(search)) return false;
    }}
    return true;
  }});
  render();
}}

function resetFilters() {{
  document.getElementById('f-search').value  = '';
  document.getElementById('f-status').value  = '';
  document.getElementById('f-pillar').value  = '';
  document.getElementById('f-service').value = '';
  document.getElementById('f-account').value = '';
  document.getElementById('f-pagesize').value = '25';
  pageSize = 25;
  currentPage = 1;
  filtered = [...CONTROLS];
  render();
}}

// ── Sort comparator ───────────────────────────────────────────────────────
function sortedData() {{
  return [...filtered].sort((a, b) => {{
    let av = a[sortCol], bv = b[sortCol];
    if (sortCol === 'status') {{
      av = STATUS_ORDER[av] ?? 99;
      bv = STATUS_ORDER[bv] ?? 99;
    }}
    if (sortCol === 'pass_pct') {{
      av = av === null ? -1 : av;
      bv = bv === null ? -1 : bv;
    }}
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ?  1 : -1;
    return 0;
  }});
}}

// ── Render ────────────────────────────────────────────────────────────────
function render() {{
  const data  = sortedData();
  const total = data.length;
  const ps    = pageSize || total;
  const pages = ps > 0 ? Math.ceil(total / ps) : 1;
  if (currentPage > pages) currentPage = pages || 1;

  const start = (currentPage - 1) * ps;
  const slice = ps > 0 ? data.slice(start, start + ps) : data;

  document.getElementById('results-count').textContent =
    `Showing ${{slice.length}} of ${{total}} control${{total !== 1 ? 's' : ''}}`;

  const tbody = document.getElementById('table-body');
  tbody.innerHTML = '';

  slice.forEach((c, i) => {{
    const pct   = c.pass_pct !== null ? c.pass_pct : null;
    const pctStr = pct !== null ? pct + '%' : '—';
    const barW   = pct !== null ? pct : 0;

    // Main row
    const tr = document.createElement('tr');
    tr.className = 'ctrl-row';
    tr.dataset.idx = i;
    tr.innerHTML = `
      <td class="status-cell"><span class="badge ${{c.status}}">${{c.status}}</span></td>
      <td class="title-cell">
        <div class="ctrl-title" onclick="toggleDetail(this)">${{esc(c.title)}}</div>
        <div class="ctrl-id">${{esc(c.id)}}</div>
      </td>
      <td class="pillar-cell">${{esc(shortPillar(c.pillar))}}</td>
      <td class="service-cell">${{esc(c.service.replace('AWS/',''))}}</td>
      <td>${{c.alarm > 0 ? `<span style="color:var(--alarm);font-weight:600">${{c.alarm}}</span>` : '<span style="color:var(--muted)">0</span>'}}</td>
      <td>${{c.ok    > 0 ? `<span style="color:var(--ok);font-weight:600">${{c.ok}}</span>`    : '<span style="color:var(--muted)">0</span>'}}</td>
      <td class="bar-cell">
        <span class="pct">${{pctStr}}</span>
        ${{pct !== null ? `<div class="mini-bar"><div class="mini-bar-fill" style="width:${{barW}}%"></div></div>` : ''}}
      </td>`;
    tbody.appendChild(tr);

    // Detail row (hidden by default)
    const dr = document.createElement('tr');
    dr.className = 'detail-row hidden';
    const resultsHtml = buildResultsHtml(c);
    dr.innerHTML = `<td colspan="7"><div class="detail-inner">
      <div class="detail-desc">${{esc(c.description)}}</div>
      ${{c.question ? `<div class="detail-heading">Question</div><div style="color:var(--text);font-size:.82rem;margin-bottom:8px">${{esc(c.question)}}</div>` : ''}}
      ${{c.best_practice ? `<div class="detail-heading">Best Practice</div><div style="color:var(--text);font-size:.82rem;margin-bottom:8px">${{esc(c.best_practice)}}</div>` : ''}}
      <div class="detail-heading">Results (${{c.results.length}})</div>
      ${{resultsHtml}}
    </div></td>`;
    tbody.appendChild(dr);
  }});

  renderPagination(pages, total, ps);
}}

function buildResultsHtml(c) {{
  if (!c.results || c.results.length === 0) {{
    return '<div class="no-results">No individual result rows available.</div>';
  }}
  const rows = c.results.slice(0, 200).map(r => {{
    const region = (r.dimensions || []).find(d => d.key === 'region')?.value || '';
    const acct   = (r.dimensions || []).find(d => d.key === 'account_id')?.value || '';
    return `<tr>
      <td><span class="badge ${{r.status}}">${{r.status}}</span></td>
      <td class="reason">${{esc(r.reason || '')}}</td>
      <td class="resource">${{esc(r.resource || '')}}</td>
      <td style="color:var(--muted);white-space:nowrap">${{esc(region)}}</td>
      <td style="color:var(--muted);white-space:nowrap">${{esc(acct)}}</td>
    </tr>`;
  }}).join('');
  const extra = c.results.length > 200
    ? `<tr><td colspan="5" style="color:var(--muted);font-style:italic;padding:8px 10px">… and ${{c.results.length - 200}} more rows</td></tr>`
    : '';
  return `<div style="overflow-x:auto"><table class="results-table">
    <thead><tr><th>Status</th><th>Reason</th><th>Resource</th><th>Region</th><th>Account</th></tr></thead>
    <tbody>${{rows}}${{extra}}</tbody>
  </table></div>`;
}}

function toggleDetail(titleEl) {{
  const tr = titleEl.closest('tr');
  const dr = tr.nextElementSibling;
  const isOpen = !dr.classList.contains('hidden');
  dr.classList.toggle('hidden', isOpen);
  tr.classList.toggle('expanded', !isOpen);
}}

function renderPagination(pages, total, ps) {{
  const pg = document.getElementById('pagination');
  if (pages <= 1) {{ pg.innerHTML = ''; return; }}

  let html = `<span class="page-info">${{total}} results</span>`;
  html += `<button onclick="goPage(${{currentPage-1}})" ${{currentPage===1?'disabled':''}}>‹ Prev</button>`;

  // Show up to 7 page buttons with ellipsis
  const range = [];
  for (let i = 1; i <= pages; i++) {{
    if (i===1||i===pages||Math.abs(i-currentPage)<=2) range.push(i);
    else if (range[range.length-1]!=='…') range.push('…');
  }}
  range.forEach(p => {{
    if (p==='…') html += `<span style="color:var(--muted);padding:0 4px">…</span>`;
    else html += `<button class="${{p===currentPage?'active':''}}" onclick="goPage(${{p}})">${{p}}</button>`;
  }});

  html += `<button onclick="goPage(${{currentPage+1}})" ${{currentPage===pages?'disabled':''}}>Next ›</button>`;
  pg.innerHTML = html;
}}

function goPage(p) {{
  currentPage = p;
  render();
  window.scrollTo({{top:document.getElementById('controls-table').offsetTop - 20, behavior:'smooth'}});
}}

// ── Helpers ───────────────────────────────────────────────────────────────
function esc(s) {{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}
function shortPillar(p) {{
  const map = {{
    'Operational Excellence':'Ops Excellence',
    'Reliability':'Reliability',
    'Security':'Security',
    'Performance Efficiency':'Perf Efficiency',
    'Cost Optimization':'Cost Optimization',
    'Sustainability':'Sustainability',
  }};
  return map[p] || p;
}}

// ── Init ──────────────────────────────────────────────────────────────────
applyFilters();
</script>
</body>
</html>"""


PILLAR_CARD_TEMPLATE = """<div class="pillar-card" data-pillar="{pillar}">
  <h3>Pillar</h3>
  <div class="pillar-title">{pillar}</div>
  <div class="pillar-bar"><div class="pillar-bar-fill" style="width:{pass_pct}%"></div></div>
  <div class="pillar-stats">
    <span class="pill alarm">{alarm} alarm</span>
    <span class="pill ok">{ok} ok</span>
    {error_pill}
    {skip_pill}
  </div>
</div>"""


def build_pillar_cards(pillars: list) -> str:
    cards = []
    for p in pillars:
        s = p["summary"]["status"]
        total = sum(s.values())
        pass_pct = round((s.get("ok", 0) / total * 100)) if total else 0
        error_pill = f'<span class="pill error">{s["error"]} error</span>' if s.get("error") else ""
        skip_pill  = f'<span class="pill skip">{s["skip"]} skip</span>'   if s.get("skip")  else ""
        cards.append(PILLAR_CARD_TEMPLATE.format(
            pillar=p["title"],
            pass_pct=pass_pct,
            alarm=s.get("alarm", 0),
            ok=s.get("ok", 0),
            error_pill=error_pill,
            skip_pill=skip_pill,
        ))
    return "\n".join(cards)


def build_options(values: list, sort=True) -> str:
    if sort:
        values = sorted(values)
    return "\n".join(f'<option value="{v}">{v}</option>' for v in values if v)


def generate_html(data: dict, account_id: str) -> str:
    root_summary = data.get("summary", {}).get("status", {})
    pillars = extract_pillars(data)
    controls = extract_controls(data)

    pillar_names  = sorted(set(c["pillar"]  for c in controls if c["pillar"]))
    service_names = sorted(set(c["service"] for c in controls if c["service"]))
    account_ids   = sorted(set(
        acct
        for c in controls
        for acct in c["account_ids"]
    ))

    total_controls = len(controls)
    generated = datetime.now().strftime("%B %d, %Y at %H:%M")

    return HTML_TEMPLATE.format(
        title=data.get("groups", [{}])[0].get("title", "AWS Well-Architected Framework"),
        generated=generated,
        account_id=account_id,
        total_controls=total_controls,
        total_alarm=root_summary.get("alarm", 0),
        total_ok=root_summary.get("ok", 0),
        total_error=root_summary.get("error", 0),
        total_info=root_summary.get("info", 0),
        total_skip=root_summary.get("skip", 0),
        pillar_cards=build_pillar_cards(pillars),
        pillar_options=build_options(pillar_names),
        service_options=build_options(service_names),
        account_options=build_options(account_ids),
        controls_json=json.dumps(controls, separators=(",", ":")),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    input_path = Path(args.input).resolve()

    if not input_path.exists():
        print(f"[ERROR] File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = Path(args.output).resolve()
    else:
        output_path = Path(__file__).parent / "reports" / "aws_well_architected.html"

    print(f"[INFO]  Reading {input_path.name}...")
    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    # Infer account ID from filename (first numeric segment)
    account_id = input_path.stem.split("_")[0] if input_path.stem[0].isdigit() else "unknown"

    print("[INFO]  Generating report...")
    html = generate_html(data, account_id)

    output_path.write_text(html, encoding="utf-8")
    print(f"[INFO]  Report written to {output_path}")


if __name__ == "__main__":
    main()
