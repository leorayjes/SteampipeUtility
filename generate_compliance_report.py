#!/usr/bin/env python3
"""
generate_compliance_report.py

Generates a self-contained, filterable HTML report from a
Powerpipe AWS Compliance JSON benchmark result file.

Usage:
    python generate_compliance_report.py <path-to-result.json> [--output report.html]
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=logging.INFO,
)
LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a styled HTML report from an AWS Compliance benchmark JSON."
    )
    parser.add_argument("input", help="Path to the benchmark result JSON file.")
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output HTML file path. Defaults to reports/aws_compliance.html.",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Data extraction
# ---------------------------------------------------------------------------

STATUS_ORDER = ["alarm", "error", "ok", "info", "skip"]


def extract_service_groups(data: dict) -> list[dict]:
    """Return the service-level groups (depth 2) with summaries."""
    try:
        groups = data["groups"][0]["groups"]
    except (KeyError, IndexError):
        LOGGER.warning("Could not locate service groups in JSON.")
        return []

    services = []
    for group in groups:
        summary = group.get("summary", {}).get("status", {})
        total   = sum(summary.get(s, 0) for s in STATUS_ORDER)
        ok      = summary.get("ok", 0)
        alarm   = summary.get("alarm", 0)
        error   = summary.get("error", 0)
        info    = summary.get("info", 0)
        skip    = summary.get("skip", 0)
        pass_pct = round((ok / total) * 100) if total > 0 else None

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

        services.append({
            "title":    group.get("title", ""),
            "status":   status,
            "alarm":    alarm,
            "ok":       ok,
            "error":    error,
            "info":     info,
            "skip":     skip,
            "total":    total,
            "pass_pct": pass_pct,
        })

    return services


def extract_controls(data: dict) -> list[dict]:
    """Flatten all controls from the benchmark tree into a single list."""
    controls: list[dict] = []
    # Service groups sit at depth 2 — directly under data['groups'][0]['groups']
    try:
        service_groups = data["groups"][0]["groups"]
    except (KeyError, IndexError):
        return controls
    for group in service_groups:
        _walk(group, service=group.get("title", "Unknown"), controls=controls)
    return controls


def _walk(node: dict, service: str, controls: list) -> None:
    for ctrl in (node.get("controls") or []):
        summary  = ctrl.get("summary") or {}
        results  = ctrl.get("results") or []
        ctrl_svc = (ctrl.get("tags") or {}).get("service", service or "Unknown")
        severity = ctrl.get("severity") or ""

        total = sum(summary.get(s, 0) for s in STATUS_ORDER)
        alarm = summary.get("alarm", 0)
        ok    = summary.get("ok", 0)
        error = summary.get("error", 0)
        info  = summary.get("info", 0)
        skip  = summary.get("skip", 0)

        pass_pct = round((ok / total) * 100) if total > 0 else None

        if error > 0:
            ctrl_status = "error"
        elif alarm > 0:
            ctrl_status = "alarm"
        elif ok > 0:
            ctrl_status = "ok"
        elif info > 0:
            ctrl_status = "info"
        else:
            ctrl_status = "skip"

        account_ids = sorted(set(
            d["value"]
            for r in results
            for d in (r.get("dimensions") or [])
            if d.get("key") == "account_id" and d.get("value")
        ))

        regions = sorted(set(
            d["value"]
            for r in results
            for d in (r.get("dimensions") or [])
            if d.get("key") == "region" and d.get("value")
        ))

        controls.append({
            "id":          ctrl.get("control_id", ""),
            "title":       ctrl.get("title", ""),
            "description": ctrl.get("description", ""),
            "service":     service,
            "ctrl_service":ctrl_svc,
            "severity":    severity,
            "status":      ctrl_status,
            "alarm":       alarm,
            "ok":          ok,
            "error":       error,
            "info":        info,
            "skip":        skip,
            "total":       total,
            "pass_pct":    pass_pct,
            "results":     results,
            "account_ids": account_ids,
            "regions":     regions,
        })

    for group in (node.get("groups") or []):
        _walk(group, service, controls)


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
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0f1117;
  --surface:#1a1d27;
  --surface2:#22263a;
  --border:#2e3250;
  --accent:#4f9cf9;
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
.page{{max-width:1400px;margin:0 auto;padding:24px 16px}}
header{{margin-bottom:32px}}
header h1{{font-size:1.6rem;font-weight:700;color:var(--accent);margin-bottom:4px}}
header p{{color:var(--muted);font-size:.875rem}}

/* ── Summary cards ────────────────────────────────────────── */
.summary-row{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}}
.summary-card{{flex:1;min-width:110px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;text-align:center}}
.summary-card .val{{font-size:1.8rem;font-weight:700;line-height:1}}
.summary-card .lbl{{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-top:4px}}
.summary-card.alarm .val{{color:var(--alarm)}}
.summary-card.ok    .val{{color:var(--ok)}}
.summary-card.error .val{{color:var(--error)}}
.summary-card.info  .val{{color:var(--info)}}
.summary-card.skip  .val{{color:var(--skip)}}
.summary-card.total .val{{color:var(--accent)}}

/* ── Service grid ─────────────────────────────────────────── */
.section-title{{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:12px}}
.service-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:32px}}
.svc-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 14px;cursor:pointer;transition:border-color .15s}}
.svc-card:hover{{border-color:var(--accent)}}
.svc-card.active{{border-color:var(--accent);background:rgba(79,156,249,.06)}}
.svc-card .svc-name{{font-size:.82rem;font-weight:600;color:var(--text);margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.svc-bar{{height:4px;border-radius:99px;background:var(--surface2);overflow:hidden;margin-bottom:6px}}
.svc-bar-fill{{height:100%;border-radius:99px;background:linear-gradient(90deg,var(--ok),var(--accent))}}
.svc-bar-fill.all-error{{background:var(--error)}}
.svc-bar-fill.all-alarm{{background:var(--alarm)}}
.svc-bar-fill.all-skip{{background:var(--skip)}}
.svc-pills{{display:flex;gap:4px;flex-wrap:wrap}}
.pill{{display:inline-flex;align-items:center;font-size:.66rem;font-weight:600;padding:1px 6px;border-radius:99px}}
.pill.alarm{{background:var(--alarm-bg);color:var(--alarm)}}
.pill.ok   {{background:var(--ok-bg);color:var(--ok)}}
.pill.error{{background:var(--error-bg);color:var(--error)}}
.pill.skip {{background:var(--skip-bg);color:var(--skip)}}

/* ── Filters ──────────────────────────────────────────────── */
.filters{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:20px;display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end}}
.filter-group{{display:flex;flex-direction:column;gap:4px;min-width:140px;flex:1}}
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

/* ── Table ────────────────────────────────────────────────── */
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
td.title-cell{{max-width:360px}}
td.title-cell .ctrl-title{{font-weight:500;color:var(--text);cursor:pointer}}
td.title-cell .ctrl-title:hover{{color:var(--accent)}}
td.title-cell .ctrl-id{{font-family:var(--mono);font-size:.68rem;color:var(--muted);margin-top:2px}}
td.svc-cell{{white-space:nowrap;color:var(--muted);font-size:.78rem}}
td.bar-cell{{min-width:90px}}
.mini-bar{{height:4px;background:var(--surface2);border-radius:99px;overflow:hidden;margin-top:4px}}
.mini-bar-fill{{height:100%;background:linear-gradient(90deg,var(--ok),var(--accent));border-radius:99px}}
.pct{{font-size:.75rem;color:var(--muted)}}

/* ── Status badge ─────────────────────────────────────────── */
.badge{{display:inline-flex;align-items:center;gap:4px;font-size:.72rem;font-weight:600;padding:2px 8px;border-radius:99px;white-space:nowrap}}
.badge::before{{content:'';width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}}
.badge.alarm{{background:var(--alarm-bg);color:var(--alarm)}}
.badge.ok   {{background:var(--ok-bg);color:var(--ok)}}
.badge.error{{background:var(--error-bg);color:var(--error)}}
.badge.info {{background:var(--info-bg);color:var(--info)}}
.badge.skip {{background:var(--skip-bg);color:var(--skip)}}

/* ── Detail rows ──────────────────────────────────────────── */
.detail-row td{{padding:0}}
.detail-row.hidden{{display:none}}
.detail-inner{{padding:14px 20px 20px;background:var(--surface);border-top:1px solid var(--border)}}
.detail-desc{{color:var(--muted);font-size:.82rem;margin-bottom:14px;line-height:1.6}}
.detail-heading{{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin-bottom:8px;margin-top:14px}}
.results-table{{width:100%;border-collapse:collapse;font-size:.78rem}}
.results-table th{{background:var(--surface2);padding:6px 10px;text-align:left;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em}}
.results-table td{{padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
.results-table tr:last-child td{{border-bottom:none}}
.results-table .reason{{font-family:var(--font);font-size:.78rem;color:var(--text)}}
.results-table .resource{{color:var(--muted);word-break:break-all;font-family:var(--mono);font-size:.72rem}}
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

@media(max-width:768px){{
  th,td{{padding:8px 10px}}
  td.svc-cell{{display:none}}
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

<!-- Service grid -->
<div class="section-title">Services — click to filter</div>
<div class="service-grid" id="service-grid">
{service_cards}
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
    <label>Region</label>
    <select id="f-region">
      <option value="">All regions</option>
      {region_options}
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
      <th data-col="status" class="sorted" data-dir="asc">Status <span class="sort-icon">↕</span></th>
      <th data-col="title">Control <span class="sort-icon">↕</span></th>
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
  <span>AWS Compliance — Audit Report</span>
  <span>Steampipe &amp; Powerpipe</span>
</footer>

</div>

<script>
const CONTROLS = {controls_json};

let filtered    = [...CONTROLS];
let sortCol     = 'status';
let sortDir     = 'asc';
let currentPage = 1;
let pageSize    = 25;
let activeService = '';
const STATUS_ORDER = {{alarm:0,error:1,ok:2,info:3,skip:4}};

// ── Service card click ────────────────────────────────────────────────────
document.querySelectorAll('.svc-card[data-service]').forEach(card => {{
  card.addEventListener('click', () => {{
    const val = card.dataset.service;
    if (activeService === val) {{
      activeService = '';
      card.classList.remove('active');
      document.getElementById('f-service').value = '';
    }} else {{
      document.querySelectorAll('.svc-card').forEach(c => c.classList.remove('active'));
      card.classList.add('active');
      activeService = val;
      document.getElementById('f-service').value = val;
    }}
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
['f-search','f-status','f-service','f-account','f-region','f-pagesize'].forEach(id => {{
  const el = document.getElementById(id);
  el.addEventListener(id === 'f-search' ? 'input' : 'change', () => {{
    if (id === 'f-service') {{
      activeService = el.value;
      document.querySelectorAll('.svc-card').forEach(c => {{
        c.classList.toggle('active', c.dataset.service === activeService && activeService !== '');
      }});
    }}
    applyFilters();
  }});
}});

function applyFilters() {{
  const search  = document.getElementById('f-search').value.toLowerCase().trim();
  const status  = document.getElementById('f-status').value;
  const service = document.getElementById('f-service').value;
  const account = document.getElementById('f-account').value;
  const region  = document.getElementById('f-region').value;
  pageSize = parseInt(document.getElementById('f-pagesize').value) || 0;
  currentPage = 1;

  filtered = CONTROLS.filter(c => {{
    if (status  && c.status  !== status)               return false;
    if (service && c.service !== service)               return false;
    if (account && !c.account_ids.includes(account))   return false;
    if (region  && !c.regions.includes(region))        return false;
    if (search) {{
      const hay = (c.title + ' ' + c.id + ' ' + c.description + ' ' + c.service).toLowerCase();
      if (!hay.includes(search)) return false;
    }}
    return true;
  }});
  render();
}}

function resetFilters() {{
  document.getElementById('f-search').value   = '';
  document.getElementById('f-status').value   = '';
  document.getElementById('f-service').value  = '';
  document.getElementById('f-account').value  = '';
  document.getElementById('f-region').value   = '';
  document.getElementById('f-pagesize').value = '25';
  pageSize = 25;
  activeService = '';
  document.querySelectorAll('.svc-card').forEach(c => c.classList.remove('active'));
  filtered = [...CONTROLS];
  currentPage = 1;
  render();
}}

function sortedData() {{
  return [...filtered].sort((a, b) => {{
    let av = a[sortCol], bv = b[sortCol];
    if (sortCol === 'status') {{ av = STATUS_ORDER[av]??99; bv = STATUS_ORDER[bv]??99; }}
    if (sortCol === 'pass_pct') {{ av = av===null?-1:av; bv = bv===null?-1:bv; }}
    if (typeof av === 'string') av = av.toLowerCase();
    if (typeof bv === 'string') bv = bv.toLowerCase();
    if (av < bv) return sortDir==='asc'?-1:1;
    if (av > bv) return sortDir==='asc'?1:-1;
    return 0;
  }});
}}

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

  slice.forEach(c => {{
    const pct    = c.pass_pct !== null ? c.pass_pct : null;
    const pctStr = pct !== null ? pct + '%' : '—';
    const barW   = pct !== null ? pct : 0;

    const tr = document.createElement('tr');
    tr.className = 'ctrl-row';
    tr.innerHTML = `
      <td><span class="badge ${{c.status}}">${{c.status}}</span></td>
      <td class="title-cell">
        <div class="ctrl-title" onclick="toggleDetail(this)">${{esc(c.title)}}</div>
        <div class="ctrl-id">${{esc(c.id)}}</div>
      </td>
      <td class="svc-cell">${{esc(c.service)}}</td>
      <td>${{c.alarm>0?`<span style="color:var(--alarm);font-weight:600">${{c.alarm}}</span>`:'<span style="color:var(--muted)">0</span>'}}</td>
      <td>${{c.ok>0?`<span style="color:var(--ok);font-weight:600">${{c.ok}}</span>`:'<span style="color:var(--muted)">0</span>'}}</td>
      <td class="bar-cell">
        <span class="pct">${{pctStr}}</span>
        ${{pct!==null?`<div class="mini-bar"><div class="mini-bar-fill" style="width:${{barW}}%"></div></div>`:''}}
      </td>`;
    tbody.appendChild(tr);

    const dr = document.createElement('tr');
    dr.className = 'detail-row hidden';
    dr.innerHTML = `<td colspan="6"><div class="detail-inner">
      <div class="detail-desc">${{esc(c.description)}}</div>
      <div class="detail-heading">Results (${{c.results.length}})</div>
      ${{buildResultsHtml(c)}}
    </div></td>`;
    tbody.appendChild(dr);
  }});

  renderPagination(pages, total, ps);
}}

function buildResultsHtml(c) {{
  if (!c.results || c.results.length === 0)
    return '<div class="no-results">No individual result rows available.</div>';
  const rows = c.results.slice(0,200).map(r => {{
    const region = (r.dimensions||[]).find(d=>d.key==='region')?.value||'';
    const acct   = (r.dimensions||[]).find(d=>d.key==='account_id')?.value||'';
    return `<tr>
      <td><span class="badge ${{r.status}}">${{r.status}}</span></td>
      <td class="reason">${{esc(r.reason||'')}}</td>
      <td class="resource">${{esc(r.resource||'')}}</td>
      <td style="color:var(--muted);white-space:nowrap">${{esc(region)}}</td>
      <td style="color:var(--muted);white-space:nowrap">${{esc(acct)}}</td>
    </tr>`;
  }}).join('');
  const extra = c.results.length>200
    ?`<tr><td colspan="5" style="color:var(--muted);font-style:italic;padding:8px 10px">… and ${{c.results.length-200}} more rows</td></tr>`:'';
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
  if (pages<=1) {{ pg.innerHTML=''; return; }}
  let html = `<span class="page-info">${{total}} results</span>`;
  html += `<button onclick="goPage(${{currentPage-1}})" ${{currentPage===1?'disabled':''}}>‹ Prev</button>`;
  const range=[];
  for(let i=1;i<=pages;i++) {{
    if(i===1||i===pages||Math.abs(i-currentPage)<=2) range.push(i);
    else if(range[range.length-1]!=='…') range.push('…');
  }}
  range.forEach(p=>{{
    if(p==='…') html+=`<span style="color:var(--muted);padding:0 4px">…</span>`;
    else html+=`<button class="${{p===currentPage?'active':''}}" onclick="goPage(${{p}})">${{p}}</button>`;
  }});
  html+=`<button onclick="goPage(${{currentPage+1}})" ${{currentPage===pages?'disabled':''}}>Next ›</button>`;
  pg.innerHTML=html;
}}

function goPage(p) {{
  currentPage=p;
  render();
  window.scrollTo({{top:document.getElementById('controls-table').offsetTop-20,behavior:'smooth'}});
}}

function esc(s) {{
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

applyFilters();
</script>
</body>
</html>"""


SVC_CARD_TEMPLATE = """\
<div class="svc-card" data-service="{name}">
  <div class="svc-name" title="{name}">{name}</div>
  <div class="svc-bar"><div class="svc-bar-fill{bar_class}" style="width:{pass_pct}%"></div></div>
  <div class="svc-pills">{pills}</div>
</div>"""


def build_service_cards(services: list[dict]) -> str:
    cards = []
    for svc in services:
        pct   = svc["pass_pct"] if svc["pass_pct"] is not None else 0
        total = svc["total"]

        if total == 0:
            bar_class = " all-skip"
        elif svc["error"] > 0 and svc["alarm"] == 0 and svc["ok"] == 0:
            bar_class = " all-error"
        elif pct == 0:
            bar_class = " all-alarm"
        else:
            bar_class = ""

        pills = []
        if svc["alarm"]:
            pills.append(f'<span class="pill alarm">{svc["alarm"]}</span>')
        if svc["ok"]:
            pills.append(f'<span class="pill ok">{svc["ok"]}</span>')
        if svc["error"]:
            pills.append(f'<span class="pill error">{svc["error"]} err</span>')
        if svc["skip"]:
            pills.append(f'<span class="pill skip">{svc["skip"]} skip</span>')
        if not pills:
            pills.append('<span class="pill skip">—</span>')

        cards.append(SVC_CARD_TEMPLATE.format(
            name=svc["title"],
            pass_pct=pct,
            bar_class=bar_class,
            pills="".join(pills),
        ))
    return "\n".join(cards)


def build_options(values: list) -> str:
    return "\n".join(f'<option value="{v}">{v}</option>' for v in sorted(values) if v)


def generate_html(data: dict, account_id: str) -> str:
    root_summary = data.get("summary", {}).get("status", {})
    services = extract_service_groups(data)
    controls = extract_controls(data)

    service_names = [s["title"] for s in services]
    account_ids   = sorted(set(a for c in controls for a in c["account_ids"]))
    region_ids    = sorted(set(r for c in controls for r in c["regions"]))

    title = data.get("groups", [{}])[0].get("title", "AWS Compliance")
    generated = datetime.now().strftime("%B %d, %Y at %H:%M")

    return HTML_TEMPLATE.format(
        title=title,
        generated=generated,
        account_id=account_id,
        total_controls=len(controls),
        total_alarm=root_summary.get("alarm", 0),
        total_ok=root_summary.get("ok", 0),
        total_error=root_summary.get("error", 0),
        total_info=root_summary.get("info", 0),
        total_skip=root_summary.get("skip", 0),
        service_cards=build_service_cards(services),
        service_options="\n".join(
            f'<option value="{s}">{s}</option>' for s in service_names
        ),
        account_options=build_options(account_ids),
        region_options=build_options(region_ids),
        controls_json=json.dumps(controls, separators=(",", ":")),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    input_path = Path(args.input).resolve()

    if not input_path.exists():
        LOGGER.error("File not found: %s", input_path)
        sys.exit(1)

    output_path = (
        Path(args.output).resolve()
        if args.output
        else Path(__file__).parent / "reports" / "aws_compliance.html"
    )

    LOGGER.info("Reading %s...", input_path.name)
    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    account_id = input_path.stem.split("_")[0] if input_path.stem[0].isdigit() else "unknown"

    LOGGER.info("Generating report...")
    html = generate_html(data, account_id)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    LOGGER.info("Report written to %s", output_path)


if __name__ == "__main__":
    main()
