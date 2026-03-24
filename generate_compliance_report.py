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

# Meta tags that are not compliance programs.
_META_TAGS = {"category", "plugin", "service", "type"}

# Canonical display names for compliance program tag keys.
PROGRAM_NAMES: dict[str, str] = {
    "acsc_essential_eight":                  "ACSC Essential Eight",
    "acsc_essential_eight_ml_3":             "ACSC Essential Eight ML3",
    "audit_manager_control_tower":           "Audit Manager Control Tower",
    "cis_controls_v8_ig1":                   "CIS Controls v8 IG1",
    "cis_v120":                              "CIS v1.2.0",
    "cis_v130":                              "CIS v1.3.0",
    "cis_v140":                              "CIS v1.4.0",
    "cis_v150":                              "CIS v1.5.0",
    "cis_v200":                              "CIS v2.0.0",
    "cis_v300":                              "CIS v3.0.0",
    "cis_v400":                              "CIS v4.0.0",
    "cisa_cyber_essentials":                 "CISA Cyber Essentials",
    "fedramp_low_rev_4":                     "FedRAMP Low Rev 4",
    "fedramp_moderate_rev_4":                "FedRAMP Moderate Rev 4",
    "ffiec":                                 "FFIEC",
    "gdpr":                                  "GDPR",
    "gxp_21_cfr_part_11":                   "GxP 21 CFR Part 11",
    "gxp_eu_annex_11":                      "GxP EU Annex 11",
    "hipaa_final_omnibus_security_rule_2013":"HIPAA Final Omnibus 2013",
    "hipaa_security_rule_2003":              "HIPAA Security Rule 2003",
    "nist_800_171_rev_2":                   "NIST 800-171 Rev 2",
    "nist_800_53_rev_4":                    "NIST 800-53 Rev 4",
    "nist_800_53_rev_5":                    "NIST 800-53 Rev 5",
    "nist_csf":                             "NIST CSF v1.1",
    "nist_csf_v2":                          "NIST CSF v2.0",
    "nydfs_23":                             "NYDFS 23 NYCRR 500",
    "nydfs_23_common_tags":                 "NYDFS 23 (Common)",
    "pci_dss_v321":                         "PCI DSS v3.2.1",
    "pci_dss_v40":                          "PCI DSS v4.0",
    "rbi_cyber_security":                   "RBI Cyber Security",
    "rbi_itf_nbfc":                         "RBI ITF NBFC",
    "soc_2":                                "SOC 2",
}


def extract_service_groups(data: dict) -> list[dict]:
    """Return service-level group titles and ordering from the JSON tree.
    Actual summary counts are recomputed from deduped controls in generate_html()."""
    try:
        return [{"title": g.get("title", "")} for g in data["groups"][0]["groups"]]
    except (KeyError, IndexError):
        return []


def compute_service_summaries(service_titles: list[dict], controls: list[dict]) -> list[dict]:
    """Build service summaries recomputed from the already-deduped control list."""
    from collections import defaultdict
    svc_alarm  = defaultdict(int)
    svc_ok     = defaultdict(int)
    svc_error  = defaultdict(int)
    svc_info   = defaultdict(int)
    svc_skip   = defaultdict(int)

    for c in controls:
        s = c["service"]
        svc_alarm[s]  += c["alarm"]
        svc_ok[s]     += c["ok"]
        svc_error[s]  += c["error"]
        svc_info[s]   += c["info"]
        svc_skip[s]   += c["skip"]

    services = []
    for entry in service_titles:
        n     = entry["title"]
        alarm = svc_alarm[n]
        ok    = svc_ok[n]
        error = svc_error[n]
        info  = svc_info[n]
        skip  = svc_skip[n]
        total = alarm + ok + error + info + skip
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
            "title":    n,
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


def _arn_account(resource: str) -> str:
    """Extract the account ID embedded in an AWS ARN, or empty string if not present."""
    # ARN format: arn:partition:service:region:account-id:resource
    parts = resource.split(":")
    if len(parts) >= 5 and parts[0] == "arn" and parts[4].isdigit() and len(parts[4]) == 12:
        return parts[4]
    return ""


def _walk(node: dict, service: str, controls: list) -> None:
    for ctrl in (node.get("controls") or []):
        ctrl_svc = (ctrl.get("tags") or {}).get("service", service or "Unknown")
        severity = ctrl.get("severity") or ""

        # Deduplicate result rows by (resource, status) within this control.
        # The same resource can appear once per compliance framework it belongs
        # to, or once per member account that sees a shared payer-account resource.
        # Deduplication produces one row per unique resource outcome.
        #
        # Attribution rule: if the account ID embedded in the resource ARN
        # differs from the dimension account_id, the resource originates in the
        # ARN account (e.g. a payer-account CloudTrail seen by a member account).
        # In that case we rewrite the account_id dimension to the ARN account so
        # the finding is attributed to the account that owns the resource.
        raw_results = ctrl.get("results") or []
        seen_keys: set = set()
        results: list = []
        for r in raw_results:
            key = (r.get("resource", ""), r.get("status", ""))
            if key not in seen_keys:
                seen_keys.add(key)
                dims = r.get("dimensions") or []
                dim_account = next(
                    (d["value"] for d in dims if d.get("key") == "account_id"), ""
                )
                arn_account = _arn_account(r.get("resource", ""))
                # If the resource belongs to a different account than the querying
                # account, attribute it to the resource owner (ARN account).
                if arn_account and arn_account != dim_account:
                    new_dims = [
                        {"key": d["key"], "value": arn_account}
                        if d.get("key") == "account_id"
                        else d
                        for d in dims
                    ]
                    # If no account_id dimension existed, add one
                    if not any(d.get("key") == "account_id" for d in dims):
                        new_dims = list(dims) + [{"key": "account_id", "value": arn_account}]
                    r = dict(r, dimensions=new_dims)
                results.append(r)

        # Recompute summary counts from the deduped result rows so that all
        # figures (table, charts, summaries) reflect deduplicated reality.
        alarm = sum(1 for r in results if r.get("status") == "alarm")
        ok    = sum(1 for r in results if r.get("status") == "ok")
        error = sum(1 for r in results if r.get("status") == "error")
        info  = sum(1 for r in results if r.get("status") == "info")
        skip  = sum(1 for r in results if r.get("status") == "skip")
        total = alarm + ok + error + info + skip

        # Fall back to the JSON summary when there are no result rows
        # (controls that ran but produced no individual rows).
        if total == 0:
            summary = ctrl.get("summary") or {}
            alarm = summary.get("alarm", 0)
            ok    = summary.get("ok", 0)
            error = summary.get("error", 0)
            info  = summary.get("info", 0)
            skip  = summary.get("skip", 0)
            total = alarm + ok + error + info + skip

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

        compliance_programs = sorted(
            k for k, v in (ctrl.get("tags") or {}).items()
            if k not in _META_TAGS and v == "true"
        )

        controls.append({
            "id":                  ctrl.get("control_id", ""),
            "title":               ctrl.get("title", ""),
            "description":         ctrl.get("description", ""),
            "service":             service,
            "ctrl_service":        ctrl_svc,
            "severity":            severity,
            "status":              ctrl_status,
            "alarm":               alarm,
            "ok":                  ok,
            "error":               error,
            "info":                info,
            "skip":                skip,
            "total":               total,
            "pass_pct":            pass_pct,
            "results":             results,
            "account_ids":         account_ids,
            "regions":             regions,
            "compliance_programs": compliance_programs,
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

/* ── Charts ───────────────────────────────────────────────── */
.insights-section{{margin-bottom:28px}}
.insights-toggle{{width:100%;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:12px 18px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;list-style:none;color:var(--text);font-size:.85rem;font-weight:600;letter-spacing:.02em;user-select:none;transition:border-color .15s}}
.insights-toggle::-webkit-details-marker{{display:none}}
.insights-toggle:hover{{border-color:var(--accent)}}
.insights-toggle .toggle-icon{{font-size:.7rem;color:var(--muted);transition:transform .2s}}
details.insights-open .insights-toggle .toggle-icon{{transform:rotate(180deg)}}
details.insights-open .insights-toggle{{border-bottom-left-radius:0;border-bottom-right-radius:0;border-bottom-color:transparent}}
.insights-body{{background:var(--surface);border:1px solid var(--border);border-top:none;border-bottom-left-radius:var(--radius);border-bottom-right-radius:var(--radius);padding:20px}}
.charts-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:20px}}
.chart-card{{background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius);padding:20px}}
.chart-title{{font-size:.78rem;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:14px;display:flex;justify-content:space-between;align-items:center}}
.chart-subtitle{{font-size:.72rem;color:var(--muted);margin-top:8px;text-align:center}}
.chart-empty{{font-size:.8rem;color:var(--muted);font-style:italic;padding:12px 0}}

/* horizontal bar chart */
.hbar-row{{display:flex;align-items:center;gap:10px;margin-bottom:7px;cursor:pointer;border-radius:4px;padding:2px 4px;transition:background .12s}}
.hbar-row:hover{{background:rgba(79,156,249,.07)}}
.hbar-row.active-bar{{background:rgba(79,156,249,.14);outline:1px solid var(--accent)}}
.hbar-label{{font-size:.74rem;color:var(--text);width:130px;flex-shrink:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:right}}
.hbar-track{{flex:1;height:14px;background:var(--bg);border-radius:4px;overflow:hidden}}
.hbar-fill{{height:100%;border-radius:4px;transition:width .35s ease}}
.hbar-val{{font-size:.72rem;color:var(--muted);width:52px;text-align:left;flex-shrink:0}}

/* donut */
.donut-wrap{{display:flex;align-items:center;gap:24px;flex-wrap:wrap}}
.donut-legend{{display:flex;flex-direction:column;gap:6px}}
.legend-item{{display:flex;align-items:center;gap:7px;font-size:.75rem;color:var(--text);cursor:pointer;border-radius:4px;padding:2px 6px;transition:background .12s}}
.legend-item:hover{{background:rgba(79,156,249,.08)}}
.legend-item.active-legend{{background:rgba(79,156,249,.15);outline:1px solid var(--accent)}}
.legend-dot{{width:10px;height:10px;border-radius:50%;flex-shrink:0}}

/* gauge */
.gauge-wrap{{display:flex;flex-direction:column;align-items:center}}
.gauge-label{{font-size:2rem;font-weight:700;margin-top:-8px}}
.gauge-sub{{font-size:.75rem;color:var(--muted);margin-top:2px}}

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

<!-- Charts — collapsible insights panel -->
<div class="insights-section">
<details id="insights-details" open>
  <summary class="insights-toggle" onclick="this.parentElement.classList.toggle('insights-open')">
    <span>&#x2728; Insights &nbsp;<span style="color:var(--muted);font-weight:400;font-size:.75rem">— updates with filters</span></span>
    <span class="toggle-icon">&#9660;</span>
  </summary>
  <div class="insights-body">
    <div class="charts-grid" id="charts-grid">

      <!-- Chart 1: Top 10 Services by Alarm -->
      <div class="chart-card">
        <div class="chart-title">Top Services by Alarm <span id="c1-count" style="color:var(--muted);font-weight:400;font-size:.7rem"></span></div>
        <div id="chart-top-alarm"></div>
      </div>

      <!-- Chart 2: Overall Status Donut -->
      <div class="chart-card">
        <div class="chart-title">Status Distribution</div>
        <div class="donut-wrap">
          <svg id="chart-donut" width="160" height="160" viewBox="0 0 160 160"></svg>
          <div class="donut-legend" id="donut-legend"></div>
        </div>
        <div class="chart-subtitle" id="donut-subtitle"></div>
      </div>

      <!-- Chart 3: Pass rate gauge -->
      <div class="chart-card">
        <div class="chart-title">Overall Pass Rate</div>
        <div class="gauge-wrap">
          <svg id="chart-gauge" width="220" height="130" viewBox="0 0 220 130"></svg>
          <div class="gauge-label" id="gauge-label"></div>
          <div class="gauge-sub">controls passing</div>
        </div>
      </div>

      <!-- Chart 4: Top 10 Compliance Programs by Fail Rate -->
      <div class="chart-card">
        <div class="chart-title">Compliance Programs by Fail Rate</div>
        <div id="chart-prog-fail"></div>
      </div>

      <!-- Chart 5: Pass Rate by Account -->
      <div class="chart-card">
        <div class="chart-title">Pass Rate by Account</div>
        <div id="chart-acct-pass"></div>
      </div>

    </div>
  </div>
</details>
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
    <label>Compliance Program</label>
    <select id="f-program">
      <option value="">All programs</option>
      {program_options}
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

// ── Chart data (static baseline injected by Python) ──────────────────────
const CHART_DATA = {chart_data_json};

// ── Chart helpers ─────────────────────────────────────────────────────────
function hBar(containerId, rows, colorFn, onClickFn) {{
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!rows || !rows.length) {{ el.innerHTML = '<div class="chart-empty">No data for current filters.</div>'; return; }}
  const max = rows.reduce((m,r)=>Math.max(m,r[1]),0) || 1;
  el.innerHTML = rows.map(([label, val]) => `
    <div class="hbar-row" data-label="${{esc(label)}}" onclick="if(typeof ${{onClickFn}}==='function')${{onClickFn}}('${{esc(label)}}')">
      <div class="hbar-label" title="${{esc(label)}}">${{esc(label)}}</div>
      <div class="hbar-track">
        <div class="hbar-fill" style="width:${{Math.round(val/max*100)}}%;background:${{colorFn(val,max)}}"></div>
      </div>
      <div class="hbar-val">${{typeof val==='number'&&val<1&&val>0?val+'%':val.toLocaleString()}}</div>
    </div>`).join('');
}}

function drawDonut(svgId, legendId, subtitleId, slices) {{
  const svg = document.getElementById(svgId);
  const legend = document.getElementById(legendId);
  const sub = document.getElementById(subtitleId);
  const cx=80,cy=80,r=60,ir=38;
  const total = slices.reduce((s,x)=>s+x.v,0);
  if (!total) {{ svg.innerHTML='<text x="80" y="85" text-anchor="middle" font-size="11" fill="#64748b">No data</text>'; legend.innerHTML=''; return; }}
  let angle=-Math.PI/2, paths='';
  slices.forEach(s=>{{
    if(!s.v) return;
    const a=(s.v/total)*Math.PI*2;
    const x1=cx+r*Math.cos(angle),y1=cy+r*Math.sin(angle);
    const x2=cx+r*Math.cos(angle+a),y2=cy+r*Math.sin(angle+a);
    const xi1=cx+ir*Math.cos(angle),yi1=cy+ir*Math.sin(angle);
    const xi2=cx+ir*Math.cos(angle+a),yi2=cy+ir*Math.sin(angle+a);
    const lg=a>Math.PI?1:0;
    paths+=`<path d="M${{x1}},${{y1}} A${{r}},${{r}} 0 ${{lg}},1 ${{x2}},${{y2}} L${{xi2}},${{yi2}} A${{ir}},${{ir}} 0 ${{lg}},0 ${{xi1}},${{yi1}} Z" fill="${{s.color}}" opacity=".9" style="cursor:pointer" onclick="filterByStatus('${{s.label}}')"><title>${{s.label}}: ${{s.v.toLocaleString()}}</title></path>`;
    angle+=a;
  }});
  const okPct=Math.round((slices.find(s=>s.label==='ok')?.v||0)/total*100);
  svg.innerHTML=paths+`<text x="${{cx}}" y="${{cy+5}}" text-anchor="middle" font-size="13" fill="#e2e8f0" font-weight="600">${{okPct}}%</text><text x="${{cx}}" y="${{cy+20}}" text-anchor="middle" font-size="9" fill="#64748b">passing</text>`;
  legend.innerHTML=slices.filter(s=>s.v>0).map(s=>
    `<div class="legend-item" onclick="filterByStatus('${{s.label}}')"><div class="legend-dot" style="background:${{s.color}}"></div><span>${{s.label}}: ${{s.v.toLocaleString()}}</span></div>`
  ).join('');
  if(sub) sub.textContent=`${{total.toLocaleString()}} total results`;
}}

function drawGauge(svgId, labelId, pct) {{
  const svg=document.getElementById(svgId), label=document.getElementById(labelId);
  const cx=110,cy=110,r=90;
  const startA=Math.PI, fillA=Math.PI*(pct/100);
  const x1=cx+r*Math.cos(startA),y1=cy+r*Math.sin(startA);
  const x2=cx+r*Math.cos(startA+fillA),y2=cy+r*Math.sin(startA+fillA);
  const lg=fillA>Math.PI?1:0;
  const color=pct>=70?'#22c55e':pct>=40?'#f59e0b':'#ef4444';
  svg.innerHTML=
    `<path d="M${{cx+r*Math.cos(startA)}},${{cy+r*Math.sin(startA)}} A${{r}},${{r}} 0 0,1 ${{cx-r}},${{cy}}" fill="none" stroke="#22263a" stroke-width="16" stroke-linecap="round"/>` +
    (pct>0?`<path d="M${{x1}},${{y1}} A${{r}},${{r}} 0 ${{lg}},1 ${{x2}},${{y2}}" fill="none" stroke="${{color}}" stroke-width="16" stroke-linecap="round"/>`:'');
  label.style.color=color;
  label.textContent=pct+'%';
}}

// ── Live chart computation from current filtered set ──────────────────────
function renderCharts(data) {{
  // --- Chart 1: top services by alarm ---
  const svcAlarm={{}}, svcOk={{}}, svcTotal={{}};
  data.forEach(c=>{{
    const s=c.service||'Unknown';
    svcAlarm[s]=(svcAlarm[s]||0)+c.alarm;
    svcOk[s]   =(svcOk[s]   ||0)+c.ok;
    svcTotal[s]=(svcTotal[s]||0)+c.total;
  }});
  const topAlarm=Object.entries(svcAlarm).sort((a,b)=>b[1]-a[1]).slice(0,10);
  hBar('chart-top-alarm', topAlarm,
    (v,m)=>`hsl(${{Math.round((1-v/m)*30)}},80%,55%)`,
    'filterByService');

  // --- Chart 2: donut from filtered result status counts ---
  let rAlarm=0,rOk=0,rError=0,rInfo=0,rSkip=0;
  data.forEach(c=>{{ rAlarm+=c.alarm; rOk+=c.ok; rError+=c.error; rInfo+=c.info; rSkip+=c.skip; }});
  drawDonut('chart-donut','donut-legend','donut-subtitle',[
    {{label:'alarm',v:rAlarm,color:'#ef4444'}},
    {{label:'error',v:rError,color:'#f97316'}},
    {{label:'ok',   v:rOk,   color:'#22c55e'}},
    {{label:'info', v:rInfo, color:'#38bdf8'}},
    {{label:'skip', v:rSkip, color:'#475569'}},
  ]);

  // --- Chart 3: gauge ---
  const grand=rAlarm+rOk+rError+rInfo+rSkip;
  const pct=grand>0?Math.round(rOk/grand*100):0;
  drawGauge('chart-gauge','gauge-label',pct);

  // --- Chart 4: compliance program fail rate ---
  const progFail={{}}, progTotal={{}};
  data.forEach(c=>{{
    (c.compliance_programs||[]).forEach(p=>{{
      (c.results||[]).forEach(r=>{{
        progTotal[p]=(progTotal[p]||0)+1;
        if(r.status==='alarm'||r.status==='error') progFail[p]=(progFail[p]||0)+1;
      }});
    }});
  }});
  const progRows=Object.entries(progTotal)
    .filter(([,t])=>t>=5)
    .map(([p,t])=>[ PROGRAM_NAMES[p]||p, Math.round((progFail[p]||0)/t*100) ])
    .sort((a,b)=>b[1]-a[1]).slice(0,10);
  hBar('chart-prog-fail', progRows,
    (v)=>`hsl(${{Math.round((100-v)*0.4)}},75%,52%)`,
    'filterByProgram');

  // --- Chart 5: pass rate by account ---
  const acctOk={{}}, acctTotal={{}};
  data.forEach(c=>{{
    (c.results||[]).forEach(r=>{{
      const dims=r.dimensions||[];
      const acct=(dims.find(d=>d.key==='account_id')||{{}}).value||'';
      if(!acct||acct==='<nil>') return;
      acctTotal[acct]=(acctTotal[acct]||0)+1;
      if(r.status==='ok') acctOk[acct]=(acctOk[acct]||0)+1;
    }});
  }});
  const acctRows=Object.entries(acctTotal)
    .map(([a,t])=>[a, Math.round((acctOk[a]||0)/t*100)])
    .sort((a,b)=>a[1]-b[1]).slice(0,12);
  hBar('chart-acct-pass', acctRows,
    (v)=>`hsl(${{Math.round(v*1.2)}},70%,50%)`,
    'filterByAccount');
}}

// ── Chart click-through filter functions ──────────────────────────────────
function filterByService(name) {{
  const el=document.getElementById('f-service');
  el.value = el.value===name ? '' : name;
  activeService=el.value;
  applyFilters();
}}
function filterByStatus(status) {{
  const el=document.getElementById('f-status');
  el.value = el.value===status ? '' : status;
  applyFilters();
}}
function filterByProgram(name) {{
  // Map display name back to key
  const key=Object.entries(PROGRAM_NAMES).find(([,v])=>v===name)?.[0] || name;
  const el=document.getElementById('f-program');
  el.value = el.value===key ? '' : key;
  applyFilters();
}}
function filterByAccount(acct) {{
  const el=document.getElementById('f-account');
  el.value = el.value===acct ? '' : acct;
  applyFilters();
}}

// ── Program name map (mirrors Python PROGRAM_NAMES) ───────────────────────
const PROGRAM_NAMES = {program_names_json};

// ── Details open/close state ──────────────────────────────────────────────
(function() {{
  const d=document.getElementById('insights-details');
  if(d && d.open) d.classList.add('insights-open');
  d.addEventListener('toggle',()=>d.classList.toggle('insights-open',d.open));
}})();

// ── Service filter (dropdown only) ────────────────────────────────────────

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
['f-search','f-status','f-service','f-program','f-account','f-region','f-pagesize'].forEach(id => {{
  const el = document.getElementById(id);
  el.addEventListener(id === 'f-search' ? 'input' : 'change', () => {{
    if (id === 'f-service') {{
      activeService = el.value;
    }}
    applyFilters();
  }});
}});

function applyFilters() {{
  const search  = document.getElementById('f-search').value.toLowerCase().trim();
  const status  = document.getElementById('f-status').value;
  const service = document.getElementById('f-service').value;
  const program = document.getElementById('f-program').value;
  const account = document.getElementById('f-account').value;
  const region  = document.getElementById('f-region').value;
  pageSize = parseInt(document.getElementById('f-pagesize').value) || 0;
  currentPage = 1;

  filtered = CONTROLS.filter(c => {{
    if (status  && c.status  !== status)                         return false;
    if (service && c.service !== service)                        return false;
    if (program && !c.compliance_programs.includes(program))     return false;
    if (account && !c.account_ids.includes(account))             return false;
    if (region  && !c.regions.includes(region))                  return false;
    if (search) {{
      const hay = (c.title + ' ' + c.id + ' ' + c.description + ' ' + c.service).toLowerCase();
      if (!hay.includes(search)) return false;
    }}
    return true;
  }});
  renderCharts(filtered);
  render();
}}

function resetFilters() {{
  document.getElementById('f-search').value   = '';
  document.getElementById('f-status').value   = '';
  document.getElementById('f-service').value  = '';
  document.getElementById('f-program').value  = '';
  document.getElementById('f-account').value  = '';
  document.getElementById('f-region').value   = '';
  document.getElementById('f-pagesize').value = '25';
  pageSize = 25;
  activeService = '';
  filtered = [...CONTROLS];
  currentPage = 1;
  renderCharts(filtered);
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
renderCharts(CONTROLS);
</script>
</body>
</html>"""


def build_options(values: list) -> str:
    return "\n".join(f'<option value="{v}">{v}</option>' for v in sorted(values) if v)


def build_chart_data(services: list[dict], controls: list[dict], root_summary: dict) -> dict:
    """Compute all chart datasets from service summaries and controls."""
    from collections import defaultdict

    # Service-level aggregates (from service group summaries)
    svc_alarm = defaultdict(int)
    svc_ok    = defaultdict(int)
    svc_total = defaultdict(int)
    for svc in services:
        n = svc["title"]
        svc_alarm[n] = svc["alarm"]
        svc_ok[n]    = svc["ok"]
        svc_total[n] = svc["total"]

    # Chart 1: top 10 services by alarm
    top_alarm = sorted(svc_alarm.items(), key=lambda x: -x[1])[:10]

    # Chart 3: overall pass rate
    grand    = sum(root_summary.get(s, 0) for s in STATUS_ORDER)
    pass_pct = round((root_summary.get("ok", 0) / grand) * 100) if grand else 0

    # Chart 4: top 10 compliance programs by fail rate — computed from result rows
    prog_alarm = defaultdict(int)
    prog_total = defaultdict(int)
    acct_alarm = defaultdict(int)
    acct_ok    = defaultdict(int)
    acct_total = defaultdict(int)

    for ctrl in controls:
        programs = ctrl.get("compliance_programs") or []
        for r in (ctrl.get("results") or []):
            dims   = {d["key"]: d["value"] for d in (r.get("dimensions") or [])}
            acct   = dims.get("account_id", "")
            status = r.get("status", "")
            # Account stats
            if acct and acct != "<nil>":
                acct_total[acct] += 1
                if status == "alarm":
                    acct_alarm[acct] += 1
                elif status == "ok":
                    acct_ok[acct] += 1
            # Program stats
            for prog in programs:
                prog_total[prog] += 1
                if status in ("alarm", "error"):
                    prog_alarm[prog] += 1

    # Top 10 programs by fail rate (min 10 results to avoid noise)
    prog_fail = sorted(
        [
            (PROGRAM_NAMES.get(p, p), round(prog_alarm[p] / prog_total[p] * 100))
            for p in prog_total
            if prog_total[p] >= 10
        ],
        key=lambda x: -x[1]
    )[:10]

    # Chart 5: worst pass rate by account
    worst_acct = sorted(
        [
            (a, round(acct_ok[a] / acct_total[a] * 100))
            for a in acct_total
            if acct_total[a] > 0
        ],
        key=lambda x: x[1]
    )[:12]

    return {
        "top_alarm":         top_alarm,
        "prog_fail_rate":    prog_fail,
        "worst_acct_pass":   worst_acct,
        "total_alarm":       root_summary.get("alarm", 0),
        "total_ok":          root_summary.get("ok", 0),
        "total_error":       root_summary.get("error", 0),
        "total_info":        root_summary.get("info", 0),
        "total_skip":        root_summary.get("skip", 0),
        "pass_pct":          pass_pct,
    }


def generate_html(data: dict, account_id: str) -> str:
    # Extract service titles (for ordering) and deduped controls
    service_titles = extract_service_groups(data)
    controls       = extract_controls(data)

    # Recompute service summaries and root summary from deduped controls
    services = compute_service_summaries(service_titles, controls)
    deduped_alarm = sum(c["alarm"] for c in controls)
    deduped_ok    = sum(c["ok"]    for c in controls)
    deduped_error = sum(c["error"] for c in controls)
    deduped_info  = sum(c["info"]  for c in controls)
    deduped_skip  = sum(c["skip"]  for c in controls)
    deduped_summary = {
        "alarm": deduped_alarm,
        "ok":    deduped_ok,
        "error": deduped_error,
        "info":  deduped_info,
        "skip":  deduped_skip,
    }

    service_names = [s["title"] for s in services]
    account_ids   = sorted(set(a for c in controls for a in c["account_ids"]))
    region_ids    = sorted(set(r for c in controls for r in c["regions"]))
    program_keys  = sorted(set(p for c in controls for p in c["compliance_programs"]))
    program_options = "\n".join(
        f'<option value="{k}">{PROGRAM_NAMES.get(k, k)}</option>'
        for k in program_keys
    )

    chart_data = build_chart_data(services, controls, deduped_summary)

    title = data.get("groups", [{}])[0].get("title", "AWS Compliance")
    generated = datetime.now().strftime("%B %d, %Y at %H:%M")

    return HTML_TEMPLATE.format(
        title=title,
        generated=generated,
        account_id=account_id,
        total_controls=len(controls),
        total_alarm=deduped_alarm,
        total_ok=deduped_ok,
        total_error=deduped_error,
        total_info=deduped_info,
        total_skip=deduped_skip,
        service_options="\n".join(
            f'<option value="{s}">{s}</option>' for s in service_names
        ),
        program_options=program_options,
        account_options=build_options(account_ids),
        region_options=build_options(region_ids),
        chart_data_json=json.dumps(chart_data, separators=(",", ":")),
        program_names_json=json.dumps(PROGRAM_NAMES, separators=(",", ":")),
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
