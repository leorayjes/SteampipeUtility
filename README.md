# AWS Organisation Audit Tool

An end-to-end automation tool for running security and compliance
benchmarks across every account in an AWS Organisation. It assumes
a cross-account IAM role in each member account, writes Steampipe
connection blocks covering the entire organisation, and runs
Powerpipe benchmarks — producing JSON, HTML, and interactive
dashboard output.

Works on macOS and Linux/WSL. Installs all dependencies automatically
on first run.

---

## How It Works

```
Your AWS credentials (SSO session)
  │
  ├─ Assume role in management (payer) account
  │    └─ List all active accounts via AWS Organizations
  │
  └─ Assume role in each member account (direct from local creds)
       └─ Write ~/.steampipe/config/aws.spc
            └─ One connection block per account + aws_all aggregator
                 └─ Start Steampipe service
                      └─ Run Powerpipe benchmark
                           └─ Export JSON + HTML to results/
                                └─ Optionally launch Powerpipe dashboard
```

### Key design decisions

- **Connections are generated once per session.** Running a second
  benchmark reuses the existing `aws.spc` — no re-authentication.
- **Credentials are cleared on exit.** `aws.spc` is overwritten with
  a placeholder comment when the tool exits, so no temporary
  credentials persist on disk.
- **All dependencies are auto-installed.** Steampipe, Powerpipe, and
  the AWS plugin are installed (or updated) by
  `install_dependencies.sh` on every run. The script is safe to re-run.
- **Benchmarks are config-driven.** `mods.json` defines which mods
  and benchmarks are available. Adding a new benchmark requires only
  a JSON edit — no code changes.
- **Reports are auto-generated.** For supported mods, a custom HTML
  report is generated automatically from the JSON export once the
  benchmark completes. The report script for each mod is declared in
  `mods.json` via `report_script`.

---

## Technologies

| Technology | Role |
|---|---|
| [Steampipe](https://steampipe.io) | SQL query engine that exposes AWS APIs as PostgreSQL tables. Runs as a local service on port 9193. |
| [Powerpipe](https://powerpipe.io) | Benchmark and dashboard runner. Reads from Steampipe, exports results, and serves interactive dashboards. |
| [AWS SDK for Python (boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) | Assumes IAM roles via STS and lists accounts via AWS Organizations. |
| [Python 3.11+](https://www.python.org) | Runtime for `generate_steampipe_connections.py`. |
| [Bash](https://www.gnu.org/software/bash/) | Orchestration layer — `run_steampipe_audit.sh` manages the venv, dependencies, prompts, and the Powerpipe lifecycle. |
| [AWS CloudFormation](https://aws.amazon.com/cloudformation/) | Deploys the cross-account IAM role (`healthcheck_collector_role.yaml`). |

---

## Repository Structure

```
.
├── run_steampipe_audit.sh              # Main entrypoint — run this
├── install_dependencies.sh             # Installs Steampipe, Powerpipe, plugins
├── generate_steampipe_connections.py   # Generates ~/.steampipe/config/aws.spc
├── generate_compliance_report.py       # HTML report generator for AWS Compliance
├── generate_well_architected_report.py # HTML report generator for Well-Architected
├── generate_top10_report.py            # HTML report generator for Top 10
├── generate_perimeter_report.py        # HTML report generator for AWS Perimeter
├── mods.json                           # Available mods and benchmarks (config)
├── healthcheck_collector_role.yaml     # CloudFormation template for the IAM role
├── requirements.txt                    # Python dependencies (boto3)
└── results/                            # Benchmark output (gitignored)
```

---

## Prerequisites

### 1. AWS IAM role

Each account you want to audit must have an IAM role that:

- Trusts your caller principal (e.g. your SSO role ARN)
- Requires an External ID
- Has the `ReadOnlyAccess` managed policy attached

A CloudFormation template is provided to deploy this role. Deploy it
to **every member account** including the management account:

```bash
aws cloudformation deploy \
  --template-file healthcheck_collector_role.yaml \
  --stack-name healthcheck-collector-role \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ExternalId=<YOUR_EXTERNAL_ID>
```

The default role name is `AWS_HEALTHCHECK_COLLECTOR`. This matches
the default value prompted by the tool at runtime.

### 2. Python 3.11+

Python 3.11 or higher is required. The tool will attempt to install
it automatically if it is missing or below the minimum version:

- **macOS** — via Homebrew (`brew install python3`)
- **Linux/WSL** — via `apt-get`; falls back to the `deadsnakes` PPA
  on older Ubuntu releases
- **Other Linux distros** — exits with a clear message and a link to
  `python.org/downloads`

To check your current version:

```bash
python3 --version
```

### 3. AWS credentials

The tool reads standard AWS credential environment variables. Set
these before running:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

> Steampipe and Powerpipe are installed automatically — you do not
> need to install them manually.

---

## Getting Started

### 1. Clone the repository

```bash
git clone <repo-url>
cd SteampipeUtility
```

### 2. Export your AWS credentials

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

### 3. Run the tool

```bash
./run_steampipe_audit.sh
```

On first run the script will:

1. Check for Python 3.11+ and install it if missing or outdated
2. Create a Python virtual environment (`.venv`)
3. Install `boto3`
4. Install / update Steampipe, Powerpipe, and the AWS plugin
5. Prompt for runtime parameters

---

## Runtime Parameters

| Parameter | Description | Default |
|---|---|---|
| **Role name** | IAM role to assume in each account | `AWS_HEALTHCHECK_COLLECTOR` |
| **Payer account ID** | AWS Organizations management account ID | _(required)_ |
| **External ID** | External ID configured on the IAM role (hidden input) | _(required)_ |

Press **Enter** to accept the default role name. The External ID is
masked — only the first 5 characters are shown in the confirmation
summary.

---

## Selecting a Mod and Benchmark

After connections are generated and the Steampipe service starts, the
tool presents a numbered mod selector:

```
  [1] AWS Compliance
  [2] AWS Well-Architected
  [3] AWS Top 10 Security Checks
  [4] AWS Perimeter
```

After selecting a mod, a benchmark selector appears (auto-selected
when only one benchmark exists):

```
  [1]  All Controls
  [2]  AWS Foundational Security Best Practices
  [3]  ACSC Essential Eight
  [4]  CIS v4.0.0
  ...
```

---

## Available Mods and Benchmarks

### AWS Compliance
34 benchmarks covering major frameworks:

| Framework | Benchmarks available |
|---|---|
| CIS AWS Foundations | v1.2.0 through v6.0.0 |
| PCI DSS | v3.2.1, v4.0 |
| NIST | 800-53 Rev 4 & 5, 800-171 Rev 2, 800-172, CSF v1.1 & v2.0 |
| HIPAA | Final Omnibus Rule 2013, Security Rule 2003 |
| SOC 2 | — |
| FedRAMP | Low Rev 4, Moderate Rev 4 |
| GDPR | — |
| FFIEC | — |
| NYDFS 23 NYCRR 500 | — |
| Others | ACSC Essential Eight, CISA Cyber Essentials, GxP, RBI, Audit Manager |

### AWS Well-Architected
Full Well-Architected Framework check across all five pillars.

### AWS Top 10 Security Checks
The top-level benchmark plus each of the 10 individual checks:

1. Accurate account information
2. Use multi-factor authentication (MFA)
3. No hard-coding secrets
4. Limit security groups
5. Intentional data policies
6. Centralize CloudTrail logs
7. Validate IAM roles
8. Take action on findings
9. Rotate keys
10. Be involved in the dev cycle

### AWS Perimeter
Three benchmarks for network and data exposure:
- Public Access
- Network Access
- Shared Access

---

## Results

Each benchmark run creates a timestamped folder:

```
results/
  <payer_account_id>_<mod_id>_<YYYYMMDD_HHmm>/
    <payer_account_id>_<mod_id>_<timestamp>.json
    <payer_account_id>_<mod_id>_<timestamp>.html
    <payer_account_id>_<mod_id>_<timestamp>.log
    <payer_account_id>_<mod_id>_<timestamp>_report.html  ← custom report (supported mods)
    <payer_account_id>_<mod_id>_dashboard.log            ← only if dashboard launched
```

JSON and HTML outputs are only written for mods that support them
(all current mods do). The `.log` file captures the full terminal
output of the benchmark run.

For mods with a `report_script` defined in `mods.json`, a custom
styled HTML report (`_report.html`) is generated automatically from
the JSON export immediately after the benchmark finishes. All four
current mods produce a report:

| Mod | Report script |
|---|---|
| AWS Compliance | `generate_compliance_report.py` |
| AWS Well-Architected | `generate_well_architected_report.py` |
| AWS Top 10 | `generate_top10_report.py` |
| AWS Perimeter | `generate_perimeter_report.py` |

Reports are self-contained single-file HTML pages with filterable
tables, sortable columns, interactive charts, and expandable per-resource
result rows. No server or internet connection is required to view them.

---

## Powerpipe Dashboard

After a benchmark completes, the tool prompts to launch the Powerpipe
dashboard server. Benchmarks are served as interactive pages — you can
run, filter, and explore results in the browser without re-running the
benchmark.

```
Launch Powerpipe dashboard for AWS Compliance? [y/N]:
```

If you choose yes:

```
  ==================================================
  Dashboard ready — open your browser and visit:

    http://localhost:9033

  Server logs: results/.../dashboard.log
  The server will be stopped when you exit the tool.
  ==================================================
```

The server runs in the background. You can continue running
additional mods while the dashboard is open. Only one dashboard
server runs at a time — launching a new one stops the previous.

---

## Cleanup

On exit the tool automatically:

- Stops the Powerpipe dashboard server (if running)
- Stops the Steampipe service
- Overwrites `~/.steampipe/config/aws.spc` with a timestamp comment
  (clears all temporary credentials from disk)
- Deletes the `.venv` virtual environment

---

## Adding Mods or Benchmarks

Edit `mods.json` — no code changes required.

To add a new mod:

```json
{
  "id": "my_mod",
  "namespace": "my_mod",
  "name": "My Mod Display Name",
  "description": "Short description shown in the selector",
  "mod": "github.com/org/steampipe-mod-name",
  "benchmarks": [
    { "id": "benchmark_name", "name": "Display Name" }
  ],
  "supports_html": true,
  "supports_json": true,
  "supports_dashboard": true,
  "report_script": "generate_my_mod_report.py"
}
```

> **Important:** `namespace` must match the prefix shown by
> `powerpipe benchmark list` (e.g. `aws_top_10`, not `aws_top10`).
> If they differ, set `namespace` explicitly.

> **`report_script`** is optional. Omit it (or leave it out entirely)
> if no custom report generator exists for the mod. The benchmark will
> still run and produce the standard Powerpipe JSON/HTML output.

---

## Troubleshooting

**Python not found or below 3.11**
The script will attempt to install Python automatically. If it cannot
(non-apt Linux), it will exit with instructions and a link to
`https://www.python.org/downloads/`.

**`steampipe` or `powerpipe` not found after install (Linux/WSL)**
```bash
export PATH="$HOME/.local/bin:$PATH"
```
Add to `~/.bashrc` to make it permanent.

**`update server` error on mod install**
Suppressed automatically via `POWERPIPE_UPDATE_CHECK=false`. If it
appears, it is non-fatal — the benchmark will still run.

**`connection refused` on port 9193**
The Steampipe service failed to start or timed out. Run
`steampipe service start` manually and check for errors.

**Credentials error on role assumption**
Verify your `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
`AWS_SESSION_TOKEN` are exported and not expired. SSO sessions
typically expire after 1–8 hours.
