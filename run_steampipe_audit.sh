#!/usr/bin/env bash
# run_steampipe_audit.sh
#
# End-to-end audit runner:
#   1. Sets up Python virtual environment and installs Python dependencies.
#   2. Installs Steampipe, Powerpipe, and required plugins.
#   3. Prompts for runtime parameters.
#   4. Generates Steampipe connection blocks for all org accounts.
#   5. Presents a mod selector and runs the chosen Powerpipe benchmark.
#   6. Saves results (JSON + HTML where supported) to ./results/.
#   7. Optionally launches the Powerpipe dashboard server.
#   8. Prompts to run another mod or exit.
#   9. Cleans up the virtual environment on exit.

set -euo pipefail

VENV_DIR=".venv"
MODS_CONFIG="mods.json"
RESULTS_DIR="results"
CONNECTION_SCRIPT="generate_steampipe_connections.py"
DEFAULT_ROLE_NAME="AWS_HEALTHCHECK_COLLECTOR"
POWERPIPE_SERVER_PID=""
DASHBOARD_MOD_DIR=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()      { echo "[INFO]  $*"; }
warn()     { echo "[WARN]  $*"; }
err()      { echo "[ERROR] $*" >&2; }
section()  { echo; echo "===================================================="; echo "  $*"; echo "===================================================="; echo; }

prompt_required() {
    local var_name="$1"
    local prompt_text="$2"
    local secret="${3:-false}"
    local value=""

    while [[ -z "$value" ]]; do
        if [[ "$secret" == "true" ]]; then
            read -rsp "$prompt_text: " value
            echo
        else
            read -rp "$prompt_text: " value
        fi
        if [[ -z "$value" ]]; then
            warn "This field is required. Please enter a value."
        fi
    done

    printf -v "$var_name" '%s' "$value"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    echo

    # Stop powerpipe server if it's still running.
    if [[ -n "$POWERPIPE_SERVER_PID" ]] && kill -0 "$POWERPIPE_SERVER_PID" 2>/dev/null; then
        log "Stopping Powerpipe dashboard server (PID $POWERPIPE_SERVER_PID)..."
        kill "$POWERPIPE_SERVER_PID" 2>/dev/null || true
        wait "$POWERPIPE_SERVER_PID" 2>/dev/null || true
        log "Dashboard server stopped."
    fi

    # Clean up the dashboard mod working directory if it was kept alive for the server.
    if [[ -n "$DASHBOARD_MOD_DIR" ]] && [[ -d "$DASHBOARD_MOD_DIR" ]]; then
        rm -rf "$DASHBOARD_MOD_DIR"
    fi

    # Stop Steampipe service on exit.
    if steampipe service status 2>/dev/null | grep -q "service is running"; then
        log "Stopping Steampipe service..."
        steampipe service stop 2>/dev/null || true
        log "Steampipe service stopped."
    fi

    # Overwrite the connections file with placeholder content to clear credentials.
    local spc_path="$HOME/.steampipe/config/aws.spc"
    if [[ -f "$spc_path" ]]; then
        log "Overwriting Steampipe connections file to clear credentials..."
        echo "# credentials cleared on $(date -u +"%Y-%m-%dT%H:%M:%SZ")" > "$spc_path"
        log "Connections file cleared: $spc_path"
    fi

    # Always remove the virtual environment on exit.
    deactivate 2>/dev/null || true
    if [[ -d "$VENV_DIR" ]]; then
        rm -rf "$VENV_DIR"
        log "Virtual environment removed."
    fi

    log "Exiting."
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Python virtual environment
# ---------------------------------------------------------------------------

section "Python Environment"

if [[ -d "$VENV_DIR" ]]; then
    log "Existing virtual environment found at $VENV_DIR — reusing."
else
    log "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR"
    log "Virtual environment created."
fi

log "Activating virtual environment..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

log "Installing Python requirements..."
pip install --quiet --require-virtualenv -r requirements.txt
log "Python requirements installed."

# ---------------------------------------------------------------------------
# Steampipe / Powerpipe / plugin installation
# ---------------------------------------------------------------------------

section "Dependency Installation"
bash install_dependencies.sh

# ---------------------------------------------------------------------------
# Runtime parameters
# ---------------------------------------------------------------------------

section "Audit Configuration"

read -rp "Role name [$DEFAULT_ROLE_NAME]: " ROLE_NAME
ROLE_NAME="${ROLE_NAME:-$DEFAULT_ROLE_NAME}"

prompt_required PAYER_ACCOUNT_ID "Payer account ID"

prompt_required EXTERNAL_ID "External ID (input hidden)" "true"
EXTERNAL_ID_PREVIEW="${EXTERNAL_ID:0:5}..."

echo
echo "  Role name        : $ROLE_NAME"
echo "  Payer account ID : $PAYER_ACCOUNT_ID"
echo "  External ID      : $EXTERNAL_ID_PREVIEW"
echo

# ---------------------------------------------------------------------------
# Generate Steampipe connections
# ---------------------------------------------------------------------------

section "Generating Steampipe Connections"

python "$CONNECTION_SCRIPT" \
    --role_name "$ROLE_NAME" \
    --payer_account_id "$PAYER_ACCOUNT_ID" \
    --external_id "$EXTERNAL_ID"

log "Connections written to ~/.steampipe/config/aws.spc"

# ---------------------------------------------------------------------------
# Start Steampipe service
# ---------------------------------------------------------------------------

section "Starting Steampipe Service"

if steampipe service status 2>/dev/null | grep -q "service is running"; then
    log "Steampipe service already running — reusing."
else
    log "Starting Steampipe service..."
    steampipe service start

    # Wait for the PostgreSQL port (9193) to accept connections.
    # steampipe service status reports "running" before the port is ready,
    # so we poll the port directly instead.
    log "Waiting for Steampipe database to be ready on port 9193..."
    MAX_WAIT=60
    WAITED=0
    until (echo > /dev/tcp/127.0.0.1/9193) 2>/dev/null; do
        if (( WAITED >= MAX_WAIT )); then
            err "Steampipe database did not become ready within ${MAX_WAIT}s. Aborting."
            exit 1
        fi
        sleep 1
        (( WAITED++ ))
    done
    log "Steampipe database is ready (${WAITED}s)."
fi

# ---------------------------------------------------------------------------
# Results directory
# ---------------------------------------------------------------------------

mkdir -p "$RESULTS_DIR"
log "Results will be saved to $RESULTS_DIR/"

# ---------------------------------------------------------------------------
# Mod helpers
# ---------------------------------------------------------------------------

# Build parallel arrays from mods.json: IDs, names, mod paths, benchmark
# targets, and capability flags. Uses while-read for bash 3.2 compatibility
# (mapfile/readarray require bash 4+).

MOD_IDS=()
while IFS= read -r line; do MOD_IDS+=("$line"); done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
for m in c['mods']:
    print(m['id'])
")

MOD_NAMES=()
while IFS= read -r line; do MOD_NAMES+=("$line"); done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
for m in c['mods']:
    print(m['name'])
")

MOD_PATHS=()
while IFS= read -r line; do MOD_PATHS+=("$line"); done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
for m in c['mods']:
    print(m['mod'])
")

MOD_HTML=()
while IFS= read -r line; do MOD_HTML+=("$line"); done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
for m in c['mods']:
    print(str(m.get('supports_html', False)).lower())
")

MOD_JSON=()
while IFS= read -r line; do MOD_JSON+=("$line"); done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
for m in c['mods']:
    print(str(m.get('supports_json', False)).lower())
")

MOD_DASHBOARD=()
while IFS= read -r line; do MOD_DASHBOARD+=("$line"); done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
for m in c['mods']:
    print(str(m.get('supports_dashboard', False)).lower())
")

# SELECTED_BENCHMARK_ID is set by select_benchmark() and consumed by run_mod().
SELECTED_BENCHMARK_ID=""

select_mod() {
    echo "  Available mods:"
    echo
    local i
    for i in "${!MOD_IDS[@]}"; do
        printf "  [%d] %s\n" "$((i+1))" "${MOD_NAMES[$i]}"
    done
    echo

    local choice=""
    while true; do
        read -rp "Select a mod to run [1-${#MOD_IDS[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#MOD_IDS[@]} )); then
            SELECTED_INDEX=$(( choice - 1 ))
            return
        fi
        warn "Invalid selection. Please enter a number between 1 and ${#MOD_IDS[@]}."
    done
}

select_benchmark() {
    local mod_index="$1"
    local mod_id="${MOD_IDS[$mod_index]}"

    # Load benchmark list for the selected mod.
    local bench_ids=()
    local bench_names=()
    while IFS='|' read -r bid bname; do
        bench_ids+=("$bid")
        bench_names+=("$bname")
    done < <(python3 -c "
import json
with open('$MODS_CONFIG') as f:
    c = json.load(f)
mod = next(m for m in c['mods'] if m['id'] == '$mod_id')
for b in mod['benchmarks']:
    print(b['id'] + '|' + b['name'])
")

    if [[ ${#bench_ids[@]} -eq 1 ]]; then
        # Only one benchmark available — select it automatically.
        SELECTED_BENCHMARK_ID="${bench_ids[0]}"
        log "Benchmark: ${bench_names[0]}"
        return
    fi

    echo "  Available benchmarks:"
    echo
    local i
    for i in "${!bench_ids[@]}"; do
        printf "  [%d] %s\n" "$((i+1))" "${bench_names[$i]}"
    done
    echo

    local choice=""
    while true; do
        read -rp "Select a benchmark [1-${#bench_ids[@]}]: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#bench_ids[@]} )); then
            SELECTED_BENCHMARK_ID="${bench_ids[$(( choice - 1 ))]}"
            return
        fi
        warn "Invalid selection. Please enter a number between 1 and ${#bench_ids[@]}."
    done
}

run_mod() {
    local index="$1"
    local mod_id="${MOD_IDS[$index]}"
    local mod_name="${MOD_NAMES[$index]}"
    local mod_path="${MOD_PATHS[$index]}"
    # Construct the fully-qualified benchmark name from the mod namespace and selected id.
    local benchmark="${mod_id}.benchmark.${SELECTED_BENCHMARK_ID}"
    local supports_html="${MOD_HTML[$index]}"
    local supports_json="${MOD_JSON[$index]}"
    local supports_dashboard="${MOD_DASHBOARD[$index]}"
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M")
    # Each run gets its own subdirectory: results/<payer_account_id>_<mod_id>_<timestamp>/
    local run_dir
    run_dir="$(pwd)/$RESULTS_DIR/${PAYER_ACCOUNT_ID}_${mod_id}_${timestamp}"
    mkdir -p "$run_dir"
    local output_base="${run_dir}/${PAYER_ACCOUNT_ID}_${mod_id}_${timestamp}"

    section "Running: $mod_name"

    # Create a temporary working directory for the mod so installs are isolated.
    local mod_work_dir
    mod_work_dir=$(mktemp -d)
    log "Working directory: $mod_work_dir"

    # Install the mod.
    log "Installing mod: $mod_path"
    (cd "$mod_work_dir" && powerpipe mod install "$mod_path")

    # Run benchmark and export results.
    log "Running benchmark..."

    local export_args=()

    if [[ "$supports_json" == "true" ]]; then
        export_args+=("--export" "${output_base}.json")
        log "JSON output: ${output_base}.json"
    fi

    if [[ "$supports_html" == "true" ]]; then
        export_args+=("--export" "${output_base}.html")
        log "HTML output: ${output_base}.html"
    fi

    local benchmark_exit=0
    pushd "$mod_work_dir" > /dev/null
    # Temporarily disable set -e so powerpipe's non-zero exit on findings
    # (alarms/errors) does not abort the script before we can read the exit code.
    set +e
    powerpipe benchmark run "$benchmark" \
        --pipes-host localhost \
        --search-path aws_all \
        "${export_args[@]}" \
        2>&1 | tee "${output_base}.log"
    benchmark_exit=${PIPESTATUS[0]}
    set -e
    popd > /dev/null

    if (( benchmark_exit == 0 )); then
        log "Benchmark complete — no alarms or errors found."
    else
        log "Benchmark complete — findings were reported (exit code: $benchmark_exit)."
    fi
    log "Results saved to $run_dir/"

    # Optionally launch the dashboard server.
    # mod_work_dir is intentionally kept alive while the server is running
    # since powerpipe server needs the mod files to serve dashboards.
    if [[ "$supports_dashboard" == "true" ]]; then
        echo
        read -rp "Launch Powerpipe dashboard for $mod_name? [y/N]: " launch_dashboard
        case "$launch_dashboard" in
            [yY][eE][sS]|[yY])
                # Stop any previously running server first.
                if [[ -n "$POWERPIPE_SERVER_PID" ]] && kill -0 "$POWERPIPE_SERVER_PID" 2>/dev/null; then
                    log "Stopping previous dashboard server (PID $POWERPIPE_SERVER_PID)..."
                    kill "$POWERPIPE_SERVER_PID" 2>/dev/null || true
                    wait "$POWERPIPE_SERVER_PID" 2>/dev/null || true
                    # Clean up the previous mod working dir if one was saved.
                    if [[ -n "$DASHBOARD_MOD_DIR" ]] && [[ -d "$DASHBOARD_MOD_DIR" ]]; then
                        rm -rf "$DASHBOARD_MOD_DIR"
                    fi
                fi

                local dashboard_log="${run_dir}/${PAYER_ACCOUNT_ID}_${mod_id}_dashboard.log"

                log "Starting Powerpipe dashboard server..."
                # Redirect all server output to a log file to keep this terminal clean.
                (cd "$mod_work_dir" && powerpipe server > "$dashboard_log" 2>&1) &
                POWERPIPE_SERVER_PID=$!
                # Save the working dir so cleanup can remove it when the server stops.
                DASHBOARD_MOD_DIR="$mod_work_dir"

                echo
                echo "  =================================================="
                echo "  Dashboard ready — open your browser and visit:"
                echo ""
                echo "    http://localhost:9033"
                echo ""
                echo "  Server logs: $dashboard_log"
                echo "  The server will be stopped when you exit the tool."
                echo "  =================================================="
                echo

                # Do NOT delete mod_work_dir here — the server needs it.
                return
                ;;
            *)
                log "Dashboard not launched."
                ;;
        esac
    fi

    # Clean up temp mod directory (only reached if dashboard was not launched).
    rm -rf "$mod_work_dir"
}

# ---------------------------------------------------------------------------
# Main audit loop — run a mod, then offer to run another or exit
# ---------------------------------------------------------------------------

section "Mod Selection"

while true; do
    select_mod
    select_benchmark "$SELECTED_INDEX"
    run_mod "$SELECTED_INDEX"

    echo
    echo "----------------------------------------------------"
    echo "  What would you like to do next?"
    echo "----------------------------------------------------"
    echo "  [1] Run another mod"
    echo "  [2] Exit"
    echo

    next_choice=""
    while true; do
        read -rp "Select an option [1-2]: " next_choice
        case "$next_choice" in
            1)
                section "Mod Selection"
                break
                ;;
            2)
                log "Audit complete. All results saved to $RESULTS_DIR/."
                exit 0
                ;;
            *)
                warn "Invalid selection. Please enter 1 or 2."
                ;;
        esac
    done
done
