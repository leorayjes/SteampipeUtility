# UI/UX Improvement Todos

Tracked items from the session discussion on improving the audit tool's
interface and user experience. To be implemented once core functionality
is stable.

---

## 1. Rewrite entrypoint as a Python CLI (`main.py`)

Move all user-facing prompts and output out of bash and into a Python
entrypoint that can be shared across macOS and WSL without
platform-specific code.

- [ ] Create `main.py` as the styled entrypoint
- [ ] `run_steampipe_audit.sh` becomes a thin launcher — venv setup,
      `pip install`, then delegates to `main.py`
- [ ] Decide: `main.py` calls `generate_steampipe_connections.py` as a
      subprocess, or imports its functions directly

---

## 2. Styled header and output (`rich`)

Replace plain `echo` output with `rich`-powered panels, tables, and
formatted log lines.

- [ ] Add `rich` to `requirements.txt`
- [ ] Styled banner/header on launch (tool name, version, description)
- [ ] Replace `[INFO]` / `[WARN]` / `[ERROR]` log lines with `rich`
      styled equivalents
- [ ] Render the runtime parameter confirmation as a `rich` table
- [ ] Render the mod selector as a styled `rich` list
- [ ] Render benchmark result summary (pass/fail counts) as a styled
      `rich` table after each run

---

## 3. Interactive prompts (`questionary`)

Replace `read -rp` prompts with `questionary`-powered interactive inputs.

- [ ] Add `questionary` to `requirements.txt`
- [ ] Role name prompt with default (`AWS_HEALTHCHECK_COLLECTOR`)
- [ ] Payer account ID prompt (required, re-prompts if blank)
- [ ] External ID prompt (password-style hidden input, required)
- [ ] Mod selector as a `questionary.select` list (single choice)
- [ ] Post-run menu ("Run another mod" / "Launch dashboard" / "Exit")
      as a `questionary.select`
- [ ] Dashboard launch confirmation as a `questionary.confirm`
- [ ] Exit/cleanup confirmation (remove venv) as a `questionary.confirm`

---

## 4. Progress spinner during long operations (`rich`)

Show a spinner while waiting for operations that have no incremental
output to display.

- [ ] Spinner during `steampipe service start` / port readiness poll
- [ ] Spinner during `powerpipe mod install`
- [ ] Spinner during `pip install -r requirements.txt`
- [ ] Spinner during Steampipe plugin install/update

---

## 5. Cross-platform compatibility validation

Ensure the Python-based UI works identically on macOS Terminal,
iTerm2, and Windows Terminal (WSL).

- [ ] Test `rich` rendering in Windows Terminal (WSL)
- [ ] Test `questionary` prompts in Windows Terminal (WSL)
- [ ] Verify ANSI color support detection (fall back to plain output
      if terminal does not support it)

---

## Notes

- Both `rich` and `questionary` install via `pip` — no system-level
  dependencies required, keeping the tool portable
- `run_steampipe_audit.sh` should retain the venv setup and
  `install_dependencies.sh` call; only the prompt/output logic moves
  to Python
- The decision on subprocess vs direct import for
  `generate_steampipe_connections.py` affects whether the two files
  can eventually be merged into a single `main.py`
