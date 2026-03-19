# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

**Install dependencies:**
```bash
uv sync
```

**Run tests:**
```bash
./.venv/bin/python -m unittest -v tests.test_intentlang_e2e
```

**Run a single test:**
```bash
./.venv/bin/python -m unittest -v tests.test_intentlang_e2e.TestIntentLangE2E.<test_name>
```

**Launch CTF or pentest session:**
```bash
uv run --env-file .env YuPentestPilot.py --ctf <url> --workspace <dir> --mode ctf|pentest
```

## Architecture

Three-layer architecture:

**Layer 1 – Scheduling (`YuPentestPilot.py`)**
Entry point. Parses args, instantiates `IntentRuntime` to bootstrap workspace metadata, spins up a Docker container (`l3yx/sandbox:latest`), and invokes `claude --dangerously-skip-permissions --print <task>` inside it. `Ctfer` is a legacy alias.

**Layer 2 – Execution (`meta-tooling/service/python_executor_mcp.py`)**
FastMCP server running inside the container. Backs each session with a live Jupyter kernel. Before running any code, `_enforce_code_policy()` calls `security_guard.find_python_shell_violations()` to block shell escapes (`!cmd`, `os.system`, `subprocess.*`, `asyncio.create_subprocess_*`) and redirects them to `toolset.terminal.run_command()`. `validate_command()` enforces a host allowlist and blocks dangerous patterns.

**Layer 3 – Capability (`meta-tooling/toolset/src/toolset/`)**
Six `@toolset`-decorated namespaces available to the agent kernel:
- `toolset.browser` – Playwright page interaction
- `toolset.terminal` – tmux session management
- `toolset.proxy` – HTTP traffic inspection
- `toolset.note` – persistent notes
- `toolset.intentlang` – IntentLang memory: metadata + artifacts read/write
- `toolset.report` – `.docx` report generation from `verified_findings`

**IntentLang runtime (`intentlang/runtime.py`)**
`IntentRuntime` bootstraps a structured workspace under `intentlang/` with:
- `intentlang/metadata/` – `run.json`, `strategy.json`, `intents.json`, `runtime_objects.json`, `artifact_schemas.json`
- `intentlang/artifacts/` – `recon_summary`, `surface_map`, `hypotheses`, `candidate_findings`, `candidate_evidence`, `verified_findings`, `final_report_reference`

The constant `CONTAINER_WORKSPACE = "/home/ubuntu/Workspace"` is used for all path rendering inside the sandbox.

**Agent definition (`claude_code/.claude/agents/security-agent.md`)**
Defines the sub-agent prompt and tool allowlist (`mcp__sandbox__execute_code`, `mcp__sandbox__list_sessions`, `mcp__sandbox__close_session`, `Task`, `EnterPlanMode`, `ExitPlanMode`, `TodoWrite`). The agent follows a recon → candidate → verified → report artifact pipeline using `toolset.intentlang` as persistent memory.

## Key Files

| Path | Role |
|------|------|
| `YuPentestPilot.py` | Top-level entry point |
| `intentlang/runtime.py` | Workspace bootstrap and task rendering |
| `meta-tooling/service/python_executor_mcp.py` | MCP server + kernel execution + security policy |
| `meta-tooling/toolset/src/security_guard.py` | Shell-escape and dangerous-command detection |
| `meta-tooling/toolset/src/toolset/` | All capability modules |
| `claude_code/.claude/agents/security-agent.md` | In-container agent definition |
| `tests/test_intentlang_e2e.py` | E2E test suite (14 tests) |

## Dependency Management

Uses `uv` (not pip). Three `pyproject.toml` files:
- `/pyproject.toml` – root (requires Python 3.12+, `docker`, `python-docx`)
- `meta-tooling/service/pyproject.toml` – MCP service (`fastmcp`, `jupyter-client`, `nbformat`, `playwright`)
- `meta-tooling/toolset/pyproject.toml` – toolset (`playwright`, `libtmux`, `pydantic`, `requests`)
