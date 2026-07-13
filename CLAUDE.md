# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP server that wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) Windows event log
forensics/timeline CLI tool, exposing it as an MCP tool (`scan_evtx`) so an MCP client can run
Hayabusa detection scans over `.evtx` files.

## Commands

```sh
pip install -e .          # install the package (and mcp[cli] dependency) in editable mode
mcp-hayabusa               # run the server over stdio (registered as a console script)
python -m mcp_hayabusa.server   # equivalent, without the console script

python scripts/download_hayabusa.py   # fetch the latest hayabusa binary for this platform into ./hayabusa/

pip install -e ".[test]"  # install with pytest
pytest                     # run the test suite
```

The test suite (`tests/`) is hermetic — it never invokes the real `hayabusa` binary or needs
`sample_evtx/`. `scan()` tests monkeypatch `subprocess.run` with a fake that writes synthetic
CSV/JSON to whatever `-o` path was requested; `list_rules()` tests run against a small synthetic
rules directory (`tests/conftest.py`'s `rules_dir` fixture); `server.py` tests monkeypatch
`hayabusa.scan`/`hayabusa.list_rules` directly to test response-shaping in isolation. There is no
linter or build step configured yet.

### Manual testing

`mcp dev` (from the `mcp[cli]` package) launches the MCP Inspector against the server for interactive
tool calls:

```sh
mcp dev src/mcp_hayabusa/server.py
```

Actually exercising `scan_evtx` requires the `hayabusa` binary to be installed (see Configuration below
— `scripts/download_hayabusa.py` handles this) and at least one real or sample `.evtx` file. Yamato
Security ships a repo of sample `.evtx` files that's useful for this — clone it into `./sample_evtx/`
(gitignored, not a submodule):

```sh
git clone https://github.com/Yamato-Security/hayabusa-sample-evtx.git sample_evtx
```

## Architecture

Two files carry all the logic:

- `src/mcp_hayabusa/hayabusa.py` — pure subprocess wrapper around the `hayabusa` binary. Owns binary
  resolution (`resolve_binary`, via `HAYABUSA_BIN` env var or `PATH`), building the `csv-timeline` /
  `json-timeline` command line, running it, and parsing the resulting CSV/JSON/JSONL output file into a
  `ScanResult` (command run, exit code, stdout/stderr tails, total `record_count`, level/rule-title counts,
  and a preview capped at `PREVIEW_RECORD_LIMIT`/`max_results` records). Raises `HayabusaError` for a
  missing binary, missing target path, unresolvable rules directory, or a timed-out scan. This module has
  no MCP dependency and can be tested/used standalone.
  - `rule_filter` (on `scan()`) restricts which rules get loaded to those whose rule file text
    case-insensitively contains a string — Hayabusa has no native free-text rule filter, so this copies
    matching `*.yml` files from the resolved rules directory into a temp dir and points `-r` at it
    (`_build_rule_filter_dir`). `_resolve_rules_dir` and `_rule_files_matching` are shared between this
    and `list_rules` so the two stay in sync (a keyword you list with is exactly what `rule_filter` would
    load).
  - `list_rules` parses Sigma-format rule YAML (via PyYAML) into `RuleInfo` (id, title, level, status,
    description, author, tags, logsource, path) without invoking the `hayabusa` binary at all — it's pure
    filesystem + YAML parsing over the rules directory.
- `src/mcp_hayabusa/server.py` — the MCP surface. A `FastMCP("hayabusa")` instance with two `@mcp.tool()`s:
  - `scan_evtx`, which validates nothing itself — it just forwards arguments to `hayabusa.scan()` and shapes
    the `ScanResult` into the dict returned to the MCP client (`result_detail="summary"`, the default,
    condenses records and level/rule-title counts and only includes stdout/stderr tails on non-zero exit;
    `"full"` returns everything), catching `HayabusaError` into an `{"error": ...}` response rather than
    raising.
  - `get_hayabusa_rules`, a thin wrapper over `hayabusa.list_rules()` for browsing/searching available
    rules (e.g. before deciding on a `rule_filter` value) — same `{"error": ...}` handling on `HayabusaError`.

When adding a new Hayabusa-backed tool (e.g. wrapping `logon-summary`, `eid-metrics`, or `search`), follow
this same split: put the subprocess/parsing logic in `hayabusa.py` as a plain function returning a
dataclass, then add a thin `@mcp.tool()` wrapper in `server.py`.

`scripts/download_hayabusa.py` is a standalone utility (not part of the `mcp_hayabusa` package, no
dependency on `mcp`) that resolves the latest (or a pinned) Hayabusa GitHub release for the current
OS/arch, downloads it, and extracts it into `./hayabusa/` — which is gitignored. It normalizes the
extracted binary to `hayabusa`/`hayabusa.exe` (Hayabusa ships it version-suffixed, e.g.
`hayabusa-3.10.0-win-x64.exe`) so `HAYABUSA_BIN` doesn't need updating across re-downloads.

### Non-interactivity

`hayabusa.scan()` always passes `-w` (`--no-wizard`) and `-q` (`--quiet`) to the underlying command. This
is deliberate and required: Hayabusa's rule-config wizard and launch banner expect a TTY, and there is no
stdin/tty when the binary is invoked from an MCP tool call. Any new subprocess call into `hayabusa` from
this codebase needs the same treatment.

### Output file handling

By default `scan()` writes Hayabusa's output to a temp file, extracts a bounded preview + total record
count from it, then deletes it — the full result set is only kept on disk if the caller passes an explicit
`output_path`. Keep this behavior when adding new scan-like tools: don't return unbounded result sets
through the MCP tool response.

## Configuration

| Env var        | Purpose                                                                 |
|----------------|--------------------------------------------------------------------------|
| `HAYABUSA_BIN` | Full path (or PATH-resolvable name) of the `hayabusa` binary to invoke. |

Without `HAYABUSA_BIN` set, `resolve_binary()` falls back to `hayabusa`/`hayabusa.exe` on `PATH`.

## CLI flag reference

The exact flags used in `hayabusa.py` (per Hayabusa's `csv-timeline`/`json-timeline` command reference)
are worth knowing before changing the command-building logic in `scan()`:

- `-d`/`-f` — directory vs. single-file input
- `-o` — output file
- `-r` — custom rules directory/file (default: Hayabusa's bundled `./rules`)
- `-m` — minimum alert level (`informational`/`low`/`medium`/`high`/`critical`)
- `-U` — UTC timestamps (default is local time)
- `-L` — JSONL output (only meaningful with `json-timeline`)
- `-w` — no-wizard (non-interactive)
- `-q` — quiet (suppress launch banner)
