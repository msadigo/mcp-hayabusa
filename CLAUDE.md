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
```

There is no test suite, linter, or build step configured yet.

### Manual testing

`mcp dev` (from the `mcp[cli]` package) launches the MCP Inspector against the server for interactive
tool calls:

```sh
mcp dev src/mcp_hayabusa/server.py
```

Actually exercising `scan_evtx` requires the `hayabusa` binary to be installed (see Configuration below)
and at least one real or sample `.evtx` file — Hayabusa's own repo ships sample `.evtx` files under
`sample_evtx/` that are useful for this.

## Architecture

Two files carry all the logic:

- `src/mcp_hayabusa/hayabusa.py` — pure subprocess wrapper around the `hayabusa` binary. Owns binary
  resolution (`resolve_binary`, via `HAYABUSA_BIN` env var or `PATH`), building the `csv-timeline` /
  `json-timeline` command line, running it, and parsing the resulting CSV/JSON/JSONL output file into a
  `ScanResult` (command run, exit code, stdout/stderr tails, total `record_count`, and a preview capped
  at `PREVIEW_RECORD_LIMIT` records). Raises `HayabusaError` for a missing binary, missing target path,
  or a timed-out scan. This module has no MCP dependency and can be tested/used standalone.
- `src/mcp_hayabusa/server.py` — the MCP surface. A `FastMCP("hayabusa")` instance with one `@mcp.tool()`,
  `scan_evtx`, which validates nothing itself — it just forwards arguments to `hayabusa.scan()` and shapes
  the `ScanResult` into the dict returned to the MCP client, catching `HayabusaError` into an `{"error": ...}`
  response rather than raising.

When adding a new Hayabusa-backed tool (e.g. wrapping `logon-summary`, `eid-metrics`, or `search`), follow
this same split: put the subprocess/parsing logic in `hayabusa.py` as a plain function returning a
dataclass, then add a thin `@mcp.tool()` wrapper in `server.py`.

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
