# mcp-hayabusa

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa),
the Windows event log fast forensics timeline and threat-hunting tool, so an
MCP client (e.g. Claude Code) can run detection scans over `.evtx` files.

## Prerequisites

- Python 3.10+
- The `hayabusa` binary, downloaded from the
  [Hayabusa releases page](https://github.com/Yamato-Security/hayabusa/releases)
  (or built from source), available on `PATH`, or pointed to via the
  `HAYABUSA_BIN` environment variable.

## Install

```sh
pip install -e .
```

## Run

```sh
mcp-hayabusa
```

Or point an MCP client's config at the installed console script
(`mcp-hayabusa`) or at `python -m mcp_hayabusa.server`.

## Configuration

| Env var       | Purpose                                                              |
|---------------|-----------------------------------------------------------------------|
| `HAYABUSA_BIN`| Full path (or PATH-resolvable name) of the hayabusa binary to invoke. |

## Tools

### `scan_evtx`

Runs `hayabusa csv-timeline` or `hayabusa json-timeline` against a single
`.evtx` file or a directory of `.evtx` files, always non-interactively.

Parameters: `target`, `is_file`, `output_format` (`csv`/`json`/`jsonl`),
`rules_dir`, `min_level`, `utc`, `output_path`.

Returns the command that was run, exit code, a preview of up to 20 result
records, the total record count, and truncated stdout/stderr. Pass
`output_path` explicitly to keep the full result file on disk; otherwise a
temporary file is used and removed after the preview is extracted.
