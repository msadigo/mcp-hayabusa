# mcp-hayabusa

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

An MCP (Model Context Protocol) server that wraps [Hayabusa](https://github.com/Yamato-Security/hayabusa),
the Windows event log fast forensics timeline and threat-hunting tool, so an
MCP client (e.g. Claude Code) can run detection scans over `.evtx` files.

## Prerequisites

- Python 3.10+
- The `hayabusa` binary, downloaded from the
  [Hayabusa releases page](https://github.com/Yamato-Security/hayabusa/releases)
  (or built from source), available on `PATH`, or pointed to via the
  `HAYABUSA_BIN` environment variable.

  `scripts/download_hayabusa.py` will fetch the latest release for your
  platform and extract it to `./hayabusa/`:

  ```sh
  python scripts/download_hayabusa.py
  # then either add ./hayabusa to PATH, or:
  export HAYABUSA_BIN=./hayabusa/hayabusa   # ./hayabusa/hayabusa.exe on Windows
  ```

  Pass `--version vX.Y.Z` to pin a release, `--musl` for a musl build on
  Linux, or `--force` to re-download.

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
