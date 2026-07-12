"""Thin subprocess wrapper around the Hayabusa CLI binary.

Flags are based on Hayabusa's csv-timeline/json-timeline reference
(https://yamato-security.github.io/hayabusa/commands/dfir-timeline/).
"""

from __future__ import annotations

import csv
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

OutputFormat = Literal["csv", "json", "jsonl"]

PREVIEW_RECORD_LIMIT = 20


class HayabusaError(RuntimeError):
    """Raised when the hayabusa binary cannot be found, or a scan fails/times out."""


def resolve_binary() -> str:
    """Locate the hayabusa executable.

    Checks the HAYABUSA_BIN env var first (either a full path or a name to
    resolve on PATH), then falls back to `hayabusa`/`hayabusa.exe` on PATH.
    """
    configured = os.environ.get("HAYABUSA_BIN")
    if configured:
        resolved = configured if Path(configured).exists() else shutil.which(configured)
        if not resolved:
            raise HayabusaError(
                f"HAYABUSA_BIN is set to '{configured}' but it does not exist "
                "and cannot be resolved on PATH."
            )
        return resolved

    found = shutil.which("hayabusa") or shutil.which("hayabusa.exe")
    if not found:
        raise HayabusaError(
            "Could not find the hayabusa binary. Install it from "
            "https://github.com/Yamato-Security/hayabusa, ensure it is on PATH, "
            "or set the HAYABUSA_BIN environment variable to its full path."
        )
    return found


@dataclass
class ScanResult:
    command: list[str]
    output_format: OutputFormat
    output_path: str
    returncode: int
    stdout_tail: str
    stderr_tail: str
    record_count: int | None = None
    preview: list[dict] | dict | None = None


def _tail(text: str, lines: int = 40) -> str:
    return "\n".join(text.splitlines()[-lines:])


def scan(
    target: str,
    *,
    is_file: bool = False,
    output_format: OutputFormat = "json",
    rules_dir: str | None = None,
    min_level: str | None = None,
    utc: bool = False,
    output_path: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 1800,
) -> ScanResult:
    """Run `hayabusa csv-timeline`/`json-timeline` against an .evtx file or directory.

    Always passes -w/-q so the scan runs non-interactively (no rule-config
    wizard, no launch banner), which is required since there is no stdin/tty
    when invoked from an MCP tool call.
    """
    target_path = Path(target)
    if not target_path.exists():
        raise HayabusaError(f"Target path does not exist: {target}")

    binary = resolve_binary()
    subcommand = "csv-timeline" if output_format == "csv" else "json-timeline"

    cleanup_output = output_path is None
    if output_path is None:
        suffix = ".csv" if output_format == "csv" else ".json"
        fd, output_path = tempfile.mkstemp(prefix="hayabusa_", suffix=suffix)
        os.close(fd)

    command = [binary, subcommand]
    command += ["-f", str(target_path)] if is_file else ["-d", str(target_path)]
    command += ["-o", output_path, "-w", "-q"]
    if rules_dir:
        command += ["-r", rules_dir]
    if min_level:
        command += ["-m", min_level]
    if utc:
        command += ["-U"]
    if output_format == "jsonl":
        command += ["-L"]
    if extra_args:
        command += extra_args

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise HayabusaError(f"Failed to execute hayabusa binary at '{binary}': {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HayabusaError(f"hayabusa scan timed out after {timeout}s") from exc

    result = ScanResult(
        command=command,
        output_format=output_format,
        output_path=output_path,
        returncode=proc.returncode,
        stdout_tail=_tail(proc.stdout),
        stderr_tail=_tail(proc.stderr),
    )

    if proc.returncode == 0 and Path(output_path).exists():
        _attach_preview(result)
        if cleanup_output:
            Path(output_path).unlink(missing_ok=True)

    return result


def _attach_preview(result: ScanResult, max_records: int = PREVIEW_RECORD_LIMIT) -> None:
    path = Path(result.output_path)

    if result.output_format == "csv":
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as f:
            rows = list(csv.DictReader(f))
        result.record_count = len(rows)
        result.preview = rows[:max_records]
        return

    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if not text.strip():
        result.record_count = 0
        result.preview = []
        return

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # JSONL: one JSON object per line.
        lines = [line for line in text.splitlines() if line.strip()]
        result.record_count = len(lines)
        result.preview = [json.loads(line) for line in lines[:max_records]]
        return

    if isinstance(data, list):
        result.record_count = len(data)
        result.preview = data[:max_records]
    else:
        result.record_count = 1
        result.preview = data
