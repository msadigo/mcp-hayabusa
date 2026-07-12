"""FastMCP server exposing Hayabusa EVTX scanning as an MCP tool."""

from __future__ import annotations

from typing import Literal

from mcp.server.fastmcp import FastMCP

from mcp_hayabusa.hayabusa import HayabusaError, ScanResult, scan

mcp = FastMCP("hayabusa")


@mcp.tool()
def scan_evtx(
    target: str,
    is_file: bool = False,
    output_format: Literal["csv", "json", "jsonl"] = "json",
    rules_dir: str | None = None,
    min_level: str | None = None,
    utc: bool = False,
    output_path: str | None = None,
) -> dict:
    """Run a Hayabusa detection scan over Windows Event Log (.evtx) data.

    Wraps `hayabusa csv-timeline` / `hayabusa json-timeline`, always run
    non-interactively (no rule-config wizard, no launch banner).

    Args:
        target: Path to a single .evtx file (set is_file=True) or a
            directory containing .evtx files.
        is_file: True if `target` is a single .evtx file rather than a
            directory.
        output_format: "csv" (uses csv-timeline), or "json"/"jsonl"
            (both use json-timeline; jsonl adds Hayabusa's -L flag).
        rules_dir: Optional path to a custom Sigma/Hayabusa rules
            directory or file (passed as -r). Defaults to Hayabusa's
            bundled ./rules.
        min_level: Optional minimum alert level to load: "informational",
            "low", "medium", "high", or "critical" (passed as -m).
        utc: Output timestamps in UTC instead of local time (-U).
        output_path: Where to write the full result file. If omitted, a
            temporary file is used and deleted after a preview is
            extracted, so the full result set is only kept on disk when
            you pass this explicitly.

    Returns:
        A dict with the command that was run, its exit code, a truncated
        stdout/stderr tail, the total record_count found, and a preview
        of up to 20 records.
    """
    try:
        result: ScanResult = scan(
            target,
            is_file=is_file,
            output_format=output_format,
            rules_dir=rules_dir,
            min_level=min_level,
            utc=utc,
            output_path=output_path,
        )
    except HayabusaError as exc:
        return {"error": str(exc)}

    return {
        "command": result.command,
        "returncode": result.returncode,
        "output_format": result.output_format,
        "output_path": output_path,
        "record_count": result.record_count,
        "preview": result.preview,
        "stdout_tail": result.stdout_tail,
        "stderr_tail": result.stderr_tail,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
