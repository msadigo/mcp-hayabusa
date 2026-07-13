from __future__ import annotations

from mcp_hayabusa import server
from mcp_hayabusa.hayabusa import HayabusaError, RuleInfo, ScanResult


def _canned_result(returncode=0):
    # Preview records carry extra fields (RecordID, Details, ExtraFieldInfo, RuleID)
    # beyond server._CONDENSED_FIELDS, to prove "summary" drops them and "full" keeps them.
    preview = [
        {
            "Timestamp": "2024-01-01T00:00:00Z",
            "RuleTitle": "HackTool - Mimikatz Execution",
            "Level": "high",
            "Computer": "WORKSTATION1",
            "Channel": "Sec",
            "EventID": 4688,
            "RecordID": 999,
            "Details": {"CommandLine": "mimikatz.exe"},
            "ExtraFieldInfo": {"User": "bob"},
            "RuleID": "22222222-2222-2222-2222-222222222222",
        }
    ]
    return ScanResult(
        command=["hayabusa", "json-timeline", "-d", "target"],
        output_format="json",
        output_path="/tmp/output.json",
        returncode=returncode,
        stdout_tail="STDOUT TAIL",
        stderr_tail="STDERR TAIL",
        record_count=1,
        preview=preview,
        level_counts={"high": 1},
        top_rules=[{"rule_title": "HackTool - Mimikatz Execution", "level": "high", "count": 1}],
    )


# --- scan_evtx: result_detail shaping ---------------------------------------


def test_summary_condenses_preview_fields(monkeypatch):
    monkeypatch.setattr(server, "scan", lambda *a, **k: _canned_result())

    out = server.scan_evtx("target")

    [record] = out["preview"]
    assert record == {
        "Timestamp": "2024-01-01T00:00:00Z",
        "RuleTitle": "HackTool - Mimikatz Execution",
        "Level": "high",
        "Computer": "WORKSTATION1",
        "Channel": "Sec",
        "EventID": 4688,
    }
    assert "RecordID" not in record
    assert "Details" not in record


def test_summary_omits_tails_and_command_on_success(monkeypatch):
    monkeypatch.setattr(server, "scan", lambda *a, **k: _canned_result(returncode=0))

    out = server.scan_evtx("target")

    assert "stdout_tail" not in out
    assert "stderr_tail" not in out
    assert "command" not in out
    assert out["level_counts"] == {"high": 1}
    assert out["top_rules"] == [{"rule_title": "HackTool - Mimikatz Execution", "level": "high", "count": 1}]


def test_summary_includes_tails_on_failure(monkeypatch):
    monkeypatch.setattr(server, "scan", lambda *a, **k: _canned_result(returncode=1))

    out = server.scan_evtx("target")

    assert out["stdout_tail"] == "STDOUT TAIL"
    assert out["stderr_tail"] == "STDERR TAIL"


def test_full_returns_complete_preview_and_command(monkeypatch):
    monkeypatch.setattr(server, "scan", lambda *a, **k: _canned_result())

    out = server.scan_evtx("target", result_detail="full")

    [record] = out["preview"]
    assert record["RecordID"] == 999
    assert record["Details"] == {"CommandLine": "mimikatz.exe"}
    assert out["command"] == ["hayabusa", "json-timeline", "-d", "target"]
    assert out["stdout_tail"] == "STDOUT TAIL"
    assert out["stderr_tail"] == "STDERR TAIL"


# --- scan_evtx: argument passthrough and error handling ---------------------


def test_scan_evtx_forwards_arguments_to_scan(monkeypatch):
    captured = {}

    def fake_scan(target, **kwargs):
        captured["target"] = target
        captured.update(kwargs)
        return _canned_result()

    monkeypatch.setattr(server, "scan", fake_scan)

    server.scan_evtx(
        "some/target",
        is_file=True,
        output_format="csv",
        rules_dir="my-rules",
        rule_filter="mimikatz",
        min_level="high",
        utc=True,
        output_path="out.csv",
        max_results=7,
    )

    assert captured == {
        "target": "some/target",
        "is_file": True,
        "output_format": "csv",
        "rules_dir": "my-rules",
        "rule_filter": "mimikatz",
        "min_level": "high",
        "utc": True,
        "output_path": "out.csv",
        "max_results": 7,
    }


def test_scan_evtx_error_passthrough(monkeypatch):
    monkeypatch.setattr(server, "scan", lambda *a, **k: (_ for _ in ()).throw(HayabusaError("boom")))

    assert server.scan_evtx("target") == {"error": "boom"}


# --- get_hayabusa_rules -------------------------------------------------------


def _canned_rules():
    return [
        RuleInfo(
            path="creds/mimikatz.yml",
            id="22222222-2222-2222-2222-222222222222",
            title="HackTool - Mimikatz Execution",
            level="high",
            status="stable",
            description="Detects mimikatz.",
            author="Test Author",
            tags=["attack.credential-access"],
            logsource={"product": "windows", "service": "sysmon"},
        )
    ]


def test_get_hayabusa_rules_shapes_response(monkeypatch):
    monkeypatch.setattr(server, "list_rules", lambda **k: (_canned_rules(), 5))

    out = server.get_hayabusa_rules(keyword="mimikatz")

    assert out == {
        "keyword": "mimikatz",
        "total_matched": 5,
        "returned": 1,
        "rules": [
            {
                "path": "creds/mimikatz.yml",
                "id": "22222222-2222-2222-2222-222222222222",
                "title": "HackTool - Mimikatz Execution",
                "level": "high",
                "status": "stable",
                "description": "Detects mimikatz.",
                "author": "Test Author",
                "tags": ["attack.credential-access"],
                "logsource": {"product": "windows", "service": "sysmon"},
            }
        ],
    }


def test_get_hayabusa_rules_forwards_arguments(monkeypatch):
    captured = {}

    def fake_list_rules(**kwargs):
        captured.update(kwargs)
        return [], 0

    monkeypatch.setattr(server, "list_rules", fake_list_rules)

    server.get_hayabusa_rules(keyword="lateral", rules_dir="my-rules", max_results=3)

    assert captured == {"keyword": "lateral", "rules_dir": "my-rules", "max_results": 3}


def test_get_hayabusa_rules_error_passthrough(monkeypatch):
    monkeypatch.setattr(server, "list_rules", lambda **k: (_ for _ in ()).throw(HayabusaError("no rules dir")))

    assert server.get_hayabusa_rules() == {"error": "no rules dir"}
