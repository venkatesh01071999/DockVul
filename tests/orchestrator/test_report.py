import json

import pytest

from orchestrator.report import EXIT_OK, EXIT_PARTIAL, EXIT_POLICY, build_report, exit_code, write_report

REQUEST = {"image": {"kind": "registry", "ref": "nginx"}}


def finding(severity="HIGH", usage="used"):
    return {"severity": severity, "usage": usage}


def test_build_report_complete_run():
    report = build_report({"run_id": "r", "request": REQUEST, "approved": True, "findings": [finding()],
                           "trivy": {"image": {"digest": "sha256:x"}}, "analysis": {"exposure": "public"}})
    assert report["status"] == "complete" and report["failures"] == []
    assert report["image"] == {"kind": "registry", "ref": "nginx", "digest": "sha256:x"}
    assert report["not_assessed"] == []


def test_failed_tool_makes_the_report_partial_and_unapproved_sandbox_is_listed():
    report = build_report({"run_id": "r", "request": REQUEST, "failures": ["trivy: down"]})
    assert report["status"] == "partial" and report["failures"] == ["trivy: down"]
    assert any("sandbox" in item for item in report["not_assessed"])
    assert report["image"]["digest"] is None


@pytest.mark.parametrize("findings,status,code", [
    ([finding("HIGH", "used")], "complete", EXIT_POLICY),
    ([finding("CRITICAL", "undetermined")], "complete", EXIT_POLICY),   # missing evidence never excuses a finding
    ([finding("CRITICAL", "not_reachable"), finding("LOW", "used")], "complete", EXIT_OK),
    ([], "complete", EXIT_OK),
    ([], "partial", EXIT_PARTIAL),
    ([finding("HIGH", "used")], "partial", EXIT_POLICY),                 # a violation wins over "partial"
])
def test_exit_code_policy(findings, status, code):
    assert exit_code({"findings": findings, "status": status}) == code


def test_write_report_creates_the_folder_and_a_fixed_file_name(tmp_path):
    path = write_report({"run_id": "r"}, tmp_path / "out" / "nested")
    assert path.name == "report.json" and json.loads(path.read_text()) == {"run_id": "r"}
