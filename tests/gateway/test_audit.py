import json

from gateway.audit import AuditLog


def test_record_writes_one_json_line_with_a_timestamp(audit, audit_lines):
    audit.record(tool="trivy", status="ok")
    entry = json.loads(audit_lines[0])
    assert entry["tool"] == "trivy" and entry["status"] == "ok" and "ts" in entry


def test_record_appends_to_the_log_file(tmp_path):
    path = tmp_path / "audit.log"
    log = AuditLog(path)
    log.record(n=1)
    log.record(n=2)
    assert [json.loads(line)["n"] for line in path.read_text().splitlines()] == [1, 2]
