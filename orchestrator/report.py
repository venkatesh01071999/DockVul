"""The JSON report, its CI exit code and where it is written."""
import json
from pathlib import Path
from typing import Any, Dict

EXIT_OK = 0
EXIT_POLICY = 1   # a critical/high finding that is not known to be unreachable
EXIT_PARTIAL = 3  # no violation found, but a tool failed so the result is incomplete (2 is argparse's)

FAIL_SEVERITIES = {"CRITICAL", "HIGH"}


def build_report(state: Dict[str, Any]) -> Dict[str, Any]:
    analysis = state.get("analysis") or {}
    failures = sorted(state.get("failures", []))
    not_assessed = list(analysis.get("not_assessed", []))
    if not state.get("approved"):
        not_assessed.append("sandbox checks (Docker Bench, seccomp profile): not run, no approval")
    return {
        "run_id": state["run_id"],
        "status": "partial" if failures else "complete",
        "failures": failures,
        "image": {**state["request"]["image"], 
        "digest": (state.get("trivy") or {}).get("image", {}).get("digest")},
        "ranking": state.get("ranking", "deterministic"),
        "exposure": analysis.get("exposure", "unknown"),
        "findings": state.get("findings", []),
        "config_findings": analysis.get("config_findings", []),
        "not_assessed": not_assessed,
        "cis": state.get("bench"),
        "seccomp": state.get("slim"),
    }


def exit_code(report: Dict[str, Any]) -> int:
    if any(f["severity"] in FAIL_SEVERITIES and f["usage"] != "not_reachable" for f in report["findings"]):
        return EXIT_POLICY
    return EXIT_PARTIAL if report["status"] == "partial" else EXIT_OK


def write_report(report: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"  # fixed name: nothing user-controlled decides where this is written
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
