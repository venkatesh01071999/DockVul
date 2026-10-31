import asyncio

import pytest

pytest.importorskip("langgraph")
pytest.importorskip("httpx")

from gateway.approval import ApprovalVerifier  # noqa: E402
from orchestrator.gateway_client import GatewayError  # noqa: E402
from orchestrator.graph import run_scan  # noqa: E402

DIGEST = "sha256:" + "a" * 64


def scan(request_, gateway, settings, **kw):
    return asyncio.run(run_scan(request_, gateway, settings, **kw))


class Approver:
    def __init__(self, answer):
        self.answer, self.asked = answer, []

    async def __call__(self, info):
        self.asked.append(info)
        return self.answer


def test_full_scan_with_approval_runs_all_four_tools_and_ranks(request_, make_gateway, settings):
    gateway, approver = make_gateway(), Approver(True)

    report = scan(request_, gateway, settings, approve=approver)

    assert sorted(gateway.tools()) == ["analyze_config", "docker_bench_section4", "slim_seccomp_profile", "trivy_scan"]
    assert report["status"] == "complete" and report["image"]["digest"] == DIGEST
    # used HIGH (3.0), used LOW (1.0), CRITICAL but not reachable (1.2) -> CVE-1, CVE-2, CVE-3 by score
    assert [f["id"] for f in report["findings"]] == ["CVE-1", "CVE-2", "CVE-3"]
    assert report["cis"] == {"checks": ["4.1 PASS"]} and report["seccomp"]["coverage"] == "GET / only"
    assert report["config_findings"][0]["id"] == "DV-ROOT"
    # the person was shown the digest and the privileged-mode warning
    assert approver.asked[0]["image_digest"] == DIGEST
    assert "PRIVILEGED" in approver.asked[0]["warning"]


def test_sandbox_calls_carry_a_valid_single_use_approval_token(request_, make_gateway, settings):
    gateway = make_gateway()
    scan(request_, gateway, settings, approve=Approver(True))

    verifier = ApprovalVerifier(settings.approval_secret)
    for tool, name in (("slim_seccomp_profile", "slim"), ("docker_bench_section4", "bench")):
        args = dict(gateway.calls)[tool]
        assert args["image_digest"] == DIGEST
        verifier.verify(args["approval_token"], tool=name, image_digest=DIGEST)  # no exception


@pytest.mark.parametrize("approver", [None, Approver(False), Approver("yes")])  # none, denied, not an explicit True
def test_without_approval_the_sandbox_never_runs(request_, make_gateway, settings, approver):
    gateway = make_gateway()

    report = scan(request_, gateway, settings, approve=approver)

    assert sorted(gateway.tools()) == ["analyze_config", "trivy_scan"]
    assert report["status"] == "complete" and report["cis"] is None and report["seccomp"] is None
    assert any("not run, no approval" in item for item in report["not_assessed"])


def test_a_failing_approval_prompt_counts_as_denied(request_, make_gateway, settings):
    async def broken(info):
        raise RuntimeError("terminal closed")

    gateway = make_gateway()
    scan(request_, gateway, settings, approve=broken)
    assert "slim_seccomp_profile" not in gateway.tools()


def test_trivy_failure_gives_a_partial_report_and_no_approval_prompt(request_, make_gateway, settings):
    gateway, approver = make_gateway(trivy_scan=GatewayError("trivy worker failed")), Approver(True)

    report = scan(request_, gateway, settings, approve=approver)

    assert report["status"] == "partial" and report["failures"] == ["trivy: trivy worker failed"]
    assert approver.asked == [] and "docker_bench_section4" not in gateway.tools()
    assert report["config_findings"]  # the analysis branch still delivered


def test_analysis_failure_keeps_findings_and_never_downgrades_them(request_, make_gateway, settings):
    gateway = make_gateway(analyze_config=GatewayError("analysis timed out"))

    report = scan(request_, gateway, settings)

    assert report["status"] == "partial" and report["exposure"] == "unknown"
    assert {f["usage"] for f in report["findings"]} == {"undetermined"}


def test_malformed_worker_answer_is_a_failure_not_a_crash(request_, make_gateway, settings):
    bad = {"image": {"digest": "latest"}, "findings": []}  # digest is not a sha256
    report = scan(request_, make_gateway(trivy_scan=bad), settings)
    assert report["failures"] == ["trivy: invalid response from the gateway"]


def test_empty_analysis_answer_is_a_failure_not_silent_success(request_, make_gateway, settings):
    report = scan(request_, make_gateway(analyze_config={}), settings)  # no usage, no exposure
    assert report["failures"] == ["analysis: invalid response from the gateway"]
    assert report["status"] == "partial"
