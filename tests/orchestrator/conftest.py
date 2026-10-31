"""Shared fixtures for the orchestrator tests (the gateway is replaced by a fake)."""
import pytest

from common.schemas import ScanRequest
from orchestrator.config import Settings

DIGEST = "sha256:" + "a" * 64


class FakeGateway:
    """Stands in for the MCP gateway. responses: tool -> result dict, or an exception to raise."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []  # (tool, args)

    async def call(self, tool, args):
        self.calls.append((tool, args))
        response = self.responses[tool]
        if isinstance(response, Exception):
            raise response
        return {"tool": tool, "run_id": args["run_id"], "redactions": 0, "result": response}

    def tools(self):
        return [tool for tool, _ in self.calls]


TRIVY_OK = {
    "image": {"digest": DIGEST, "entrypoint": ["gunicorn", "app:app"]},
    "findings": [
        {"id": "CVE-1", "pkg": "libA", "severity": "HIGH"},
        {"id": "CVE-2", "pkg": "libB", "severity": "CRITICAL"},
        {"id": "CVE-3", "pkg": "libC", "severity": "LOW"},
    ],
}
ANALYSIS_OK = {
    "usage": {"CVE-1:libA": "used", "CVE-2:libB": "not_reachable", "CVE-3:libC": "used"},
    "exposure": "public",
    "config_findings": [{"id": "DV-ROOT", "severity": "MEDIUM", "title": "runs as root"}],
}


@pytest.fixture
def settings():
    return Settings(gateway_token="g" * 16, approval_secret=b"s" * 32)


@pytest.fixture
def request_():
    return ScanRequest.model_validate({"image": {"kind": "registry", "ref": "nginx:latest"}})


@pytest.fixture
def make_gateway():
    """make_gateway(**overrides) -> FakeGateway answering all four tools (overrides replace single tools)."""

    def _make(**overrides):
        responses = {"trivy_scan": TRIVY_OK, "analyze_config": ANALYSIS_OK,
                     "docker_bench_section4": {"checks": ["4.1 PASS"]},
                     "slim_seccomp_profile": {"syscalls_observed": ["read"], "coverage": "GET / only"}}
        responses.update(overrides)
        return FakeGateway(responses)

    return _make
