import json

import pytest

pytest.importorskip("mcp")
pytest.importorskip("httpx")
pytest.importorskip("uvicorn")

from gateway.approval import issue_approval

DIGEST = "sha256:" + "a" * 64
RUN = {"run_id": "run-12345678"}


def body(result):
    return json.loads(result.content[0].text)


def test_exposes_the_four_tools(call_tool):
    import asyncio

    tools = asyncio.run(call_tool.server.list_tools())
    assert sorted(t.name for t in tools) == [
        "analyze_config", "docker_bench_section4", "slim_seccomp_profile", "trivy_scan"]


def test_trivy_scan_forwards_to_the_worker_and_masks_the_answer(call_tool, worker_stub, audit_lines):
    worker_stub.responses["/scan"] = (200, {"image_config": {"Env": ["DB_PASSWORD=hunter2"]}})

    result = call_tool("trivy_scan", {**RUN, "image": {"kind": "registry", "ref": "nginx:latest"}})

    assert not result.isError
    # structured output is the envelope itself, not wrapped in {"result": ...}
    assert result.structuredContent["tool"] == "trivy"
    assert result.structuredContent["result"] == {"image_config": {"Env": ["DB_PASSWORD=<REDACTED:env_secret>"]}}
    out = body(result)
    assert out["redactions"] == 1
    assert out["result"] == {"image_config": {"Env": ["DB_PASSWORD=<REDACTED:env_secret>"]}}
    assert "hunter2" not in result.content[0].text
    assert json.loads(worker_stub.requests[0].content) == {
        "image": {"kind": "registry", "ref": "nginx:latest"}, "skip_db_update": True}
    assert json.loads(audit_lines[-1])["status"] == "ok"


@pytest.mark.parametrize("args", [
    {**RUN, "image": {"kind": "registry", "ref": "--config=evil"}},     # option injection
    {"run_id": "x", "image": {"kind": "registry", "ref": "nginx"}},     # run_id too short
    {**RUN, "image": {"kind": "tarball", "name": "../../etc/passwd"}},  # path in tarball name
])
def test_invalid_arguments_are_rejected_before_reaching_a_worker(call_tool, worker_stub, args):
    result = call_tool("trivy_scan", args)
    assert result.isError
    assert worker_stub.requests == []

def test_analyze_config_accepts_and_forwards(call_tool, worker_stub):
    worker_stub.responses["/analyze"] = (200, {"result": ""})
    request = {"image": {"kind": "tarball", "name": "img.tar"}, "source": {"kind": "local"}}
    assert not call_tool("analyze_config", {**RUN, "request": request}).isError

def test_analyze_config_rejects_a_path_that_escapes_the_source(call_tool, worker_stub):
    request = {"image": {"kind": "registry", "ref": "nginx"}, "source": {"kind": "local"},
               "dockerfile": "../../etc/passwd"}
    assert call_tool("analyze_config", {**RUN, "request": request}).isError
    assert worker_stub.requests == []

def test_sandbox_tool_without_a_valid_approval_is_denied(call_tool, worker_stub, audit_lines):
    result = call_tool("slim_seccomp_profile", {**RUN, "image_digest": DIGEST, "approval_token": "x" * 40})

    assert result.isError
    assert worker_stub.requests == []
    assert json.loads(audit_lines[-1])["status"] == "denied"

def test_sandbox_dockerbench_with_a_valid_approval_runs_once(call_tool, worker_stub, settings):
    worker_stub.responses["/section4"] = (200, {})
    approval = issue_approval(settings.approval_secret, tool="bench", image_digest=DIGEST)
    args = {**RUN, "image_digest": DIGEST, "approval_token": approval}
    bench = call_tool("docker_bench_section4", args)
    assert not bench.isError and body(bench)["result"] == {}

def test_sandbox_slim_with_a_valid_approval_runs_once(call_tool, worker_stub, settings):
    worker_stub.responses["/profile"] = (200, {"syscalls": ["read"]})
    approval = issue_approval(settings.approval_secret, tool="slim", image_digest=DIGEST)
    args = {**RUN, "image_digest": DIGEST, "approval_token": approval}

    first = call_tool("slim_seccomp_profile", args)
    assert not first.isError and body(first)["result"] == {"syscalls": ["read"]}
    assert json.loads(worker_stub.requests[0].content) == {"image_digest": DIGEST}

    # the same token cannot be replayed
    assert call_tool("slim_seccomp_profile", args).isError
    assert len(worker_stub.requests) == 1

def test_worker_failure_is_reported_without_internal_details(call_tool, worker_stub, audit_lines):
    worker_stub.responses["/scan"] = (500, {"trace": "internal stack trace"})

    result = call_tool("trivy_scan", {**RUN, "image": {"kind": "registry", "ref": "nginx"}})

    assert result.isError
    assert "trivy worker failed" in result.content[0].text
    assert "internal stack trace" not in result.content[0].text
    assert "internal stack trace" in audit_lines[-1]  # but it is in the audit log