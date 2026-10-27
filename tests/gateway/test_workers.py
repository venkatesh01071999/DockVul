import asyncio

import pytest

httpx = pytest.importorskip("httpx")

from gateway.workers import WorkerError


def call(pool, tool="trivy", path="/scan", payload=None):
    return asyncio.run(pool.call(tool, path, payload or {"image": "x"}))


def test_successful_call_posts_json_with_the_worker_token(pool, worker_stub, settings):
    worker_stub.responses["/scan"] = (200, {"findings": []})

    assert call(pool) == {"findings": []}

    request = worker_stub.requests[0]
    assert str(request.url) == f"{settings.worker_urls['trivy']}/scan"
    assert request.headers["authorization"] == f"Bearer {settings.worker_token}"
    assert request.content == b'{"image":"x"}'


@pytest.mark.parametrize("status,message", [(422, "rejected the input"), (500, "worker failed")])
def test_worker_errors_are_translated_and_details_kept_for_the_log(pool, worker_stub, status, message):
    worker_stub.responses["/scan"] = (status, {"trace": "internal detail"})

    with pytest.raises(WorkerError, match=message) as e:
        call(pool)

    assert "internal detail" not in str(e.value)    # safe for the caller
    assert "internal detail" in e.value.detail      # kept for the audit log


def test_unreachable_worker_is_reported(make_pool, settings):
    def down(request):
        raise httpx.ConnectError("connection refused")

    with pytest.raises(WorkerError, match="unreachable"):
        call(make_pool(settings, handler=down))


def test_response_over_the_size_cap_is_rejected(make_pool, worker_stub, override):
    worker_stub.responses["/scan"] = (200, {"big": "x" * 100})
    with pytest.raises(WorkerError, match="too large"):
        call(make_pool(override(max_response_bytes=10)))


def test_second_call_is_refused_as_busy_when_the_tool_limit_is_reached(make_pool, settings):
    async def slow(request):
        await asyncio.sleep(0.5)
        return httpx.Response(200, json={})

    pool = make_pool(settings, handler=slow)  # slim allows 1 concurrent call, queue_timeout is 0.1s

    async def two_calls():
        return await asyncio.gather(
            pool.call("slim", "/profile", {}), pool.call("slim", "/profile", {}), return_exceptions=True)

    results = asyncio.run(two_calls())
    assert sorted(type(r).__name__ for r in results) == ["WorkerError", "dict"]
    assert any(isinstance(r, WorkerError) and "busy" in str(r) for r in results)
