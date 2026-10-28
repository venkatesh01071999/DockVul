"""
Shared fixtures for the gateway tests.
"""
import asyncio
import dataclasses

import pytest

from gateway.auth import AuthMiddleware
from gateway.audit import AuditLog
from gateway.approval import ApprovalVerifier
from gateway.config import Settings
from gateway.workers import WorkerPool
from gateway.server import create_server


DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def settings():
    # short queue_timeout for test
    return Settings(gateway_token="g" * 16, worker_token="w" * 16, approval_secret=b"s" * 32, queue_timeout=0.1)


@pytest.fixture
def override(settings):
    """override(max_response_bytes=10) -> a copy of the settings with those fields changed."""
    return lambda **changes: dataclasses.replace(settings, **changes)


@pytest.fixture
def audit_lines():
    return []


@pytest.fixture
def audit(audit_lines):
    return AuditLog(sink=audit_lines.append)


@pytest.fixture
def verifier(settings):
    return ApprovalVerifier(settings.approval_secret)


class WorkerStub:
    """Stands in for all four workers: records requests, answers per path (default 200 {})."""

    def __init__(self):
        self.requests = []
        self.responses = {}  # path -> (status code, JSON body)

    def handler(self, request):
        import httpx

        self.requests.append(request)
        status, body = self.responses.get(request.url.path, (200, {}))
        return httpx.Response(status, json=body)


@pytest.fixture
def worker_stub():
    return WorkerStub()


@pytest.fixture
def make_pool(worker_stub):
    """make_pool(settings, handler=None) -> WorkerPool whose HTTP calls go to the stub (or `handler`)."""
    httpx = pytest.importorskip("httpx")

    def _make(settings, handler=None):
        transport = httpx.MockTransport(handler or worker_stub.handler)
        return WorkerPool(settings, client=httpx.AsyncClient(transport=transport))

    return _make


@pytest.fixture
def pool(settings, make_pool):
    return make_pool(settings)


@pytest.fixture
def call_tool(settings, pool, audit, verifier):
    """call_tool(name, args) runs one MCP tool call against an in-memory gateway and returns the result."""
    pytest.importorskip("mcp")
    pytest.importorskip("uvicorn")
    from mcp.shared.memory import create_connected_server_and_client_session


    server = create_server(settings, pool=pool, audit=audit, verifier=verifier)

    def _call(name, args):
        async def go():
            async with create_connected_server_and_client_session(server) as client:
                return await client.call_tool(name, args)

        return asyncio.run(go())

    _call.server = server
    return _call

@pytest.fixture
def inner_calls():
    return []


@pytest.fixture
def app(inner_calls):
    async def inner(scope, receive, send):
        inner_calls.append(scope["type"])
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

    return AuthMiddleware(inner, "t" * 16, exempt_paths={"/health"})


@pytest.fixture
def asgi_request():
    """asgi_request(app, path, headers) -> list of the ASGI messages the app sent back."""

    def _request(app, path="/mcp", headers=()):
        sent = []

        async def receive():
            return {"type": "http.request"}

        async def send(message):
            sent.append(message)

        asyncio.run(app({"type": "http", "path": path, "headers": list(headers)}, receive, send))
        return sent

    return _request
