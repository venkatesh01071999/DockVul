"""
The orchestrator's only way to reach a scanner: tool calls to the MCP gateway.

The graph calls the tools itself, so the LLM is never given them. Each call opens its own short
connection
"""
import json
from datetime import timedelta
from typing import Any, Dict

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult

MAX_ERROR_CHARS = 300


class GatewayError(Exception):
    """A failed gateway call. The message is safe to show and to put in the report."""


def unwrap(result: CallToolResult) -> Dict[str, Any]:
    """Turn a tool result into its JSON object, or raise GatewayError."""
    text = result.content[0].text if result.content and hasattr(result.content[0], "text") else ""
    if result.isError:
        raise GatewayError(text[:MAX_ERROR_CHARS] or "tool call failed")
    data = result.structuredContent
    if data is None:
        try:
            data = json.loads(text)
        except ValueError:
            raise GatewayError("gateway returned a response that is not JSON") from None
    if not isinstance(data, dict):
        raise GatewayError("gateway returned an unexpected response")
    return data


class GatewayClient:
    def __init__(self, url: str, token: str, timeout: float = 1800.0) -> None:
        self._url = url
        self._token = token
        self._timeout = timeout

    async def call(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]: # pragma: no cover
        # no redirects and no proxy settings from the environment: the gateway URL is the only target
        http = httpx.AsyncClient(headers={"Authorization": f"Bearer {self._token}"},
                                 timeout=httpx.Timeout(self._timeout), follow_redirects=False, trust_env=False)
        try:
            async with http, streamable_http_client(self._url, http_client=http) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        tool, args, read_timeout_seconds=timedelta(seconds=self._timeout))
        except Exception:  # connection, HTTP status (e.g. 401) or protocol errors: details stay out of the report
            raise GatewayError("gateway unreachable or rejected the call") from None
        return unwrap(result)
