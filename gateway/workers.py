"""
Client for the decoupled workers behind the gateway.

Worker contract (plain HTTP + JSON, reachable only from the gateway's network; every request
carries `Authorization: Bearer <WORKER_TOKEN>`):

    tool      endpoint               request body                                   notes
    trivy     POST /scan             {"image": Image, "skip_db_update": bool}       new Trivy process per request
    analysis  POST /analyze          ScanRequest                                    deterministic checks
    slim      POST /profile          {"image_digest", "http_probe", "exec_script"}  sandbox, privileged, approved
    bench     POST /section4         {"image_digest"}                               sandbox, CIS section 4 only

A worker answers 200 with a JSON object. Anything else is an error

Per-tool concurrency limits live here: a call waits for a free slot for at most `queue_timeout`
and is then refused as "busy", so a flood of requests cannot pile up behind one slow tool.
"""
import asyncio
import json
from typing import Any, Dict, Optional

import httpx

from gateway.config import Settings


class WorkerError(Exception):
    """`str(e)` is safe to show the caller; `detail` is for the audit log only."""

    def __init__(self, message: str, detail: str = "") -> None:
        super().__init__(message)
        self.detail = detail


class WorkerPool:
    def __init__(self, settings: Settings, client: Optional[httpx.AsyncClient] = None) -> None:
        self._settings = settings
        # No redirects (a worker must not redirect the gateway elsewhere)
        # Connection pooling is handled by httpx.AsyncClient, so the gateway can scale to many concurrent requests without opening a new TCP connection for every request.
        self._client = client or httpx.AsyncClient(follow_redirects=False, trust_env=False)
        self._slots: Dict[str, asyncio.Semaphore] = {
            tool: asyncio.Semaphore(n) for tool, n in settings.concurrency.items()
        }

    async def aclose(self) -> None:
        await self._client.aclose()

    async def call(self, tool: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            # wait to acquire a lock for this tool, or timeout if the queue is full
            await asyncio.wait_for(self._slots[tool].acquire(), self._settings.queue_timeout)
        except asyncio.TimeoutError:
            raise WorkerError(f"{tool} is busy, try again later") from None
        try:
            return await asyncio.wait_for(self._post(tool, path, payload), self._settings.timeouts[tool])
        except asyncio.TimeoutError:
            raise WorkerError(f"{tool} timed out") from None
        finally:
            self._slots[tool].release()

    async def _post(self, tool: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self._settings.worker_urls[tool]}{path}"
        headers = {"Authorization": f"Bearer {self._settings.worker_token}"}
        cap = self._settings.max_response_bytes
        try:
            async with self._client.stream("POST", url, json=payload, headers=headers) as resp:
                if resp.status_code != 200:
                    body = (await resp.aread())[:500].decode("utf-8", "replace")
                    if resp.status_code in (400, 422):
                        raise WorkerError(f"{tool} worker rejected the input", f"HTTP {resp.status_code}: {body}")
                    raise WorkerError(f"{tool} worker failed", f"HTTP {resp.status_code}: {body}")
                chunks, size = [], 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > cap:
                        raise WorkerError(f"{tool} worker response too large", f"over {cap} bytes")
                    chunks.append(chunk)
        except httpx.TransportError as e:
            raise WorkerError(f"{tool} worker unreachable", f"{type(e).__name__}: {e}") from None

        try:
            data = json.loads(b"".join(chunks))
        except ValueError:
            raise WorkerError(f"{tool} worker returned invalid JSON") from None
        if not isinstance(data, dict):
            raise WorkerError(f"{tool} worker returned an unexpected response", f"type {type(data).__name__}")
        return data
