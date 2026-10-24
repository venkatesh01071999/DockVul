"""Bearer-token check in front of the MCP endpoint"""
import hmac
import json
from typing import Awaitable, Callable, Iterable

Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]

# Custom Middleware for Bearer token authentication, to be used in front of the MCP endpoint.
class AuthMiddleware:
    def __init__(self, app, token: str, exempt_paths: Iterable[str] = ()) -> None:
        self._app = app
        self._expected = f"Bearer {token}".encode()
        self._exempt = frozenset(exempt_paths) # exemption paths that don't require authentication

    async def __call__(self, scope: dict, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] not in self._exempt:
            given = dict(scope["headers"]).get(b"authorization", b"")
            if not hmac.compare_digest(given, self._expected):
                body = json.dumps({"error": "unauthorized"}).encode()
                await send({"type": "http.response.start", "status": 401, "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b"Bearer"),
                ]})
                await send({"type": "http.response.body", "body": body})
                return
        await self._app(scope, receive, send)
