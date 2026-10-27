"""
Human-approval tokens for the sandbox tools (Slim runs the target privileged).

The graph's human-in-the-loop step mints a token once the person approves. The gateway checks it
before forwarding to the Slim / Docker Bench workers, so a buggy or prompt-injected graph that
skips the approval step still cannot start the sandbox.

A token is bound to ONE tool and ONE image digest, expires after a TTL (a timeout counts as
denied) and can be used once. Used tokens are remembered in memory only and after a gateway restart
an unexpired token could be replayed once.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Callable, Dict, Optional


class ApprovalError(Exception):
    """The token is missing, malformed, forged, expired, for another tool/digest, or already used."""


def _b64(raw: bytes) -> str:
    # strip the final = from base 64 encoding
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    # add back the final = to properly decode
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(secret: bytes, payload: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).digest()


def issue_approval(secret: bytes, *, tool: str, image_digest: str, ttl_seconds: int = 600,
                   now: Optional[float] = None) -> str:
    """Called by the orchestrator after a person approved running `tool` on `image_digest`."""
    now = time.time() if now is None else now
    # n - random nonce
    payload = json.dumps(
        {"t": tool, "d": image_digest, "exp": int(now) + ttl_seconds, "n": secrets.token_hex(8)},
        separators=(",", ":"),
    ).encode()
    return f"{_b64(payload)}.{_b64(_sign(secret, payload))}"


class ApprovalVerifier:
    def __init__(self, secret: bytes, clock = time.time) -> None:
        self._secret = secret
        self._clock = clock
        self._used: Dict[str, int] = {} # nonce -> expiry (random hex string -> int timestamp)

    def verify(self, token: str, *, tool: str, image_digest: str) -> None:
        """Raise ApprovalError unless `token` approves `tool` on `image_digest`."""
        try:
            payload_part, sig_part = token.split(".")
            payload, sig = _unb64(payload_part), _unb64(sig_part)
            claims = json.loads(payload)
            tool_claim, digest_claim = claims["t"], claims["d"]
            expiry, nonce = int(claims["exp"]), str(claims["n"])
        except (ValueError, KeyError, TypeError, AttributeError):
            raise ApprovalError("malformed approval token") from None

        if not hmac.compare_digest(sig, _sign(self._secret, payload)):
            raise ApprovalError("invalid approval token signature")
        if tool_claim != tool or digest_claim != image_digest:
            raise ApprovalError("approval is for a different tool or image")

        now = self._clock()
        self._used = {n: exp for n, exp in self._used.items() if exp > now}
        if expiry <= now:
            raise ApprovalError("approval expired")
        if nonce in self._used:
            raise ApprovalError("approval already used")
        self._used[nonce] = expiry
