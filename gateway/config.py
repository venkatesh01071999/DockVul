"""Gateway settings, read once from environment variables at startup."""
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

TOOLS = ("trivy", "analysis", "slim", "bench")


class ConfigError(Exception):
    pass

# frozen dataclass is used to make Settings immutable after object creation, which is a good practice for configuration objects.
@dataclass(frozen=True)
class Settings:
    # instance variables like pydantic fields and not class variables

    # Secrets. The gateway refuses to start without them.
    gateway_token: str    # bearer token callers (LangGraph, Airflow) must present to the gateway
    worker_token: str     # bearer token the gateway presents to the workers
    approval_secret: bytes  # HMAC key for the human-approval tokens of the sandbox tools

    # default values for dataclass fields are provided using default_factory for mutable types like dicts else dataclass would throw an error.
    # default values tells an instance variable to be created at time of object creation.
    worker_urls: Mapping[str, str] = field(default_factory=lambda: {
        "trivy": "http://trivy-worker:8001",
        "analysis": "http://analysis-worker:8002",
        "slim": "http://slim-worker:8003",
        "bench": "http://bench-worker:8004",
    })
    # Per-tool concurrency limit (rate limiting). Slim and Bench run privileged/with the Docker socket: one at a time.
    concurrency: Mapping[str, int] = field(default_factory=lambda: {"trivy": 4, "analysis": 8, "slim": 1, "bench": 1})
    # Per-tool wall-clock limit for one worker call, in seconds
    timeouts: Mapping[str, float] = field(default_factory=lambda: {
        "trivy": 600.0, "analysis": 300.0, "slim": 1800.0, "bench": 600.0,
    })

    # Immutable types like below doesnt require default_factory, so they can be assigned directly.
    queue_timeout: float = 30.0                 # how long a call waits for a free slot before "busy"
    max_response_bytes: int = 20 * 1024 * 1024  # cap on what one worker may return
    max_request_bytes: int = 64 * 1024          # input size cap for MCP requests
    approval_ttl_seconds: int = 600             # a human approval expires after this (timeout counts as denied)

    host: str = "0.0.0.0"
    port: int = 8000
    # Host header values accepted by the MCP endpoint, "host:*" allows any port
    allowed_hosts: tuple = ("gateway:*", "localhost:*", "127.0.0.1:*")

    audit_log_path: Optional[Path] = None   # None -> audit lines go to stdout

    # can be called before object creation to read settings from environment variables, with validation and defaults.
    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env

        secrets = {n: env.get(n, "") for n in ("GATEWAY_TOKEN", "WORKER_TOKEN", "APPROVAL_SECRET")}
        missing = [n for n, v in secrets.items() if len(v) < 16]
        if missing:
            raise ConfigError(f"{', '.join(missing)} must be set to a random value of at least 16 characters")

        defaults = cls(gateway_token="x", worker_token="x", approval_secret=b"x")
        urls = dict(defaults.worker_urls)
        concurrency = dict(defaults.concurrency)
        timeouts = dict(defaults.timeouts)
        for tool in TOOLS:
            up = tool.upper()
            urls[tool] = env.get(f"{up}_WORKER_URL", urls[tool]).rstrip("/")
            concurrency[tool] = _positive_int(env, f"{up}_CONCURRENCY", concurrency[tool])
            timeouts[tool] = float(_positive_int(env, f"{up}_TIMEOUT_SECONDS", int(timeouts[tool])))

        hosts = env.get("ALLOWED_HOSTS")
        return cls(
            gateway_token=secrets["GATEWAY_TOKEN"],
            worker_token=secrets["WORKER_TOKEN"],
            approval_secret=secrets["APPROVAL_SECRET"].encode(),
            worker_urls=urls,
            concurrency=concurrency,
            timeouts=timeouts,
            queue_timeout=float(_positive_int(env, "QUEUE_TIMEOUT_SECONDS", int(defaults.queue_timeout))),
            max_response_bytes=_positive_int(env, "MAX_RESPONSE_BYTES", defaults.max_response_bytes),
            max_request_bytes=_positive_int(env, "MAX_REQUEST_BYTES", defaults.max_request_bytes),
            approval_ttl_seconds=_positive_int(env, "APPROVAL_TTL_SECONDS", defaults.approval_ttl_seconds),
            host=env.get("GATEWAY_HOST", defaults.host),
            port=_positive_int(env, "GATEWAY_PORT", defaults.port),
            allowed_hosts=tuple(h.strip() for h in hosts.split(",") if h.strip()) if hosts else defaults.allowed_hosts,
            audit_log_path=Path(env["AUDIT_LOG_PATH"]) if env.get("AUDIT_LOG_PATH") else None,
        )


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value <= 0:
        raise ConfigError(f"{name} must be positive, got {value}")
    return value
