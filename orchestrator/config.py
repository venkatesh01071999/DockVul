"""Orchestrator settings, read from environment variables."""
import os
from dataclasses import dataclass
from typing import Mapping, Optional


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    gateway_token: str      # bearer token for the MCP gateway
    approval_secret: bytes  # signs the approval tokens the gateway checks for the sandbox tools
    gateway_url: str = "http://gateway:8000/mcp"
    approval_ttl: int = 600  # seconds an approval stays valid after a person gave it
    call_timeout: float = 1800.0  # longest wait for one gateway call (Slim can run for a long time)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        missing = [n for n in ("GATEWAY_TOKEN", "APPROVAL_SECRET") if len(env.get(n, "")) < 16]
        if missing:
            raise ConfigError(f"{', '.join(missing)} must be set to a random value of at least 16 characters")
        return cls(
            gateway_token=env["GATEWAY_TOKEN"],
            approval_secret=env["APPROVAL_SECRET"].encode(),
            gateway_url=env.get("GATEWAY_URL", cls.gateway_url),
        )
