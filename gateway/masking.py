"""
Secret masking for everything that leaves the gateway towards the LLM orchestrator.

Each secret value is replaced by a typed placeholder (<REDACTED:aws_access_key>), so the agent can
still say "a secret is exposed here" without ever handling the value. Masking is deterministic
(keys, KEY=value assignments and well-known token formats), not an LLM judgement, and it is a
safety net on top of the workers, not a replacement for them.

mask() returns (masked_copy, number_of_redactions); the count feeds the guardrail metrics.
"""
import re
from typing import Any

# Names that mark a value as secret. "pass" only counts as a whole word (DB_PASS, not "bypass").
_SENSITIVE_NAME = re.compile(
    r"password|passwd|passphrase|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key"
    r"|authorization|(?<![A-Za-z])pass(?![A-Za-z])",
    re.IGNORECASE,
)

# KEY=value inside a longer string: Env entries, "ENV X=y" / "ARG X=y" in build history, --build-arg X=y
_ASSIGNMENT = re.compile(r"""(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>"[^"]*"|'[^']*'|\S+)""")

# Well-known secret formats: (type, pattern)
_VALUE_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("url_credentials", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),
)


def placeholder(kind: str) -> str:
    return f"<REDACTED:{kind}>"


class Masker:
    def __init__(self) -> None:
        self.count = 0

    def _hit(self, kind: str) -> str:
        self.count += 1
        return placeholder(kind)

    def assignment(self, m: "re.Match[str]") -> str:
        if not _SENSITIVE_NAME.search(m["key"]) or m["value"] in ("", '""', "''"):
            return m[0] # original match
        return f"{m['key']}={self._hit('env_secret')}"
    
    def string(self, text: str) -> str:
        text = _ASSIGNMENT.sub(self.assignment, text)
        for kind, pattern in _VALUE_PATTERNS:
            text = pattern.sub(lambda _m, k=kind: self._hit(k), text)
        return text

    def value(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.string(obj)
        if isinstance(obj, list):
            return [self.value(item) for item in obj]
        if isinstance(obj, dict):
            return self.mapping(obj)
        return obj  # numbers, booleans, None

    def mapping(self, obj: dict) -> dict:
        # A Trivy secret finding quotes the secret in Match and Code
        is_secret_finding = "RuleID" in obj and ("Match" in obj or "Code" in obj)
        out = {}
        for key, val in obj.items():
            if is_secret_finding and key in ("Match", "Code") and val:
                out[key] = self._hit("secret_finding")
            elif isinstance(val, str) and val and isinstance(key, str) and _SENSITIVE_NAME.search(key):
                out[key] = self._hit("secret")
            else:
                out[key] = self.value(val)
        return out


def mask(data: Any) -> tuple:
    """Return (copy of `data` with secrets replaced by typed placeholders, number of redactions)."""
    masker = Masker()
    masked = masker.value(data)
    return masked, masker.count
