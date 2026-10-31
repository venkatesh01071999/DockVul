"""
Ranking of the Trivy findings.

The deterministic ranking (severity x usage x exposure) is always computed and is the fallback.
An LLM may reorder and explain it, but it is untrusted: its answer must match a schema, may only name
findings that exist, and must not contain secrets. If it fails that check twice, or is unavailable,
the deterministic ranking stands.
"""
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError

from gateway.masking import mask  # the same masking rules, used here as the secret rescan (rescan)
from orchestrator.contract import Finding

SEVERITY_WEIGHT = {"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0, "UNKNOWN": 0.5}
# Missing evidence ("undetermined") and unknown exposure never push a finding down as far as a
# confirmed "not_reachable" or "internal" does.
USAGE_WEIGHT = {"used": 1.0, "undetermined": 0.8, "not_reachable": 0.3}
# Public - exposed to internet
# Host local - exposed to host machine network (e.g. localhost)
# Internal - exposed to the internal network of the container, but not to the host or internet
EXPOSURE_WEIGHT = {"public": 1.0, "host_local": 0.8, "unknown": 0.8, "internal": 0.6}
USAGE_TEXT = {"used": "confirmed in use", "undetermined": "usage could not be determined",
              "not_reachable": "not reachable from the application"}

# Protect the LLM from being asked to rank too many findings, which would exceed the token budget
MAX_LLM_FINDINGS = 50  # only the top of the ranking goes to the LLM (token budget)

LLM = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]  # takes the bundle, returns {"rankings": [...]}


def rank_deterministic(findings: List[Finding], usage: Dict[str, str], exposure: str) -> List[Dict[str, Any]]:
    ranked = []
    for f in findings:
        u = usage.get(f.key, "undetermined")
        score = SEVERITY_WEIGHT[f.severity] * USAGE_WEIGHT[u] * EXPOSURE_WEIGHT[exposure]
        ranked.append({
            "key": f.key, "id": f.id, "pkg": f.pkg, "severity": f.severity,
            "installed_version": f.installed_version, "fixed_version": f.fixed_version,
            "usage": u, "exposure": exposure, "score": round(score, 2),
            "reason": f"{f.severity} severity; package {USAGE_TEXT[u]}; exposure {exposure}",
        })
    return sorted(ranked, key=lambda r: (-r["score"], r["key"]))


class LLMItem(BaseModel):
    key: str
    reason: str = Field(max_length=400)


class LLMRanking(BaseModel):
    rankings: List[LLMItem] = Field(max_length=MAX_LLM_FINDINGS)


def llm_bundle(ranked: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What the LLM sees: finding facts only, no raw tool output."""
    fields = ("key", "id", "pkg", "severity", "usage", "exposure", "fixed_version")
    return {"findings": [{k: r[k] for k in fields} for r in ranked[:MAX_LLM_FINDINGS]]}


def validate_llm_output(raw: Any, allowed_keys: set) -> LLMRanking:
    """Schema check, every finding must exist (no invented CVEs), no duplicates, no secrets."""
    parsed = LLMRanking.model_validate(raw)
    keys = [item.key for item in parsed.rankings]
    if len(set(keys)) != len(keys) or not set(keys) <= allowed_keys:
        raise ValueError("LLM ranking names an unknown or duplicate finding")
    if mask([item.reason for item in parsed.rankings])[1]:
        raise ValueError("LLM ranking contains a secret")
    return parsed


def apply_llm_ranking(ranked: List[Dict[str, Any]], parsed: LLMRanking) -> List[Dict[str, Any]]:
    by_key = {r["key"]: r for r in ranked}
    first = [{**by_key[i.key], "reason": i.reason} for i in parsed.rankings]
    listed = {i.key for i in parsed.rankings}
    return first + [r for r in ranked if r["key"] not in listed]


async def rank_with_llm(ranked: List[Dict[str, Any]], llm: Optional[LLM]) -> Tuple[List[Dict[str, Any]], str]:
    """Returns (ranking, "llm" | "deterministic")."""
    if llm is None or not ranked:
        return ranked, "deterministic"
    bundle = llm_bundle(ranked)
    allowed = {f["key"] for f in bundle["findings"]}
    for _attempt in range(2):  # one retry after an invalid answer
        try:
            raw = await llm(bundle)
        except Exception:  # the LLM is unavailable: fall back, do not retry
            return ranked, "deterministic"
        try:
            return apply_llm_ranking(ranked, validate_llm_output(raw, allowed)), "llm"
        except (ValidationError, ValueError):
            continue
    return ranked, "deterministic"
