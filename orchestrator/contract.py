"""
The worker results the orchestrator relies on. This is the contract the workers must follow.

Everything the gateway returns is parsed into these models before it is used. Anything that does
not fit is treated as a failed tool, so malformed worker output never reaches the report
or the LLM.

Trivy worker    -> TrivyResult     {"image": {"digest", "entrypoint"}, "findings": [...]}
Analysis worker -> AnalysisResult  {"usage": {"<id>:<pkg>": "used|not_reachable|undetermined"},
                                    "exposure": "...", "config_findings": [...], "not_assessed": [...]}
Bench / Slim    -> OpenResult      passed through to the report unchanged
"""
from typing import Annotated, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from common.schemas import Digest

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
Usage = Literal["used", "not_reachable", "undetermined"]
Exposure = Literal["public", "host_local", "internal", "unknown"]

MAX_ITEMS = 5000  # size cap on any list a worker returns


class Result(BaseModel):
    model_config = ConfigDict(extra="ignore")


class ImageInfo(Result):
    digest: Digest
    entrypoint: List[Annotated[str, Field(max_length=500)]] = Field(default_factory=list, max_length=50)


class Finding(Result):
    id: str = Field(max_length=100)  # e.g. CVE-2024-1234
    pkg: str = Field(max_length=200)
    severity: Severity = "UNKNOWN"
    installed_version: Optional[str] = Field(default=None, max_length=100)
    fixed_version: Optional[str] = Field(default=None, max_length=100)

    @property
    def key(self) -> str:
        """The same CVE can hit several packages, so a finding is identified by id and package."""
        return f"{self.id}:{self.pkg}"



class TrivyResult(Result):
    image: ImageInfo
    findings: List[Finding] = Field(default_factory=list, max_length=MAX_ITEMS)



class ConfigFinding(Result):
    id: str = Field(max_length=100)
    severity: Severity = "UNKNOWN"
    title: str = Field(default="", max_length=300)


class AnalysisResult(Result):
    # usage and exposure are required on purpose: an empty or garbled answer must be a failure,
    # not silently read as "nothing found, exposure unknown"
    usage: Dict[str, Usage]
    exposure: Exposure
    config_findings: List[ConfigFinding] = Field(default_factory=list, max_length=MAX_ITEMS)
    not_assessed: List[Annotated[str, Field(max_length=300)]] = Field(default_factory=list, max_length=100)


class OpenResult(BaseModel):
    model_config = ConfigDict(extra="allow")
