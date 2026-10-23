"""
Single source of truth for the scan inputs (the CLI arguments).

The same models are used at every hop: CLI -> LangGraph -> MCP gateway -> worker.
Each hop re-validates (nothing trusts its caller), but all of them validate against
this one definition, so the rules cannot drift apart.

- a tarball is a bare file name,
- a local source is just a marker (the directory is mounted at a fixed path),
- a GitHub source is "owner/repo" (never a free-form URL, so no SSRF),
- in-source paths are relative and cannot contain "..". (no path traversal)
Workers run external CLIs, so values that become CLI arguments cannot start with "-"
(no option injection).
"""
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

GITHUB_RE = re.compile(
    r"^(?:https://github\.com/|git@github\.com:)"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
NAME_PART_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
REGISTRY_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,254}$")
TARBALL_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]*\.(?:tar|tar\.gz|tgz)$")
COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
# no ':' , no '\', no leading '/' or '-' or '.', no '..' path segments (so no path traversal)
RELPATH_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_. \-/]*$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")


class Strict(BaseModel):
    # unknown fields are rejected, so a caller cannot pass extra arguments to a worker
    model_config = ConfigDict(extra="forbid", frozen=True)


class RegistryImage(Strict):
    # kind holds exactly registry as the value through type annotation
    kind: Literal["registry"] = "registry"
    ref: str

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        if not REGISTRY_REF_RE.match(v):
            raise ValueError("invalid registry image reference")
        return v


class TarballImage(Strict):
    kind: Literal["tarball"] = "tarball"
    name: str  # file name only; the worker resolves it inside its own mount

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not TARBALL_RE.match(v):
            raise ValueError("tarball must be a file name ending in .tar, .tar.gz or .tgz")
        return v


class GithubSource(Strict):
    kind: Literal["github"] = "github"
    repo: str  # "owner/repo"
    commit: Optional[str] = None  # None -> worker derives it from the OCI revision label

    @field_validator("repo")
    @classmethod
    def _repo(cls, v: str) -> str:
        parts = v.split("/")
        if len(parts) != 2 or not all(NAME_PART_RE.match(p) and p not in (".", "..") for p in parts):
            raise ValueError("repo must be 'owner/repo'")
        return v

    @field_validator("commit")
    @classmethod
    def _commit(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.lower()
        if not COMMIT_RE.match(v):
            raise ValueError("commit must be a 7-40 character hex SHA")
        return v


class LocalSource(Strict):
    kind: Literal["local"] = "local"  # directory is mounted read-only at a fixed path

# The union types are discriminated by the "kind" field, so the worker can parse them without knowing the full schema.
Image = Annotated[Union[RegistryImage, TarballImage], Field(discriminator="kind")]
Source = Annotated[Union[GithubSource, LocalSource], Field(discriminator="kind")]


def parse_github_url(url: str) -> tuple[str, str]:
    """'https://github.com/o/r(.git)' or 'git@github.com:o/r(.git)' returns ('o', 'r')."""
    m = GITHUB_RE.match(url)
    if not m:
        raise ValueError("not a GitHub URL")
    return m["owner"], m["repo"]


def safe_relpath(v: str) -> str:
    """A path inside the source tree: relative, forward slashes, no '..'.
    Returns a normalized forward-slash path (PurePosixPath) for the worker to use.
    """
    v = v.replace("\\", "/")
    while v.startswith("./"):
        v = v[2:]
    if len(v) > 255 or not RELPATH_RE.match(v) or ".." in PurePosixPath(v).parts:
        raise ValueError("must be a relative path inside the source (no '..', no absolute path)")
    return PurePosixPath(v).as_posix()


def validate_run_id(v: str) -> str:
    """run_id becomes an object-store key and a log field"""
    if not RUN_ID_RE.match(v):
        raise ValueError("run_id must be 8-64 chars of [A-Za-z0-9_-]")
    return v



class ScanRequest(Strict):
    """Everything the user can supply on the command line, validated and normalized."""

    image: Image
    source: Optional[Source] = None
    dockerfile: Optional[str] = None
    compose_file: Optional[str] = None
    compose_service: Optional[str] = None
    source_subdir: Optional[str] = None

    # runs before pydantic's own validation (class variable), so we can treat empty strings as None
    @field_validator("dockerfile", "compose_file", "compose_service", "source_subdir", mode="before")
    @classmethod
    def _empty_is_absent(cls, v):
        return None if v == "" else v

    @field_validator("dockerfile", "compose_file", "source_subdir")
    @classmethod
    def _paths(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else safe_relpath(v)

    @field_validator("compose_service")
    @classmethod
    def _service(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not SERVICE_RE.match(v):
            raise ValueError("invalid compose service name")
        return v

    # runs after pydantic's own validation, so we can check the consistency of multiple fields
    # model validator (mode = after) runs after object creation hence we use instance method instead of class method
    # whereas field validator and field validator (mode = before) run before object creation hence we use class method
    @model_validator(mode="after")
    def _consistent(self):
        if (self.dockerfile or self.compose_file or self.source_subdir) and self.source is None:
            raise ValueError("dockerfile, compose_file and source_subdir require a source")
        if self.compose_service and not self.compose_file:
            raise ValueError("compose_service requires compose_file")
        return self
