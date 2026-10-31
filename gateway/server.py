"""
MCP gateway: the single entry point for the LangGraph agent and Airflow.

Exposes four tools, each forwarding to a decoupled worker (see workers.py):

    trivy_scan              -> Trivy worker      CVEs, SBOM, image misconfiguration and secret checks
    analyze_config          -> analysis worker   dependency usage, exposure signals, config rules (deterministic)
    docker_bench_section4   -> Docker Bench      CIS section 4 (sandbox, needs human approval)
    slim_seccomp_profile    -> Slim worker       seccomp profile capture (sandbox, privileged, needs approval)

On every call the gateway: validates the arguments (the same models as the CLI, via common.schemas),
checks the approval token for the sandbox tools, enforces the per-tool concurrency limit, forwards to
the worker, masks secrets in the answer and writes an audit line.

Run:  python -m gateway.server      (settings come from environment variables, see config.py)
"""
import sys
import time
from typing import Annotated, Any, Dict, Optional
import uvicorn

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from common.schemas import Digest, Image, RunId, ScanRequest
from gateway.approval import ApprovalError, ApprovalVerifier
from gateway.audit import AuditLog
from gateway.auth import AuthMiddleware
from gateway.config import ConfigError, Settings
from gateway.masking import mask
from gateway.workers import WorkerError, WorkerPool

ApprovalToken = Annotated[str, Field(min_length=20, max_length=2048)]


class ToolResult(BaseModel):
    """What every tool returns to the gateway, which then masks secrets"""

    tool: str
    run_id: str
    redactions: int  # how many secrets were masked in `result`
    result: Dict[str, Any]  # the worker's answer, masked

INSTRUCTIONS = (
    "DockVul gateway. trivy_scan and analyze_config are read-only scans. docker_bench_section4 and "
    "slim_seccomp_profile run in the sandbox and need an approval token issued after a person approved."
)


def create_server(
    settings: Settings,
    *,
    pool: Optional[WorkerPool] = None,
    audit: Optional[AuditLog] = None,
    verifier: Optional[ApprovalVerifier] = None,
) -> FastMCP:
    pool = pool or WorkerPool(settings)
    audit = audit or AuditLog(settings.audit_log_path)
    verifier = verifier or ApprovalVerifier(settings.approval_secret)

    mcp = FastMCP(
        "dockvul-gateway",
        instructions=INSTRUCTIONS,
        stateless_http=True,  # no state is kept in the gateway, all state is in the workers and the audit log
        json_response=True,
        max_request_body_size=settings.max_request_bytes,
        # restricted to the allowed hosts
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=list(settings.allowed_hosts),
        ),
    )

    async def invoke(tool: str, path: str, payload: Dict[str, Any], run_id: str,
                     summary: Dict[str, Any]) -> ToolResult:
        started = time.monotonic()
        try:
            raw = await pool.call(tool, path, payload)
        except WorkerError as e:
            audit.record(tool=tool, run_id=run_id, status="error", error=str(e), args=summary,
                         detail=mask(e.detail)[0], ms=int((time.monotonic() - started) * 1000))
            raise ToolError(str(e)) from None  # the caller never sees worker internals
        # mask secrets in the result, so the agent can say "a secret is exposed here"
        masked, redactions = mask(raw)
        audit.record(tool=tool, run_id=run_id, status="ok", redactions=redactions, args=summary,
                     ms=int((time.monotonic() - started) * 1000))
        return ToolResult(tool=tool, run_id=run_id, redactions=redactions, result=masked)

    def require_approval(tool: str, run_id: str, image_digest: str, token: str) -> None:
        try:
            verifier.verify(token, tool=tool, image_digest=image_digest)
        except ApprovalError as e:
            audit.record(tool=tool, run_id=run_id, status="denied", reason=str(e),
                         args={"image_digest": image_digest})
            raise ToolError("sandbox approval missing, invalid, expired, already used or for another image") from None
        audit.record(tool=tool, run_id=run_id, status="approved", args={"image_digest": image_digest})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def trivy_scan(run_id: RunId, image: Image, skip_db_update: bool = True) -> ToolResult:
        """Scan a container image with Trivy: CVEs (OS and language packages), SBOM, image
        misconfigurations and secret findings. Secrets in the result are masked."""
        payload = {"image": image.model_dump(mode="json"), "skip_db_update": skip_db_update}
        return await invoke("trivy", "/scan", payload, run_id,
                            {"image": payload["image"], "skip_db_update": skip_db_update})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=True))
    async def analyze_config(run_id: RunId, request: ScanRequest) -> ToolResult:
        """Deterministic analysis of the image and its source: dependency usage, exposure signals
        and Docker/compose configuration rules. Missing inputs are reported as 'not assessed'."""
        payload = request.model_dump(mode="json", exclude_none=True)
        return await invoke("analysis", "/analyze", payload, run_id, payload)

    # sandbox tools that need human approval for the image digest, because they run privileged thats why they are not read-only and not open-world
    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=False))
    async def docker_bench_section4(run_id: RunId, image_digest: Digest, approval_token: ApprovalToken
                                    ) -> ToolResult:
        """CIS Docker Benchmark section 4 (container image and build file checks). Runs in the
        sandbox and needs an approval token for this image digest."""
        require_approval("bench", run_id, image_digest, approval_token)
        return await invoke("bench", "/section4", {"image_digest": image_digest}, run_id,
                            {"image_digest": image_digest})

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, openWorldHint=False))
    async def slim_seccomp_profile(run_id: RunId, image_digest: Digest, approval_token: ApprovalToken
                                   ) -> ToolResult:
        """Capture the syscalls a running container uses and recommend a seccomp profile. Runs the
        image privileged in the sandbox and needs an approval token for this image digest. The result
        states how much of the app was exercised, because syscalls not observed are only candidates."""
        require_approval("slim", run_id, image_digest, approval_token)
        return await invoke("slim", "/profile", {"image_digest": image_digest}, run_id,
                            {"image_digest": image_digest})

    # custom route for the health check, so it can be exempt from the Bearer token check
    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    return mcp


def build_app(settings: Settings, **kwargs: Any) -> AuthMiddleware: # pragma: no cover
    mcp = create_server(settings, **kwargs)
    return AuthMiddleware(mcp.streamable_http_app(), settings.gateway_token, exempt_paths={"/health"})


def main() -> None:  # pragma: no cover
    try:
        settings = Settings.from_env()
    except ConfigError as e:
        sys.exit(f"gateway configuration error: {e}")
    # ASGI server (ASGI interface that handles requests and response to MCP)
    uvicorn.run(build_app(settings), host=settings.host, port=settings.port)


if __name__ == "__main__":  # pragma: no cover
    main()
