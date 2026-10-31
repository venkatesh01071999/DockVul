"""
The scan as a LangGraph graph.

    START -> run_trivy ---+                         +-> run_bench --+
                          +-> approve (human) ------+               +-> rank -> build_report -> END
          -> run_analysis +                         +-> run_slim ---+

- Every node calls the MCP gateway itself: the LLM has no tools and only ever sees finding facts in `rank`.
- A failed tool does not stop the scan; it is recorded and the report is labelled partial.
- The graph pauses before `approve` (interrupt_before). `run_scan` then asks a person and resumes the
  graph with the answer. A denial, an error or no answer means the sandbox nodes do nothing, and approval
  tokens are minted only after a yes. (LangGraph's interrupt() cannot be used in async nodes on
  Python 3.10, so the pause is done around the graph instead of inside a node.)
- State is checkpointed (in memory for local runs; pass a Postgres saver for monitoring mode).
"""
import operator
import uuid
from typing import Annotated, Any, Awaitable, Callable, Dict, List, Optional, Tuple, Type, TypedDict

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command
from pydantic import BaseModel, ValidationError

from common.schemas import ScanRequest
from gateway.approval import issue_approval
from orchestrator.config import Settings
from orchestrator.contract import AnalysisResult, OpenResult, TrivyResult
from orchestrator.gateway_client import GatewayError
from orchestrator.ranking import LLM, rank_deterministic, rank_with_llm
from orchestrator.report import build_report

Approve = Callable[[Dict[str, Any]], Awaitable[bool]]

SANDBOX_WARNING = ("Slim runs the image PRIVILEGED in the sandbox and Docker Bench uses the Docker socket "
                   "(through a proxy). Only approve for an image you are willing to run.")


def approval_info(trivy: Dict[str, Any]) -> Dict[str, Any]:
    """What the person is shown before approving: the digest, the entrypoint and the privileged-mode warning."""
    return {"image_digest": trivy["image"]["digest"], "warning": SANDBOX_WARNING}


class State(TypedDict, total=False):
    run_id: str
    request: Dict[str, Any]      # the ScanRequest as JSON
    trivy: Dict[str, Any]
    analysis: Dict[str, Any]
    human_answer: bool           # the person's answer, supplied by run_scan when it resumes the graph
    approved: bool
    bench: Dict[str, Any]
    slim: Dict[str, Any]
    failures: Annotated[List[str], operator.add]  # parallel nodes append to it
    findings: List[Dict[str, Any]]
    ranking: str
    report: Dict[str, Any]


def build_graph(gateway, settings: Settings, llm: Optional[LLM] = None, checkpointer=None):
    """`gateway` is anything with `async call(tool, args) -> dict` (GatewayClient, or a fake in tests)."""

    async def call(label: str, tool: str, args: Dict[str, Any],
                   model: Type[BaseModel]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Call one gateway tool and parse the answer. Returns (result, None) or (None, failure message)."""
        try:
            raw = await gateway.call(tool, args)
            return model.model_validate(raw["result"]).model_dump(), None
        except GatewayError as e:
            return None, f"{label}: {e}"
        except (ValidationError, KeyError, TypeError):
            return None, f"{label}: invalid response from the gateway"

    def outcome(key: str, result: Optional[Dict[str, Any]], failure: Optional[str]) -> Dict[str, Any]:
        return {key: result} if result is not None else {"failures": [failure]}

    async def run_trivy(state: State) -> Dict[str, Any]:
        request = ScanRequest.model_validate(state["request"])
        args = {"run_id": state["run_id"], "image": request.image.model_dump(mode="json")}
        return outcome("trivy", *await call("trivy", "trivy_scan", args, TrivyResult))

    async def run_analysis(state: State) -> Dict[str, Any]:
        args = {"run_id": state["run_id"], "request": state["request"]}
        return outcome("analysis", *await call("analysis", "analyze_config", args, AnalysisResult))

    def approve(state: State) -> Dict[str, Any]:
        # runs after the pause; only an explicit yes, and only if there is a digest to approve
        return {"approved": bool(state.get("trivy")) and state.get("human_answer") is True}

    async def sandbox(state: State, key: str, tool: str) -> Dict[str, Any]:
        if not state.get("approved"):
            return {}
        digest = state["trivy"]["image"]["digest"]
        token = issue_approval(settings.approval_secret, tool=key, image_digest=digest,
                               ttl_seconds=settings.approval_ttl)
        args = {"run_id": state["run_id"], "image_digest": digest, "approval_token": token}
        return outcome(key, *await call(key, tool, args, OpenResult))

    async def run_bench(state: State) -> Dict[str, Any]:
        return await sandbox(state, "bench", "docker_bench_section4")

    async def run_slim(state: State) -> Dict[str, Any]:
        return await sandbox(state, "slim", "slim_seccomp_profile")

    async def rank(state: State) -> Dict[str, Any]:
        trivy = TrivyResult.model_validate(state["trivy"]) if state.get("trivy") else None
        analysis = AnalysisResult.model_validate(state["analysis"]).model_dump(mode="json") if state.get("analysis") else {}
        ranked = rank_deterministic(trivy.findings if trivy else [], analysis.get("usage", {}),
                                    analysis.get("exposure", "unknown"))
        ranked, how = await rank_with_llm(ranked, llm)
        return {"findings": ranked, "ranking": how}

    def make_report(state: State) -> Dict[str, Any]:
        return {"report": build_report(state)}

    g = StateGraph(State)
    g.add_node("run_trivy", run_trivy)
    g.add_node("run_analysis", run_analysis)
    g.add_node("approve", approve)
    g.add_node("run_bench", run_bench)
    g.add_node("run_slim", run_slim)
    g.add_node("rank", rank)
    g.add_node("build_report", make_report)

    g.add_edge(START, "run_trivy")
    g.add_edge(START, "run_analysis")
    g.add_edge(["run_trivy", "run_analysis"], "approve")  # wait for both scans
    g.add_edge("approve", "run_bench")
    g.add_edge("approve", "run_slim")
    g.add_edge(["run_bench", "run_slim"], "rank")
    g.add_edge("rank", "build_report")
    g.add_edge("build_report", END)
    return g.compile(checkpointer=checkpointer or MemorySaver(), interrupt_before=["approve"])


async def run_scan(request: ScanRequest, gateway, settings: Settings, approve: Optional[Approve] = None,
                   llm: Optional[LLM] = None, checkpointer=None) -> Dict[str, Any]:
    """
    Run one scan and return the report. `approve(info)` is asked whether the sandbox checks may run;
    without it the answer is always no.
    """
    run_id = f"run-{uuid.uuid4().hex[:16]}"
    graph = build_graph(gateway, settings, llm, checkpointer)
    config = {"configurable": {"thread_id": run_id}}

    # runs both scans, then pauses before `approve`
    # configurable state is used to resume the graph after the pause, so the run_id and request are preserved
    await graph.ainvoke({"run_id": run_id, "request": request.model_dump(mode="json", exclude_none=True)}, config)

    # ask the person and resume the graph with the answer
    values = (await graph.aget_state(config)).values
    approved = False
    if values.get("trivy") and approve is not None:  # without Trivy there is no digest to approve
        try:
            approved = await approve(approval_info(values["trivy"])) is True  # only an explicit True counts
        except Exception:  # a failing prompt must never count as a yes
            approved = False
    result = await graph.ainvoke(Command(update={"human_answer": approved}), config)
    return result["report"]
