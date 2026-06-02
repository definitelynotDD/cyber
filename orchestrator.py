"""Supervisor orchestration as a LangGraph StateGraph.

The supervisor is an LLM that decides which specialist runs next, but every
decision is constrained by:
  * a whitelist (a hallucinated agent name can't crash the graph), and
  * a circuit breaker (step_count) so the loop can never run away.

Pipeline intent: recon -> vision + analysis -> report -> FINISH.
"""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph

import agents
import config
import tools
from memory import MemoryStore

SCREENSHOT_DIR = "runs/screenshots"


class MapperState(TypedDict):
    target: str
    completed: Annotated[list, operator.add]
    logs: Annotated[list, operator.add]
    next: str
    step_count: int


# One memory store per run; set by run_scan().
_MEMORY: MemoryStore | None = None


def _log(agent: str, message: str) -> dict:
    return {"agent": agent, "message": message}


# --- supervisor ------------------------------------------------------------
_supervisor_llm = config.build_llm(config.LLM_MODEL, temperature=0)

_SUPERVISOR_SYS = (
    "You are the supervisor of an attack-surface-mapping team. Decide which "
    "specialist should act next, or whether the assessment is done.\n"
    "Specialists: recon (subdomains + ports), vision (screenshot + UI "
    "analysis), analysis (signature-based vuln detection), report (final "
    "write-up).\n"
    "Sensible order: recon first; then vision and analysis; report last.\n"
    "Reply with EXACTLY ONE word: the name of the next specialist, or FINISH "
    "if report is already done."
)


def supervisor_node(state: MapperState) -> dict:
    step = state.get("step_count", 0) + 1
    completed = state.get("completed", [])

    # circuit breaker
    if step > config.MAX_SUPERVISOR_STEPS:
        return {"next": "FINISH", "step_count": step,
                "logs": [_log("supervisor", "Step limit reached — finishing.")]}

    remaining = [w for w in config.WORKERS if w not in completed]
    if not remaining:
        return {"next": "FINISH", "step_count": step,
                "logs": [_log("supervisor", "All specialists done — finishing.")]}

    mem_summary = _MEMORY.summary() if _MEMORY else ""
    prompt = (
        f"Target: {state['target']}\n"
        f"Completed: {completed or 'none'}\n"
        f"Remaining: {remaining}\n"
        f"Current knowledge: {mem_summary}\n"
        "Who acts next?"
    )
    raw = config.llm_retry(_supervisor_llm.invoke)(
        [{"role": "system", "content": _SUPERVISOR_SYS},
         {"role": "user", "content": prompt}]
    ).content
    choice = (raw if isinstance(raw, str) else str(raw)).strip().lower().split()[0]
    choice = choice.strip(".,!")

    # whitelist validation + deterministic fallback
    if choice == "finish" and "report" in completed:
        nxt = "FINISH"
    elif choice in remaining:
        nxt = choice
    else:
        nxt = "report" if completed and "report" in remaining and set(
            config.WORKERS) - {"report"} <= set(completed) else remaining[0]

    return {"next": nxt, "step_count": step,
            "logs": [_log("supervisor", f"Delegating to: {nxt}")]}


def route(state: MapperState) -> str:
    nxt = state.get("next", "FINISH")
    return END if nxt == "FINISH" else nxt


# --- worker nodes ----------------------------------------------------------
def recon_node(state: MapperState) -> dict:
    tools.set_active_memory(_MEMORY)
    summary = agents.run_recon(state["target"])
    return {"completed": ["recon"],
            "logs": [_log("recon", summary)]}


def vision_node(state: MapperState) -> dict:
    tools.set_active_memory(_MEMORY)
    findings = agents.run_vision(state["target"], SCREENSHOT_DIR)
    return {"completed": ["vision"],
            "logs": [_log("vision", findings)]}


def analysis_node(state: MapperState) -> dict:
    tools.set_active_memory(_MEMORY)
    summary = agents.run_analysis(state["target"])
    return {"completed": ["analysis"],
            "logs": [_log("analysis", summary)]}


def report_node(state: MapperState) -> dict:
    import report
    tools.set_active_memory(_MEMORY)
    md = report.generate(_MEMORY)
    return {"completed": ["report"],
            "logs": [_log("report", "Final report generated.")]}


def build_graph():
    g = StateGraph(MapperState)
    g.add_node("supervisor", supervisor_node)
    g.add_node("recon", recon_node)
    g.add_node("vision", vision_node)
    g.add_node("analysis", analysis_node)
    g.add_node("report", report_node)

    g.add_edge(START, "supervisor")
    g.add_conditional_edges("supervisor", route,
                            {"recon": "recon", "vision": "vision",
                             "analysis": "analysis", "report": "report",
                             END: END})
    for w in ("recon", "vision", "analysis", "report"):
        g.add_edge(w, "supervisor")  # always return control to supervisor
    return g.compile()


def run_scan(target: str):
    """Generator yielding (state_update) dicts as the graph streams.

    Yields the per-node update dicts so a UI can render live progress.
    Returns the MemoryStore via the final 'memory' sentinel.
    """
    global _MEMORY
    _MEMORY = MemoryStore(target)
    tools.set_active_memory(_MEMORY)
    graph = build_graph()

    init: MapperState = {"target": target, "completed": [], "logs": [],
                         "next": "", "step_count": 0}
    for update in graph.stream(init, stream_mode="updates",
                               config={"recursion_limit": 50}):
        yield update
    yield {"__memory__": _MEMORY}
