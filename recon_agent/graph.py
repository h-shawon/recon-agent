"""The LangGraph recon agent.

A classic ReAct-style loop built explicitly with LangGraph:

    agent ──(tool calls?)──> tools ──> agent ──> ... ──> END

The model is bound to the recon tools and keeps calling them until it has
enough to stop, at which point it writes the final summary. Scope enforcement
lives in the tools themselves, so the model physically cannot act out of scope
even if it tries.
"""
from __future__ import annotations

from typing import Annotated, TypedDict

from langchain_core.messages import AnyMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from .llm import build_llm
from .scope import ScopeGuard
from .tools import ALL_TOOLS, set_guard

SYSTEM_PROMPT = """You are a reconnaissance assistant for AUTHORISED security \
testing only. You are given one or more targets that the operator has confirmed \
are in scope.

Your job:
1. Resolve hosts and enumerate subdomains of the target domain(s).
2. Port-scan the hosts that resolve.
3. HTTP-probe any web services you find.
4. Stop once you have a clear picture of the attack surface.

Rules:
- Only act on targets in scope. The tools enforce this; if a tool reports a \
scope error, do not retry that target.
- Be efficient. Do not repeat a tool call with the same input.
- When you are done gathering, reply with a final summary (no more tool calls). \
Describe hosts found, open ports, and notable web services. Do NOT invent \
findings; report only what the tools returned."""


class ReconState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]


def _should_continue(state: ReconState) -> str:
    last = state["messages"][-1]
    if getattr(last, "tool_calls", None):
        return "tools"
    return END


def build_agent(guard: ScopeGuard, llm=None):
    """Compile and return the recon agent graph."""
    set_guard(guard)
    llm = llm or build_llm()
    model = llm.bind_tools(ALL_TOOLS)

    def agent_node(state: ReconState) -> ReconState:
        return {"messages": [model.invoke(state["messages"])]}

    graph = StateGraph(ReconState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", ToolNode(ALL_TOOLS))
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", _should_continue, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")
    return graph.compile()


def run_recon(guard: ScopeGuard, targets: list[str], llm=None, recursion_limit: int = 40):
    """Run the agent over the given targets and return the full message list."""
    agent = build_agent(guard, llm=llm)
    task = (
        "Targets in scope: "
        + ", ".join(targets)
        + "\n\nBegin reconnaissance and produce a summary."
    )
    initial = {"messages": [SystemMessage(SYSTEM_PROMPT), HumanMessage(task)]}
    result = agent.invoke(initial, config={"recursion_limit": recursion_limit})
    return result["messages"]
