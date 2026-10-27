"""End-to-end test of the agent loop using a scripted fake model (no API, no key).

Proves the multi-step flow: model -> tool call -> tool result -> model -> summary,
and that the report is assembled from the run.
"""
from langchain_core.messages import AIMessage

from recon_agent.graph import run_recon
from recon_agent.report import build_report
from recon_agent.scope import Scope, ScopeGuard


class _ScriptedModel:
    """Emits a port_scan tool call first, then a final summary."""

    def __init__(self):
        self.calls = 0

    def bind_tools(self, tools):
        return self

    def invoke(self, messages):
        self.calls += 1
        if self.calls == 1:
            return AIMessage(
                content="",
                tool_calls=[
                    {"name": "port_scan", "args": {"host": "127.0.0.1"},
                     "id": "call_1", "type": "tool_call"}
                ],
            )
        return AIMessage(content="Recon complete. Scanned 127.0.0.1; see raw output.")


def test_agent_runs_tool_then_summarises():
    guard = ScopeGuard(Scope(cidrs=["127.0.0.0/8"]))
    messages = run_recon(guard, ["127.0.0.1"], llm=_ScriptedModel())

    # A tool was actually executed (ToolMessage present) and a summary followed.
    kinds = [m.__class__.__name__ for m in messages]
    assert "ToolMessage" in kinds
    assert messages[-1].content.startswith("Recon complete")

    report = build_report(["127.0.0.1"], messages)
    assert "# Reconnaissance Report" in report
    assert "Recon complete" in report
    assert "port_scan" in report
