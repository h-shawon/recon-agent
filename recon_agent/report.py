"""Turn the agent's run into a markdown report."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, ToolMessage


def build_report(targets: list[str], messages: list) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        "# Reconnaissance Report",
        "",
        f"**Generated:** {ts}",
        f"**Targets (authorised scope):** {', '.join(targets)}",
        "",
        "> For authorised security testing only.",
        "",
        "## Summary",
        "",
    ]

    # The final AI message (no tool calls) is the model's written summary.
    summary = ""
    for m in reversed(messages):
        if isinstance(m, AIMessage) and not getattr(m, "tool_calls", None):
            summary = m.content if isinstance(m.content, str) else str(m.content)
            break
    lines.append(summary.strip() or "_No summary produced._")
    lines += ["", "## Raw tool output", ""]

    # Pair each tool call with its result for an auditable appendix.
    pending: dict[str, str] = {}
    for m in messages:
        if isinstance(m, AIMessage):
            for call in getattr(m, "tool_calls", []) or []:
                pending[call["id"]] = f"{call['name']}({json.dumps(call['args'])})"
        elif isinstance(m, ToolMessage):
            label = pending.get(m.tool_call_id, m.name or "tool")
            lines += [f"### {label}", "", "```json", _pretty(m.content), "```", ""]

    return "\n".join(lines)


def _pretty(content: str) -> str:
    try:
        return json.dumps(json.loads(content), indent=2)
    except (json.JSONDecodeError, TypeError):
        return str(content)
