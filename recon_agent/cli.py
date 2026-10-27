"""Command-line entry point for the recon agent.

Usage:
    python -m recon_agent.cli --scope scope.yaml --target example.com
    python -m recon_agent.cli --scope scope.yaml --target example.com --target 10.10.10.5 -o report.md
    python -m recon_agent.cli --scope scope.yaml --target 127.0.0.1 --offline
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from langchain_core.messages import AIMessage

from .graph import run_recon
from .report import build_report
from .scope import Scope, ScopeError, ScopeGuard


class _OfflineModel:
    """A deterministic, no-API stand-in for --offline runs.

    Walks a fixed recon plan over the given targets — resolve, port-scan and
    HTTP-probe each one — then writes a plain summary. The tools still run for
    real (so you get genuine output), but no DeepSeek key or API call is needed.
    """

    def __init__(self, targets: list[str]):
        self._targets = targets
        self._queue: list[tuple[str, dict, str]] = []
        for i, t in enumerate(targets):
            url = t if "://" in t else f"http://{t}"
            self._queue += [
                ("resolve_host", {"host": t}, f"off_{i}_resolve"),
                ("port_scan", {"host": t}, f"off_{i}_scan"),
                ("http_probe", {"url": url}, f"off_{i}_http"),
            ]

    def bind_tools(self, tools):  # the graph binds tools; nothing to do here
        return self

    def invoke(self, messages):
        if self._queue:
            name, args, cid = self._queue.pop(0)
            return AIMessage(
                content="",
                tool_calls=[{"name": name, "args": args, "id": cid, "type": "tool_call"}],
            )
        return AIMessage(
            content=(
                "Offline recon complete for " + ", ".join(self._targets) + ". "
                "Each target was resolved, port-scanned, and HTTP-probed; all "
                "results are in the raw tool output below. No LLM API was used."
            )
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scope-guarded recon agent (LangGraph + DeepSeek).")
    p.add_argument("--scope", required=True, help="Path to scope.yaml listing authorised targets.")
    p.add_argument("--target", action="append", required=True, help="A target in scope (repeatable).")
    p.add_argument("-o", "--output", default="recon_report.md", help="Where to write the markdown report.")
    p.add_argument(
        "--offline",
        action="store_true",
        help="Use a built-in scripted model instead of DeepSeek (no API key or call).",
    )
    args = p.parse_args(argv)

    guard = ScopeGuard(Scope.from_file(args.scope))

    # Fail fast if any target the user named is not actually in scope.
    try:
        for t in args.target:
            guard.require(t)
    except ScopeError as e:
        print(f"[scope] {e}", file=sys.stderr)
        return 2

    mode = "offline (scripted model)" if args.offline else "live (DeepSeek)"
    print(f"[*] Running recon on: {', '.join(args.target)}  [{mode}]", file=sys.stderr)
    llm = _OfflineModel(args.target) if args.offline else None
    messages = run_recon(guard, args.target, llm=llm)
    report = build_report(args.target, messages)
    Path(args.output).write_text(report)
    print(f"[+] Report written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
