"""Command-line entry point for the recon agent.

Usage:
    python -m recon_agent.cli --scope scope.yaml --target example.com
    python -m recon_agent.cli --scope scope.yaml --target example.com --target 10.10.10.5 -o report.md
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

from .graph import run_recon
from .report import build_report
from .scope import Scope, ScopeError, ScopeGuard


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Scope-guarded recon agent (LangGraph + DeepSeek).")
    p.add_argument("--scope", required=True, help="Path to scope.yaml listing authorised targets.")
    p.add_argument("--target", action="append", required=True, help="A target in scope (repeatable).")
    p.add_argument("-o", "--output", default="recon_report.md", help="Where to write the markdown report.")
    args = p.parse_args(argv)

    guard = ScopeGuard(Scope.from_file(args.scope))

    # Fail fast if any target the user named is not actually in scope.
    try:
        for t in args.target:
            guard.require(t)
    except ScopeError as e:
        print(f"[scope] {e}", file=sys.stderr)
        return 2

    print(f"[*] Running recon on: {', '.join(args.target)}", file=sys.stderr)
    messages = run_recon(guard, args.target)
    report = build_report(args.target, messages)
    Path(args.output).write_text(report)
    print(f"[+] Report written to {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
