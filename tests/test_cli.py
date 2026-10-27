"""CLI tests for --offline mode.

These drive the real command-line entry point with no DeepSeek key set, proving
the built-in scripted model runs the whole loop and writes a report offline.
Targets are loopback only, so the tools stay on the local machine.
"""
from recon_agent.cli import main


def _write_scope(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("cidrs:\n  - 127.0.0.0/8\n")
    return scope


def test_offline_cli_writes_report(tmp_path, monkeypatch):
    # No key in the environment — proves --offline needs no credentials.
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    out = tmp_path / "report.md"

    rc = main(
        ["--scope", str(_write_scope(tmp_path)),
         "--target", "127.0.0.1", "-o", str(out), "--offline"]
    )

    assert rc == 0
    report = out.read_text()
    assert "# Reconnaissance Report" in report
    assert "No LLM API was used" in report
    # The scripted model drove the real tools over the loopback target.
    for tool in ("resolve_host", "port_scan", "http_probe"):
        assert tool in report


def test_offline_cli_still_enforces_scope(tmp_path, monkeypatch):
    # --offline must not weaken the scope guard: an out-of-scope target fails fast.
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    out = tmp_path / "report.md"

    rc = main(
        ["--scope", str(_write_scope(tmp_path)),
         "--target", "8.8.8.8", "-o", str(out), "--offline"]
    )

    assert rc == 2            # scope-failure exit code
    assert not out.exists()   # nothing was scanned or written
