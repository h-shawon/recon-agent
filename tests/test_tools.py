"""Tests for the recon tools, run fully offline (no network, no LLM)."""
import json

import pytest

from recon_agent import tools
from recon_agent.scope import Scope, ScopeError, ScopeGuard


@pytest.fixture(autouse=True)
def guard():
    g = ScopeGuard(Scope(domains=["example.com", "*.example.com"], cidrs=["10.10.0.0/16"]))
    tools.set_guard(g)
    return g


def test_port_scan_raises_out_of_scope():
    # Invoking the raw tool out of scope must raise before any network action.
    with pytest.raises(ScopeError):
        tools.port_scan.invoke({"host": "google.com"})


def test_http_probe_raises_out_of_scope():
    with pytest.raises(ScopeError):
        tools.http_probe.invoke({"url": "http://google.com/"})


def test_resolve_host_blocks_out_of_scope():
    with pytest.raises(ScopeError):
        tools.resolve_host.invoke({"host": "example.org"})


def test_set_guard_required():
    tools._GUARD = None
    with pytest.raises(RuntimeError):
        tools._guard()
    # restore for other tests
    tools.set_guard(ScopeGuard(Scope(domains=["example.com"])))
