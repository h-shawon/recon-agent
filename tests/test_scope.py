"""Tests for scope enforcement — the safety core of the project."""
import pytest

from recon_agent.scope import Scope, ScopeError, ScopeGuard, sanitize_host


@pytest.fixture
def guard():
    scope = Scope(domains=["example.com", "*.example.com"], cidrs=["10.10.0.0/16"])
    return ScopeGuard(scope)


def test_exact_domain_in_scope(guard):
    assert guard.is_in_scope("example.com")


def test_wildcard_subdomain_in_scope(guard):
    assert guard.is_in_scope("api.example.com")
    assert guard.is_in_scope("a.b.example.com")


def test_unrelated_domain_out_of_scope(guard):
    assert not guard.is_in_scope("example.org")
    assert not guard.is_in_scope("notexample.com")


def test_lookalike_suffix_not_matched(guard):
    # evilexample.com must NOT match *.example.com
    assert not guard.is_in_scope("evilexample.com")


def test_ip_in_cidr(guard):
    assert guard.is_in_scope("10.10.5.5")


def test_ip_outside_cidr(guard):
    assert not guard.is_in_scope("10.20.5.5")


def test_require_raises_out_of_scope(guard):
    with pytest.raises(ScopeError):
        guard.require("google.com")


def test_require_returns_host_in_scope(guard):
    assert guard.require("example.com") == "example.com"


@pytest.mark.parametrize("bad", ["example.com; rm -rf /", "a.com && curl x", "$(id)", "a com"])
def test_sanitize_rejects_shell_metacharacters(bad):
    with pytest.raises(ScopeError):
        sanitize_host(bad)


def test_sanitize_accepts_plain_host():
    assert sanitize_host("api.example.com") == "api.example.com"
    assert sanitize_host("10.10.0.0/16") == "10.10.0.0/16"
