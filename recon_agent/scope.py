"""Scope enforcement.

Every active action in this tool must pass through `ScopeGuard`. A target is
only in scope if it matches a rule the operator wrote in `scope.yaml`. This is
the safety core of the project: if a host is not explicitly authorised, no tool
will touch it.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ScopeError(Exception):
    """Raised when a target is not covered by the authorised scope."""


@dataclass
class Scope:
    """A set of authorised targets, loaded from scope.yaml.

    domains:  exact hostnames or wildcard suffixes (e.g. "*.example.com")
    cidrs:    IPv4/IPv6 networks in CIDR notation (e.g. "10.10.0.0/16")
    """

    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            domains=[str(d).strip().lower() for d in data.get("domains", [])],
            cidrs=[str(c).strip() for c in data.get("cidrs", [])],
        )


class ScopeGuard:
    """Decides whether a given host or IP is authorised."""

    def __init__(self, scope: Scope):
        self.scope = scope
        self._networks = [ipaddress.ip_network(c, strict=False) for c in scope.cidrs]

    def _matches_domain(self, host: str) -> bool:
        host = host.strip().lower().rstrip(".")
        for rule in self.scope.domains:
            if rule.startswith("*."):
                suffix = rule[1:]  # ".example.com"
                if host == rule[2:] or host.endswith(suffix):
                    return True
            elif host == rule:
                return True
        return False

    def _matches_cidr(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in self._networks)

    def is_in_scope(self, host: str) -> bool:
        host = host.strip()
        if not host:
            return False
        return self._matches_cidr(host) or self._matches_domain(host)

    def require(self, host: str) -> str:
        """Return the host if authorised, else raise ScopeError."""
        if not self.is_in_scope(host):
            raise ScopeError(
                f"'{host}' is not in the authorised scope. "
                f"Add it to scope.yaml only if you have written permission to test it."
            )
        return host


_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]/]+$")


def sanitize_host(host: str) -> str:
    """Reject anything that isn't a plain hostname/IP/CIDR.

    Blocks shell metacharacters so a target string can never smuggle extra
    commands into a subprocess argument list.
    """
    host = host.strip()
    if not host or not _HOST_RE.match(host):
        raise ScopeError(f"Refusing suspicious target string: {host!r}")
    return host
