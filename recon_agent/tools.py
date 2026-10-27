"""Recon tools exposed to the agent.

Each tool is scope-guarded: it calls `guard.require()` before doing anything on
the network. Tools degrade gracefully when the underlying binary (nmap,
subfinder) is not installed, so the project runs in a dev environment and on a
pentester's Kali box alike.

All subprocess calls pass arguments as a list (never shell=True) and use the
sanitised target, so a target string cannot inject extra commands.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
from urllib.parse import urlparse

import httpx
from langchain_core.tools import tool

from .scope import ScopeError, ScopeGuard, sanitize_host

# The guard is injected at graph-build time via set_guard(); tools read it here.
_GUARD: ScopeGuard | None = None


def set_guard(guard: ScopeGuard) -> None:
    global _GUARD
    _GUARD = guard


def _guard() -> ScopeGuard:
    if _GUARD is None:
        raise RuntimeError("ScopeGuard not set. Call set_guard() before running the agent.")
    return _GUARD


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


@tool
def resolve_host(host: str) -> str:
    """Resolve a hostname to its IP addresses. Input: a single hostname in scope."""
    host = sanitize_host(host)
    _guard().require(host)
    try:
        _, _, ips = socket.gethostbyname_ex(host)
        return json.dumps({"host": host, "addresses": ips})
    except socket.gaierror as e:
        return json.dumps({"host": host, "error": f"resolution failed: {e}"})


@tool
def enumerate_subdomains(domain: str) -> str:
    """Enumerate subdomains of an in-scope domain using subfinder if available,
    otherwise fall back to certificate-transparency logs (crt.sh). Input: a
    registrable domain such as example.com."""
    domain = sanitize_host(domain)
    _guard().require(domain)
    found: set[str] = set()

    if shutil.which("subfinder"):
        try:
            code, out, _ = _run(["subfinder", "-silent", "-d", domain], timeout=180)
            if code == 0:
                found.update(l.strip() for l in out.splitlines() if l.strip())
        except subprocess.TimeoutExpired:
            pass

    if not found:
        # Passive fallback: crt.sh certificate transparency.
        try:
            r = httpx.get(
                "https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                timeout=60,
            )
            if r.status_code == 200:
                for row in r.json():
                    for name in str(row.get("name_value", "")).splitlines():
                        name = name.strip().lstrip("*.").lower()
                        if name.endswith(domain):
                            found.add(name)
        except (httpx.HTTPError, json.JSONDecodeError):
            pass

    # Only report subdomains that are themselves in scope.
    in_scope = sorted(h for h in found if _guard().is_in_scope(h))
    return json.dumps({"domain": domain, "count": len(in_scope), "subdomains": in_scope})


@tool
def port_scan(host: str) -> str:
    """Scan common TCP ports on an in-scope host with nmap if available,
    otherwise a lightweight built-in connect scan. Input: a single hostname or
    IP in scope."""
    host = sanitize_host(host)
    _guard().require(host)

    if shutil.which("nmap"):
        try:
            code, out, err = _run(
                ["nmap", "-Pn", "-T4", "--top-ports", "100", host], timeout=300
            )
            if code == 0:
                return json.dumps({"host": host, "scanner": "nmap", "output": out})
            return json.dumps({"host": host, "scanner": "nmap", "error": err.strip()})
        except subprocess.TimeoutExpired:
            return json.dumps({"host": host, "error": "nmap scan timed out"})

    # Fallback: connect scan over a small set of common ports.
    common = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
    open_ports = []
    for port in common:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            s.close()
    return json.dumps(
        {"host": host, "scanner": "builtin", "open_ports": open_ports}
    )


@tool
def http_probe(url: str) -> str:
    """Fetch an in-scope URL and report status, server header, title and
    redirect target. Input: a full http(s) URL whose host is in scope."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = sanitize_host(parsed.hostname or "")
    _guard().require(host)
    try:
        r = httpx.get(url, timeout=30, follow_redirects=True)
        title = ""
        if "text/html" in r.headers.get("content-type", ""):
            import re

            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            if m:
                title = m.group(1).strip()[:200]
        return json.dumps(
            {
                "url": url,
                "status": r.status_code,
                "server": r.headers.get("server", ""),
                "title": title,
                "final_url": str(r.url),
            }
        )
    except httpx.HTTPError as e:
        return json.dumps({"url": url, "error": str(e)})


ALL_TOOLS = [resolve_host, enumerate_subdomains, port_scan, http_probe]
