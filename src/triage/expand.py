"""
Optional shortened-link expansion.

Scoring stays offline and deterministic; this module is the one place that makes
network calls, and the caller opts in. Because it fetches attacker-supplied URLs,
it is built to avoid server-side request forgery:

- only http/https, never localhost or non-global addresses (private, loopback,
  link-local such as the cloud metadata address, reserved)
- every redirect hop is re-checked before it is followed
- hop count, number of links and request time are all capped
- it sends HEAD requests and never reads a response body

Status: CONTAINED. `make_http_resolver()` without an explicit `head` is the identity function
(no DNS, no HTTP). The stdlib transport resolves the host again at connect time (DNS rebinding)
and honours env proxies, so live expansion stays off until a transport that pins the validated
address exists. Independent QA: AI Lab task 9ada4880.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import re
import socket
import urllib.error
import urllib.request
from typing import Callable, Iterable
from urllib.parse import urljoin, urlparse

from .scorer import SHORTENERS, Email, Link, _domain

Resolver = Callable[[str], str]


def _default_resolve(host: str) -> list[str]:
    return [ai[4][0] for ai in socket.getaddrinfo(host, None)]


_AUTHORITY = re.compile(r"(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]+)?")
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", re.IGNORECASE)
_DENY_NETS = [ipaddress.ip_network(n) for n in (
    "168.63.129.16/32",   # Azure WireServer
    "2002::/16",          # 6to4
    "2001::/32",          # Teredo
    "64:ff9b::/96",       # NAT64
)]


def _canonical_dotted_ipv4(host: str) -> str | None:
    """Strict dotted-quad only: four decimal octets, no leading zeros."""
    parts = host.split(".")
    if len(parts) != 4 or not all(p.isdigit() and (p == "0" or not p.startswith("0")) and int(p) < 256
                                  for p in parts):
        return None
    return host


def _addr_ok(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not any(ip in n for n in _DENY_NETS if n.version == ip.version)


def is_safe_target(url: str, resolve: Callable[[str], Iterable[str]] = _default_resolve) -> bool:
    try:
        if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 or c == "\\" for c in url):
            return False
        parts = urlparse(url)
        if parts.scheme not in ("http", "https") or "@" in parts.netloc or "%" in parts.netloc:
            return False
        if not _AUTHORITY.fullmatch(parts.netloc):
            return False
        host = parts.hostname
        if not host or host.lower() == "localhost" or host.lower().endswith(".localhost"):
            return False
        if parts.port not in (None, 80, 443):
            return False
        if host.startswith("[") or ":" in host:
            addrs = [host]
        elif _NUMERIC_HOST.fullmatch(host):
            if _canonical_dotted_ipv4(host) is None:
                return False
            addrs = [host]
        else:
            addrs = list(resolve(host))
        return bool(addrs) and all(_addr_ok(a) for a in addrs)
    except Exception:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _default_head(url: str, timeout: float = 3.0) -> str | None:
    """One HEAD request, redirects not followed. Returns Location only for 301/302/303/307/308."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "phish-triage/1.0"})
    opener = urllib.request.build_opener(_NoRedirect)
    resp = None
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception:
        return None
    try:
        status = getattr(resp, "status", None) or getattr(resp, "code", None)
        return resp.headers.get("Location") if status in (301, 302, 303, 307, 308) else None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def make_http_resolver(head: Callable[[str], str | None] | None = None,
                       resolve: Callable[[str], Iterable[str]] = _default_resolve,
                       max_hops: int = 5) -> Resolver:
    """Containment: with no explicit `head` the resolver is the identity function and makes
    no DNS or HTTP calls. The stdlib transport cannot pin the validated address (DNS rebinding)
    or bypass env proxies, so it must be passed in deliberately until a pinned transport exists."""
    if head is None:
        return lambda url: url

    def resolver(url: str) -> str:
        current = url
        for _ in range(max_hops):
            if not is_safe_target(current, resolve):
                break
            nxt = head(current)
            if not nxt:
                break
            nxt = urljoin(current, nxt)
            if not is_safe_target(nxt, resolve):
                break
            current = nxt
        return current
    return resolver


def expand_links(email: Email, resolver: Resolver, max_links: int = 5) -> Email:
    """Return a copy of `email` with shortened links' `resolved_url` filled in."""
    out: list[Link] = []
    budget = max_links
    for link in email.links:
        resolved = ""
        if budget > 0 and _domain(link.url) in SHORTENERS:
            budget -= 1
            try:
                final = resolver(link.url)
                if final and final != link.url:
                    resolved = final
            except Exception:
                resolved = ""
        out.append(dataclasses.replace(link, resolved_url=resolved))
    return dataclasses.replace(email, links=out)
