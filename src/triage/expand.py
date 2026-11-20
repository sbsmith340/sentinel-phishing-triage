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

Known limit: the hostname is resolved once for the safety check and again by the
HTTP client, so DNS rebinding is not fully closed. Run the Function with no
access to internal networks (VNet egress rules) as defense in depth.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import socket
import urllib.error
import urllib.request
from typing import Callable, Iterable
from urllib.parse import urljoin, urlparse

from .scorer import SHORTENERS, Email, Link, _domain

Resolver = Callable[[str], str]


def _default_resolve(host: str) -> list[str]:
    return [ai[4][0] for ai in socket.getaddrinfo(host, None)]


def is_safe_target(url: str, resolve: Callable[[str], Iterable[str]] = _default_resolve) -> bool:
    try:
        parts = urlparse(url)
        host = parts.hostname
        if parts.scheme not in ("http", "https") or not host or host.lower() == "localhost":
            return False
        try:
            addrs = [str(ipaddress.ip_address(host))]
        except ValueError:
            addrs = list(resolve(host))
        return bool(addrs) and all(ipaddress.ip_address(a).is_global for a in addrs)
    except Exception:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _default_head(url: str, timeout: float = 3.0) -> str | None:
    """One HEAD request, redirects not followed. Returns the Location header, if any."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "phish-triage/1.0"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        resp = opener.open(req, timeout=timeout)
        return resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return e.headers.get("Location")
        return None


def make_http_resolver(head: Callable[[str], str | None] = _default_head,
                       resolve: Callable[[str], Iterable[str]] = _default_resolve,
                       max_hops: int = 5) -> Resolver:
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
