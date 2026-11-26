"""Vercel Python Function adapter for the existing ACP HTTP handler.

The rewrite carries the original URL path in the reserved `__acp_path`
parameter. Durable state remains in the shared PostgreSQL authority.
"""
from __future__ import annotations

import os
import logging
import threading
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

# `vercel dev` does not always set the platform marker on Python workers.
# This adapter is Vercel-only, so select the same fail-closed storage default
# locally and in the deployed runtime before importing the gateway.
os.environ["VERCEL"] = "1"

from gateway import Handler, boot_check


ROUTE_PARAMETER = "__acp_path"
MAX_URL_BYTES = 8192


def restore_request_path(request_path: str) -> str:
    """Recover ACP's path and caller query from the Vercel rewrite URL."""
    if len(request_path.encode("utf-8")) > MAX_URL_BYTES:
        raise ValueError("request URL exceeds the ACP limit")
    parsed = urlsplit(request_path)
    values = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256)
    routes = [value for key, value in values if key == ROUTE_PARAMETER]
    if not routes and parsed.path not in ("", "/api"):
        route = parsed.path
        if (not route.startswith("/") or "\\" in route
                or parsed.fragment or any(ord(char) < 32 for char in request_path)):
            raise ValueError("Vercel request path is invalid")
        query = urlencode([(key, value) for key, value in values if key != ROUTE_PARAMETER])
        safe_route = quote(route, safe="/@:!$&'()*+,;=-._~%")
        return safe_route + ("?" + query if query else "")
    if len(routes) != 1:
        raise ValueError(f"Vercel rewrite route parameter count is {len(routes)}")
    routed = urlsplit(routes[0])
    if (not routed.path.startswith("/") or routed.scheme or routed.netloc or routed.fragment
            or "\\" in routed.path or any(ord(char) < 32 for char in routes[0])):
        raise ValueError("Vercel rewrite route parameter is invalid")
    caller_query = [(key, value) for key, value in values if key != ROUTE_PARAMETER]
    embedded_query = parse_qsl(routed.query, keep_blank_values=True, max_num_fields=256)
    if len(caller_query) + len(embedded_query) > 256:
        raise ValueError("Vercel rewrite query exceeds the ACP limit")
    if any(key == ROUTE_PARAMETER for key, _ in caller_query + embedded_query):
        raise ValueError("Vercel rewrite query contains a reserved parameter")
    query = urlencode(embedded_query + caller_query)
    safe_route = quote(routed.path, safe="/@:!$&'()*+,;=-._~%")
    return safe_route + ("?" + query if query else "")


# A passed check holds for the instance's life. A failed one is run again, at most every BOOT_RETRY_SECONDS:
# a database that was briefly unreachable (waking, at its connection limit) must not leave a warm instance
# refusing every request until Vercel recycles it, as happened on 2026-11-26.
BOOT_RETRY_SECONDS = 15
_BOOT = {"passed": False, "problem": None, "checked_at": None}
_BOOT_LOCK = threading.Lock()


def boot_problem(now=None):
    """The gateway's start-up configuration check (Vercel never calls main()); None once it has passed.

    Requests that arrive while a check runs wait for its answer: none is served before the check has
    passed, and none is refused only because another request got there first."""
    if _BOOT["passed"]:
        return None
    with _BOOT_LOCK:
        if _BOOT["passed"]:
            return None
        now = time.monotonic() if now is None else now
        if _BOOT["checked_at"] is not None and now - _BOOT["checked_at"] < BOOT_RETRY_SECONDS:
            return _BOOT["problem"]                          # a recent failure; not checked again yet
        try:
            boot_check()
        except SystemExit as exc:
            problem = str(exc) or "configuration check failed"
            if problem != _BOOT["problem"]:                  # log each new failure, not every retry
                logging.error("ACP configuration check failed: %s", problem)
            _BOOT.update(problem=problem, checked_at=now)
            return problem
        if _BOOT["problem"]:
            logging.warning("ACP configuration check passed after failing: %s", _BOOT["problem"])
        _BOOT.update(passed=True, problem=None, checked_at=now)
        return None


class handler(Handler):
    """Vercel's required top-level Python function handler."""

    def _restore_path(self):
        try:
            self.path = restore_request_path(self.path)
        except (UnicodeError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            logging.warning("Rejected Vercel rewrite: %s", reason)
            self.reply(400, {"error": "INVALID_REWRITE", "detail": "The request route is invalid."})
            return False
        if urlsplit(self.path).path != "/health" and boot_problem():
            # Fail closed, as the server does when it refuses to start; /health still answers.
            self.discard_body()
            self.reply(503, {"error": "MISCONFIGURED", "detail": "This ACP host failed its configuration check.",
                             "remedy": "The owner reads the function log for the named setting."})
            return False
        return True

    def do_GET(self):
        if self._restore_path():
            super().do_GET()

    def do_POST(self):
        if self._restore_path():
            super().do_POST()
