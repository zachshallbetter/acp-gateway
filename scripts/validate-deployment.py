#!/usr/bin/env python3
"""Validate a deployed ACP contract without exposing credentials or policy contents."""
from __future__ import annotations
import argparse
import json
import os
import sys
import urllib.request

def get(url: str, token: str | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if token: headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as response:
            return {"status": response.status, "body": json.loads(response.read(65536))}
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"request failed for {url}: {exc}") from exc

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("ACP_GATEWAY_URL"))
    parser.add_argument("--token", default=os.getenv("ACP_GATEWAY_TOKEN"), help="prefer ACP_GATEWAY_TOKEN")
    parser.add_argument("--require-security", action="store_true", help="fail unless signing, persistence, and audit are enabled")
    args = parser.parse_args()
    if not args.url: parser.error("--url or ACP_GATEWAY_URL is required")
    base = args.url.rstrip("/")
    health = get(f"{base}/health")
    if health["status"] != 200 or health["body"].get("status") != "ok": raise RuntimeError("health contract failed")
    status = get(f"{base}/internal/app-status", args.token)
    body = status["body"]
    if status["status"] != 200 or body.get("configured") is not True: raise RuntimeError("authenticated app-status contract failed")
    keys = ("configured", "policy_signing", "capability_signing", "security_state_persisted", "audit_log_configured", "audit_hash_chain", "installation_resolution", "token_minting")
    print(json.dumps({"health": "ok", "app_status": {key: body.get(key) for key in keys}}, sort_keys=True))
    if args.require_security:
        required = ("policy_signing", "capability_signing", "security_state_persisted", "audit_log_configured", "audit_hash_chain")
        missing = [key for key in required if body.get(key) is not True]
        if missing: raise RuntimeError("required production security controls are disabled: " + ", ".join(missing))
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
