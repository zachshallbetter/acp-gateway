#!/usr/bin/env python3
"""Stage and optionally apply the ACP Railway production-hardening transition.

The default is a read-only preflight. Applying requires both --apply and
--confirm-production, writes all variables with deploys suppressed, and only
then redeploys the exact selected service.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "hardening-preflight")
import gateway  # noqa: E402


def railway(args: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(["railway", *args], input=input_text, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip()[:300] or "Railway command failed")
    return result.stdout


def variables(service: str, environment: str) -> dict:
    raw = railway(["variable", "list", "--service", service, "--environment", environment, "--json"])
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("Railway variable list did not return an object")
    return value


def policies(text: str) -> list[dict]:
    if not text.strip():
        raise RuntimeError("ACP_POLICY is empty; refusing to enable signed production mode")
    value = json.loads(text)
    entries = value.get("policies") if isinstance(value, dict) and "policies" in value else value
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries or not all(isinstance(item, dict) for item in entries):
        raise RuntimeError("ACP_POLICY is not a non-empty policy list")
    return copy.deepcopy(entries)


def sign(policy: dict, key: str, key_id: str) -> dict:
    body = {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id", "sha256")}
    digest = gateway.policy_digest(body)
    result = dict(body)
    result["signature"] = hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest()
    if key_id:
        result["signing_key_id"] = key_id
    return result


def volume_present() -> bool:
    raw = railway(["volume", "list", "--json"])
    value = json.loads(raw)
    return bool(value if isinstance(value, list) else value.get("volumes", []))


def set_variable(name: str, value: str, service: str, environment: str, secret: bool) -> None:
    base = ["variable", "set", name, "--service", service, "--environment", environment, "--skip-deploys"]
    if secret:
        railway(base + ["--stdin"], input_text=value)
    else:
        railway(["variable", "set", f"{name}={value}", "--service", service, "--environment", environment, "--skip-deploys"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", default=os.getenv("ACP_RAILWAY_SERVICE", "acp-gateway"))
    parser.add_argument("--environment", default=os.getenv("ACP_RAILWAY_ENV", "production"))
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-production", action="store_true")
    args = parser.parse_args()
    if args.apply and not args.confirm_production:
        parser.error("--apply requires --confirm-production")
    current = variables(args.service, args.environment)
    current_policies = policies(current.get("ACP_POLICY", ""))
    has_volume = volume_present()
    result = {
        "service": args.service,
        "environment": args.environment,
        "policy_count": len(current_policies),
        "already_signed": all("signature" in item for item in current_policies),
        "volume_present": has_volume,
        "will_redeploy": bool(args.apply),
    }
    if not has_volume:
        result["remedy"] = "Create and attach a Railway volume mounted at /data before applying."
    print(json.dumps(result, sort_keys=True))
    if not args.apply:
        return 0
    if not has_volume:
        raise RuntimeError("no Railway volume is attached; refusing to enable durable production state")
    # Preserve keys from an interrupted staged run. Rotating them here would
    # make any policy signed by the previous staged key unverifiable.
    policy_key = current.get("ACP_POLICY_SIGNING_KEY") or secrets.token_urlsafe(48)
    capability_key = current.get("ACP_CAPABILITY_SIGNING_KEY") or secrets.token_urlsafe(48)
    key_id = current.get("ACP_POLICY_SIGNING_KEY_ID", "acp-policy-hmac-sha256")
    signed = [sign(item, policy_key, key_id) for item in current_policies]
    document = json.dumps(signed, sort_keys=True, separators=(",", ":"))
    set_variable("ACP_POLICY_SIGNING_KEY", policy_key, args.service, args.environment, True)
    set_variable("ACP_CAPABILITY_SIGNING_KEY", capability_key, args.service, args.environment, True)
    set_variable("ACP_POLICY", document, args.service, args.environment, True)
    for name, value in (("ACP_SECURITY_STATE_FILE", "/data/security-state.json"),
                        ("ACP_AUDIT_LOG", "/data/audit.jsonl"),
                        ("ACP_AUDIT_HASH_CHAIN", "1"),
                        ("ACP_REQUIRE_PRODUCTION_CONTROLS", "1")):
        set_variable(name, value, args.service, args.environment, False)
    railway(["service", "redeploy", "--service", args.service, "--environment", args.environment, "--yes"])
    print(json.dumps({"applied": True, "policy_count": len(signed), "key_id": key_id}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
