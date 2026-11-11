#!/usr/bin/env python3
"""posture-report.py -- render ACP's build posture as one HTML page for the owner.

    .venv/bin/python scripts/posture-report.py [--refresh] [--out posture.html] [--json]

Reads GET /internal/posture (read-only). --refresh first asks ACP to re-read every governed
repository's Vercel, Railway and GitHub Actions settings, which needs the owner's administrative
credential. Credentials come from the Keychain service "ACP Gateway Production" and are never
printed. Nothing is changed on any provider: every finding names the exact fix and who applies it.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))


def admin_module():
    spec = importlib.util.spec_from_file_location("policy_admin", HERE / "scripts/policy-admin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--refresh", action="store_true", help="re-read providers first (owner credential)")
    parser.add_argument("--out", default="posture.html")
    parser.add_argument("--json", action="store_true", help="print the JSON report instead of writing HTML")
    args = parser.parse_args()
    admin = admin_module()
    bearer = admin.keychain("ACP_GATEWAY_TOKEN")
    if args.refresh:
        admin_token, refreshed = admin.keychain("ACP_POLICY_ADMIN_TOKEN"), 0
        for _ in range(50):                      # one short request per batch of repositories
            result = admin.gateway_call("/internal/posture/refresh", bearer, admin_token, {})
            refreshed += len(result["refreshed"])
            if not result.get("remaining"):
                break
        print(f"refreshed {refreshed}, skipped {len(result['skipped_recent'])} (refreshed recently)", file=sys.stderr)
    body = admin.gateway_call("/internal/posture", bearer)
    import posture
    try:
        drift = posture.policy_drift(admin.gateway_call("/internal/policy", bearer),
                                     admin.gateway_call_at(admin.RAILWAY_URL, "/internal/policy", bearer))
    except SystemExit as exc:                          # the peer could not be read: that is a finding too
        drift = [{"severity": "high", "code": "POLICY_DRIFT_UNCHECKED", "repository": "railway",
                  "subject": admin.RAILWAY_URL, "problem": f"Railway's policies could not be read: {exc}",
                  "fix": "Check the Railway service is up (GET /ready) and answers the shared bearer.",
                  "who": "owner"}]
    body["findings"] = drift + body["findings"]
    if args.json:
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0
    Path(args.out).write_text(posture.render_html(body), encoding="utf-8")
    high = sum(1 for f in body["findings"] if f["severity"] == "high")
    print(f"wrote {args.out}: {len(body['findings'])} findings, {high} high", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
