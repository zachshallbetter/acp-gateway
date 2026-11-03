#!/usr/bin/env python3
"""Vercel build step: refuse to build a production release its database does not match.

Production checks the database read-only; pending or conflicting migrations fail the build,
so a release whose schema the production database does not have can never be built (and so
never promoted). Production migrations stay a separate, ACP-authorized step
(scripts/migrate-db.py). A commit without the Vercel runtime refuses to build.

Preview is not a release gate: a Preview build reports its database's schema state and never
writes to it or fails because of it. Releases are verified on the unpromoted production
deployment instead.

The database URL is read from the deployment's own environment, exactly as the runtime
reads it, and is never printed. Outside Vercel this does nothing.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "migrate-db.py"


def check(dsn: str) -> tuple[str, dict]:
    env = {**os.environ, "ACP_DATABASE_MIGRATION_URL": dsn, "ACP_STORAGE_BACKEND": "postgres"}
    cp = subprocess.run([sys.executable, str(RUNNER), "--check"], cwd=ROOT, env=env,
                        capture_output=True, text=True)
    out = cp.stdout.strip() or cp.stderr.strip()
    return out, (json.loads(out) if out.startswith("{") else {})


def explain(report: dict) -> str:
    status = report.get("status", "unknown")
    if status == "pending":
        return "pending migrations: " + ", ".join(report.get("pending_versions") or [])
    if status == "conflict":
        parts = [f"{label} {', '.join(report[key])}" for key, label in (
            ("unknown_versions", "versions this release does not ship:"),
            ("checksum_mismatch_versions", "versions with different checksums:")) if report.get(key)]
        return "migrated by a different release (" + ("; ".join(parts) or "history has a gap") + ")"
    return f"schema state {status}"


def main() -> int:
    target = os.getenv("VERCEL_ENV", "").strip()
    if not os.getenv("VERCEL") or target not in ("preview", "production"):
        print(f"acp build: not a Vercel preview or production build ({target or 'local'}); database step skipped")
        return 0
    if not (ROOT / "api" / "index.py").exists() or not (ROOT / "vercel.json").exists():
        print("acp build: this commit has no Vercel runtime (api/index.py, vercel.json); refusing to build")
        return 1
    dsn = (os.getenv("ACP_DATABASE_URL", "").strip() or os.getenv("POSTGRES_URL", "").strip()
           or os.getenv("DATABASE_URL", "").strip())
    if not dsn:
        if target == "preview":
            print("acp build: preview has no database URL; Preview is not a release gate, continuing")
            return 0
        print("acp build: no database URL in the production environment (ACP_DATABASE_URL); refusing to build")
        return 1

    out, report = check(dsn)
    print(f"acp build: {target} schema: {out}")
    if report.get("status") == "current":
        return 0
    if target == "preview":
        print(f"acp build: warning: the Preview database is {explain(report)}; /ready will report not ready. "
              "Preview is not a release gate, so the build continues and nothing was written.")
        return 0
    print(f"acp build: the production database is {explain(report)} for this release. "
          + ("Apply the pending migrations with an ACP-authorized scripts/migrate-db.py run before deploying."
             if report.get("status") == "pending" else
             "Do not deploy this release against it; reconcile the schema under an ACP-authorized migration plan."))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
