#!/usr/bin/env python3
"""Vercel build step: keep each environment's database in step with this release.

Preview  applies this release's pending migrations to the Preview database, then checks it.
Production only checks; pending or conflicting migrations fail the build, so a release whose
schema the production database does not have can never be built (and so never promoted).
Production migrations stay a separate, ACP-authorized step (scripts/migrate-db.py).

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


def runner(dsn: str, *args: str) -> tuple[int, str]:
    env = {**os.environ, "ACP_DATABASE_MIGRATION_URL": dsn, "ACP_STORAGE_BACKEND": "postgres"}
    cp = subprocess.run([sys.executable, str(RUNNER), *args], cwd=ROOT, env=env,
                        capture_output=True, text=True)
    return cp.returncode, (cp.stdout.strip() or cp.stderr.strip())


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
        print(f"acp build: no database URL in the {target} environment (ACP_DATABASE_URL); refusing to build")
        return 1

    if target == "preview":
        code, out = runner(dsn)
        print(f"acp build: preview migrate: {out}")
        if code != 0:
            return 1
    code, out = runner(dsn, "--check")
    print(f"acp build: {target} schema: {out}")
    if code == 0:
        return 0
    status = json.loads(out).get("status") if out.startswith("{") else "unknown"
    print(f"acp build: {target} database is {status} for this release; "
          + ("apply the pending migrations with an ACP-authorized scripts/migrate-db.py run before deploying"
             if target == "production" else "fix the Preview database before deploying"))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
