#!/usr/bin/env python3
"""Release a reviewed revision of ACP to both production hosts, in the one safe order.

    scripts/release.py --work-item OWNER/NAME#N [--branch BRANCH] [--skip-railway]
                       [--token-account ACP_GATEWAY_TOKEN] [--timeout SECONDS] [--dry-run]

It acts on the checkout it lives in, which must be clean and on the pull request branch at the
commit to release, with ACP_DATABASE_MIGRATION_URL in the environment (never printed). In order:

1. Plan: HEAD is published as BRANCH on GitHub and fast-forwards origin/main.
2. Hold: the machine is not on hold (~/.claude/hooks/HOLD). The pushes and deploys below run in
   subprocesses the Bash guards cannot see, so the script checks the hold itself and asks ACP.
3. Migrate: if the production database lacks this release's migrations, ask ACP for an
   exact `database.migrate`, apply them, and check again. Only migrations marked additive
   are applied here: the running release keeps serving on them. Anything else stops.
4. Merge: fast-forward main under an exact `git.protected_ref.update` (scripts/ff-merge.py).
   Vercel builds main and moves the production alias on its own.
5. Vercel: wait for that build to be READY and the alias to point at it.
6. Railway: deploy `git archive` of the same SHA (nothing local rides along) and wait for SUCCESS.
7. Verify: /health and /ready on both hosts.

Migrating before merging is the point: a build of a release whose migrations are pending
fails the production build guard. --dry-run runs steps 1 and the migration check, prints
the plan, and changes nothing. Exit 0 only when every step passed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acp_ops
from acp_ops import ROOT, Stop, git

sys.path.insert(0, str(ROOT))
from db_migrations import is_additive, migration_files

_spec = importlib.util.spec_from_file_location("ff_merge", Path(__file__).resolve().parent / "ff-merge.py")
ff_merge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ff_merge)

VERCEL_PROJECT = "acp-gateway"
VERCEL_TEAM = "team_8mC0mXDMIpioyO8cMRjLwb4H"
VERCEL_URL = "https://acp-gateway.vercel.app"
RAILWAY_PROJECT = "a3dbbfc5-3fe7-4365-a754-9a7856766f05"
RAILWAY_SERVICE = "b2f28e52-a113-41c5-b29f-6dcb6a54d3aa"
RAILWAY_ENVIRONMENT = "dac18c6b-a1ce-485b-b3a4-a8949dc5ad6e"
RAILWAY_URL = "https://acp-gateway-production.up.railway.app"
RAILWAY_IDS = ("-p", RAILWAY_PROJECT, "-s", RAILWAY_SERVICE, "-e", RAILWAY_ENVIRONMENT)
# The non-secret name ACP's database.migrate decisions use for the production database.
DATABASE_ID = "neon-wispy-scene-19011576-production"
POLL_SECONDS = 10
sleep = time.sleep


def report(step: str, **fields) -> None:
    print(json.dumps({"step": step, **fields}))


def migration_state() -> tuple[int, dict]:
    """migrate-db.py --check in its own process, so the connection string never enters this one's output."""
    dsn = os.environ.get("ACP_DATABASE_MIGRATION_URL", "").strip()
    if not dsn:
        raise Stop("ACP_DATABASE_MIGRATION_URL is not set. Run this under "
                   "latchkey run --env-file .env.local -- ...")
    if dsn.startswith("latchkey://"):
        raise Stop("ACP_DATABASE_MIGRATION_URL is a Latchkey reference, not a value. Run this under "
                   "latchkey run --env-file .env.local -- ...")
    result = acp_ops.run(sys.executable, str(ROOT / "scripts/migrate-db.py"), "--check")
    try:
        state = json.loads(result.stdout.strip().splitlines()[-1]) if result.stdout.strip() else {}
    except ValueError:
        state = {}
    if result.returncode not in (0, 3) or not state:
        raise Stop(f"the migration check failed: {result.stderr.strip() or 'no report'}; nothing was changed")
    if result.returncode == 0 and state.get("status") != "current":
        raise Stop(f"the migration check reported {state.get('status')!r}; nothing was changed")
    return result.returncode, state


def pending_plan(state: dict) -> dict | None:
    """What a migration would do, or None when the database is current. Refuses non-additive steps."""
    pending = sorted(int(version) for version in state.get("pending_versions") or [])
    if not pending:
        return None
    files = {version: sql for version, _name, _checksum, sql in migration_files()}
    blocking = [f"{version:04d}" for version in pending if not is_additive(files[version])]
    if blocking:
        raise Stop(f"pending migrations {', '.join(blocking)} are not marked additive, so the running release "
                   "would refuse the database between migrating and deploying. Split them into expand and "
                   "contract steps, or run that lockstep by hand under its own ACP decision")
    applied = sorted(int(version) for version in state.get("applied_versions") or [])
    return {"from": f"{applied[-1]:04d}" if applied else "0000", "to": f"{pending[-1]:04d}",
            "versions": [f"{version:04d}" for version in pending]}


def migrate(update: dict, branch: str, token: str, work_item: str, step: dict) -> None:
    context = {"source_database": f"{DATABASE_ID}-at-{step['from']}",
               "target_database": f"{DATABASE_ID}-at-{step['to']}",
               "work_item": work_item, "environment": "production",
               "ref": f"refs/heads/{branch}", "new_sha": update["new_sha"]}
    decision = acp_ops.authorize(token, update["owner"], update["name"], "database.migrate", update["new_sha"],
                                 context, f"migrate production to {step['to']} for {work_item}", ff_merge.AGENT_ID)
    report("authorize-migration", **decision)
    acp_ops.require_allow(decision, "database.migrate", **context)
    result = acp_ops.run(sys.executable, str(ROOT / "scripts/migrate-db.py"))
    if result.returncode != 0:
        raise Stop(f"the migration failed: {result.stderr.strip() or 'no detail'}. main and both hosts are "
                   "unchanged; fix the migration and run this again")
    code, state = migration_state()
    if code != 0:
        raise Stop(f"the database is still {state.get('status')} after migrating; main and both hosts are unchanged")
    report("migrated", versions=step["versions"])


def vercel_build(new_sha: str, timeout: float) -> dict:
    """Wait for Vercel's production build of new_sha. Returns the deployment once READY."""
    deadline = time.monotonic() + timeout
    while True:
        result = acp_ops.run("vercel", "ls", VERCEL_PROJECT, "--environment", "production", "--json",
                             "--scope", VERCEL_TEAM)
        try:
            deployments = json.loads(result.stdout).get("deployments") or []
        except ValueError:
            deployments = []
        build = next((d for d in deployments if (d.get("meta") or {}).get("githubCommitSha") == new_sha), None)
        state = (build or {}).get("state") or (build or {}).get("readyState")
        if state == "READY":
            return build
        if state in ("ERROR", "CANCELED"):
            raise Stop(f"Vercel's production build of {new_sha[:12]} ended {state}: vercel inspect "
                       f"{build.get('url')} --logs. The alias stays on the previous deployment; main is at "
                       f"{new_sha[:12]} and Railway was not deployed. Fix forward with a new release")
        if time.monotonic() >= deadline:
            raise Stop(f"Vercel had no READY production build of {new_sha[:12]} after {int(timeout)}s "
                       f"(last state: {state or 'not started'}); Railway was not deployed. Check vercel ls")
        sleep(POLL_SECONDS)


def vercel_alias(build: dict) -> None:
    result = acp_ops.run("vercel", "inspect", VERCEL_URL.removeprefix("https://"), "--json", "--scope", VERCEL_TEAM)
    try:
        current = json.loads(result.stdout)
    except ValueError:
        current = {}
    if current.get("url") != build.get("url"):
        raise Stop(f"the production alias points at {current.get('url') or 'an unknown deployment'}, not "
                   f"{build.get('url')}; Railway was not deployed. Promote or roll back on Vercel first")


def railway_deployments() -> list[dict]:
    result = acp_ops.run("railway", "deployment", "list", "--json", "--limit", "1", *RAILWAY_IDS)
    try:
        listed = json.loads(result.stdout)
    except ValueError:
        listed = None
    if result.returncode != 0 or not isinstance(listed, list):
        raise Stop("Railway's deployment list could not be read; run `railway login` and check the service")
    return listed


def railway_deploy(checkout: Path, new_sha: str, timeout: float) -> dict:
    """Deploy exactly new_sha's tree to Railway and wait for the deployment to succeed."""
    before = (railway_deployments() or [{}])[0].get("id")
    with tempfile.TemporaryDirectory(prefix="acp-release-") as tree:
        archive = subprocess.run(["git", "archive", "--format=tar", new_sha], cwd=checkout, capture_output=True)
        if archive.returncode != 0:
            raise Stop(f"git archive {new_sha[:12]} failed; Railway was not deployed")
        unpacked = subprocess.run(["tar", "-x", "-C", tree], input=archive.stdout, capture_output=True)
        if unpacked.returncode != 0:
            raise Stop("the release tree could not be unpacked; Railway was not deployed")
        up = acp_ops.run("railway", "up", tree, "--path-as-root", "--detach", *RAILWAY_IDS, cwd=tree)
        if up.returncode != 0:
            raise Stop(f"railway up failed ({up.stderr.strip()[-300:] or 'no detail'}); Railway still runs the "
                       "previous release")
    deadline = time.monotonic() + timeout
    while True:
        latest = (railway_deployments() or [{}])[0]
        if latest.get("id") and latest["id"] != before:
            if latest.get("status") == "SUCCESS":
                return latest
            if latest.get("status") in ("FAILED", "CRASHED", "REMOVED", "SKIPPED"):
                raise Stop(f"Railway deployment {latest['id']} ended {latest['status']}; Railway still runs the "
                           "previous release. Read its logs with `railway logs --deployment` and fix forward")
        if time.monotonic() >= deadline:
            raise Stop(f"Railway's deployment of {new_sha[:12]} did not succeed within {int(timeout)}s "
                       f"(last: {latest.get('status') or 'not started'})")
        sleep(POLL_SECONDS)


def verify(hosts: list[str]) -> None:
    failures = []
    for base in hosts:
        for path, expect in (("/health", "ok"), ("/ready", "ready")):
            status, body = acp_ops.get_json(base + path)
            if status != 200 or body.get("status") != expect:
                failures.append(f"{base}{path} answered {status} {body.get('status')}")
    if failures:
        raise Stop("the release is deployed but not healthy: " + "; ".join(failures))
    report("verified", hosts=hosts)


def release(args, checkout: Path) -> None:
    branch = args.branch or git(checkout, "symbolic-ref", "--short", "HEAD")
    if git(checkout, "status", "--porcelain", "--untracked-files=no"):
        raise Stop("the checkout has uncommitted changes; release from a clean checkout of the branch")
    head = git(checkout, "rev-parse", "HEAD")
    git(checkout, "fetch", "--quiet", "origin", "+refs/heads/main:refs/remotes/origin/main")
    resuming = git(checkout, "rev-parse", "refs/remotes/origin/main") == head
    if resuming:
        # A release that stopped after the merge: main already holds this exact revision, so the
        # remaining steps (Vercel check, Railway, verify) run again and the merge is skipped.
        update = {"owner": "zachshallbetter", "name": "acp-gateway", "ref": "refs/heads/main", "new_sha": head}
    else:
        update = ff_merge.plan(checkout, "origin", "refs/heads/main", "HEAD")
    if git(checkout, "ls-remote", "origin", f"refs/heads/{branch}").split()[:1] != [update["new_sha"]]:
        raise Stop(f"origin/{branch} is not at HEAD ({update['new_sha'][:12]}); push the branch and run this again")
    report("plan", branch=branch, resuming=resuming, **update)
    _code, state = migration_state()
    step = pending_plan(state)
    report("migrations", status=state.get("status"), pending=step["versions"] if step else [])
    if resuming and step:
        raise Stop("main already holds this release but the database is missing its migrations; apply them under "
                   "their own database.migrate decision before deploying again")
    if args.dry_run:
        return
    report("harness", allowed_by=acp_ops.harness_gate(update["name"]))
    if not resuming:
        token = acp_ops.bearer(args.token_account)
        if step:
            migrate(update, branch, token, args.work_item, step)
        ff_merge.merge(checkout, update, token, args.work_item)
        report("merged", ref=update["ref"], new_sha=update["new_sha"])
    build = vercel_build(update["new_sha"], args.timeout)
    vercel_alias(build)
    report("vercel", deployment=build.get("url"))
    hosts = [VERCEL_URL]
    if not args.skip_railway:
        deployment = railway_deploy(checkout, update["new_sha"], args.timeout)
        report("railway", deployment=deployment.get("id"))
        hosts.append(RAILWAY_URL)
    verify(hosts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work-item", required=True, help="the reviewed work item, e.g. owner/name#59")
    parser.add_argument("--branch", help="the published branch at HEAD (default: the checked-out branch)")
    parser.add_argument("--skip-railway", action="store_true", help="release to Vercel only")
    parser.add_argument("--token-account", default="ACP_GATEWAY_TOKEN")
    parser.add_argument("--timeout", type=float, default=600, help="seconds to wait for each host's deployment")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        release(args, ROOT)
    except Stop as exc:
        print(f"release: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
