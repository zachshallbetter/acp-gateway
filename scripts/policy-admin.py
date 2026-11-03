#!/usr/bin/env python3
"""policy-admin.py -- the owner's policy and baseline changes for the Vercel deployment.

    .venv/bin/python scripts/policy-admin.py register OWNER/NAME [OWNER/NAME ...] [--apply]
    .venv/bin/python scripts/policy-admin.py grant OWNER/NAME --checkout DIR [--apply]

register  puts repositories under an ACP policy. It reads production's ACP_POLICY from
          Vercel, checks that the Keychain signing key reproduces every existing signature,
          adds or replaces one policy per repository (default protected actions, no pinned
          artifacts), signs it, loads the whole document with the gateway's own loader, and
          only with --apply writes ACP_POLICY on Vercel and policies/production.json here.
          The new policy takes effect on the next production deployment.

grant     authorizes the pinned-artifact changes a checkout's HEAD makes for a governed
          repository whose policy has an artifact manifest. For every protected path whose
          content at HEAD differs from what ACP expects, it asks for a single-use grant from
          the expected digest to the new one (24 hours). ACP advances the baseline when a
          snapshot reports the new digest. Nothing is sent without --apply.

Owner credentials come from the macOS Keychain service "ACP Gateway Production"
(ACP_POLICY_SIGNING_KEY, ACP_POLICY_ADMIN_TOKEN, ACP_GATEWAY_TOKEN). They are read into
memory, never printed and never written to disk. Agents do not run this: it is the
operator path that the gateway bearer cannot reach.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent.parent
PROJECT = "prj_DDyafzBJvYfVi85dFzgEYxosxDMn"
TEAM = "team_8mC0mXDMIpioyO8cMRjLwb4H"
GATEWAY = os.environ.get("ACP_GATEWAY_URL", "https://acp-gateway.vercel.app").rstrip("/")
KEYCHAIN_SERVICE = "ACP Gateway Production"
KEY_ID = "acp-policy-hmac-sha256"
POLICY_FILE = HERE / "policies/production.json"


def keychain(account: str) -> str:
    out = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        raise SystemExit(f"error: Keychain has no {account} under {KEYCHAIN_SERVICE!r}")
    return out.stdout.strip()


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def vercel_api(path: str, method: str = "GET", body: dict | None = None) -> dict:
    cmd = ["vercel", "api", f"{path}{'&' if '?' in path else '?'}teamId={TEAM}", "--raw"]
    if method != "GET":
        cmd += ["-X", method, "--input", "-"]
    result = subprocess.run(cmd, cwd=HERE, input=json.dumps(body) if body is not None else None,
                            capture_output=True, text=True)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise SystemExit(f"error: Vercel API {method} {path} returned no JSON (exit {result.returncode}); "
                         "run `vercel login` and retry")
    if isinstance(data, dict) and data.get("error"):
        raise SystemExit(f"error: Vercel API {method} {path}: {data['error'].get('message', data['error'])}")
    return data


def gateway_call(path: str, bearer: str, admin: str | None = None, body: dict | None = None) -> dict:
    headers = {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"}
    if admin:
        headers["X-ACP-Admin-Authorization"] = f"Bearer {admin}"
    request = urllib.request.Request(GATEWAY + path, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc)
        except ValueError:
            detail = {}
        raise SystemExit(f"error: {path} answered {exc.code} {detail.get('error', '')}: "
                         f"{detail.get('detail', '')} {detail.get('remedy', '')}".rstrip())


def load_register_policy():
    os.environ.setdefault("ACP_GATEWAY_TOKEN", "policy-admin-offline")
    sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location("register_policy", HERE / "scripts/register-policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def production_policy_env() -> tuple[dict, list]:
    envs = vercel_api(f"/v10/projects/{PROJECT}/env")["envs"]
    entry = next((e for e in envs if e["key"] == "ACP_POLICY" and e.get("target") == ["production"]), None)
    if entry is None:
        raise SystemExit("error: production ACP_POLICY is not set on Vercel")
    value = vercel_api(f"/v1/projects/{PROJECT}/env/{entry['id']}")["value"]
    return entry, json.loads(value)


def cmd_register(args) -> int:
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    entry, document = production_policy_env()
    existing = document["policies"] if isinstance(document, dict) else document
    try:
        states = rp.validate(document, key, KEY_ID)
        bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    except ValueError as exc:
        bad = str(exc)
    if bad:
        raise SystemExit(f"error: the Keychain signing key (fingerprint {fingerprint(key)}) does not verify "
                         f"production's policies: {bad}. Nothing was changed.")
    print(f"signing key {fingerprint(key)} verifies all {len(states)} production policies")

    merged = list(existing)
    for spec in args.repositories:
        owner, _, name = spec.partition("/")
        if not owner or not name:
            raise SystemExit(f"error: repositories are OWNER/NAME, not {spec!r}")
        policy = rp.build_policy(argparse.Namespace(source=None, owner=owner, name=name, remote=None,
                                                    policy_id=None, board=args.board, actions=None))
        merged, replaced = rp.merge(merged, policy)
        merged[-1] = rp.sign(merged[-1], key, KEY_ID)
        print(f"{'replace' if replaced else 'add'} {merged[-1]['policy_id']} v{merged[-1]['version']} "
              f"for {owner}/{name}")
    updated = {**document, "policies": merged} if isinstance(document, dict) else merged
    try:
        states = rp.validate(updated, key, KEY_ID)
        bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    except ValueError as exc:
        bad = str(exc)
    if bad:
        raise SystemExit(f"error: the new document does not load cleanly: {bad}. Nothing was changed.")
    print(f"the gateway loader accepts all {len(states)} policies")
    if not args.apply:
        print("dry run: pass --apply to write ACP_POLICY on Vercel and policies/production.json")
        return 0
    text = json.dumps(updated, separators=(",", ":"), sort_keys=True)
    vercel_api(f"/v9/projects/{PROJECT}/env/{entry['id']}", "PATCH", {"value": text})
    POLICY_FILE.write_text(text + "\n", encoding="utf-8")
    print("wrote production ACP_POLICY on Vercel and policies/production.json; "
          "the next production deployment loads it")
    return 0


def git(checkout: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(checkout), *args], capture_output=True)


def cmd_grant(args) -> int:
    owner, _, name = args.repository.partition("/")
    checkout = Path(args.checkout).expanduser().resolve()
    head = git(checkout, "rev-parse", "HEAD").stdout.decode().strip()
    if not head:
        raise SystemExit(f"error: {checkout} is not a Git checkout")
    bearer, admin = keychain("ACP_GATEWAY_TOKEN"), keychain("ACP_POLICY_ADMIN_TOKEN")
    _, document = production_policy_env()
    policies = document["policies"] if isinstance(document, dict) else document
    policy = next((p for p in policies if (p.get("repository") or {}).get("owner", "").lower() == owner.lower()
                   and (p.get("repository") or {}).get("name", "").lower() == name.lower()), None)
    if policy is None:
        raise SystemExit(f"error: no production policy governs {owner}/{name}")
    pinned = (policy.get("artifact_manifest") or {}).get("artifacts") or []
    if not pinned:
        print(f"{owner}/{name} pins no artifacts; nothing to grant")
        return 0
    # What ACP expects now: the signed pin, unless an earlier grant advanced it.
    view = gateway_call(f"/internal/security/integrity?owner={owner}&name={name}", bearer, admin)
    overrides = view.get("baseline_overrides") or {}
    changes = []
    for item in pinned:
        path = item["path"]
        expected = (overrides.get(path) or {}).get("sha256") or item.get("expected_sha256")
        shown = git(checkout, "show", f"{head}:{path}")
        new = hashlib.sha256(shown.stdout).hexdigest() if shown.returncode == 0 else None
        if new and new != expected:
            changes.append((path, expected, new))
    print(f"{owner}/{name} at {head[:7]}: {len(changes)} pinned artifact(s) change")
    for path, old, new in changes:
        print(f"  {path}: {(old or 'none')[:12]} -> {new[:12]}")
    if not args.apply:
        print("dry run: pass --apply to request the grants")
        return 0
    for path, old, new in changes:
        body = {"action": "authorize_artifact_change", "resource": {"owner": owner, "name": name},
                "artifact": path, "authorized_new_sha256": new, "authorized_by": args.authorized_by,
                "reason": args.reason, "expires_in": 86400}
        if old:
            body["expected_old_sha256"] = old
        granted = gateway_call("/internal/recover", bearer, admin, body)
        print(f"  granted {path}: {(granted.get('artifact_change') or {}).get('authorization_id')}")
    print("done: the grants are consumed when the next snapshot reports these digests")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register", help="put repositories under an ACP policy")
    register.add_argument("repositories", nargs="+", metavar="OWNER/NAME")
    register.add_argument("--board", action="append", default=[], help="OWNER:NUMBER board to bind")
    register.add_argument("--apply", action="store_true")
    grant = sub.add_parser("grant", help="authorize a checkout's pinned-artifact changes")
    grant.add_argument("repository", metavar="OWNER/NAME")
    grant.add_argument("--checkout", required=True, help="local checkout whose HEAD is the new state")
    grant.add_argument("--authorized-by", default="repository owner")
    grant.add_argument("--reason", default="formal-project-bootstrap client upgrade")
    grant.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not (HERE / "gateway.py").exists():
        raise SystemExit("error: run this from an acp-gateway checkout")
    return cmd_register(args) if args.command == "register" else cmd_grant(args)


if __name__ == "__main__":
    raise SystemExit(main())
