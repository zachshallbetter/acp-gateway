#!/usr/bin/env python3
"""policy-admin.py -- the owner's policy and baseline changes for the Vercel deployment.

    .venv/bin/python scripts/policy-admin.py register OWNER/NAME [OWNER/NAME ...] [--apply]
    .venv/bin/python scripts/policy-admin.py grant OWNER/NAME --checkout DIR [--ref REF] [--apply]
    .venv/bin/python scripts/policy-admin.py repin OWNER/NAME --checkout DIR [--ref REF] [--apply]
    .venv/bin/python scripts/policy-admin.py unregister OWNER/NAME [--apply]
    .venv/bin/python scripts/policy-admin.py meter OWNER/NAME [--vercel PRJ ... [--vercel-team TEAM]] [--railway-project ID
                     [--railway-service ID ...]] [--production-branch B] [--protect ACTION] [--apply]
    .venv/bin/python scripts/policy-admin.py budget-policy [--limits FILE] [--apply]
    .venv/bin/python scripts/policy-admin.py budget-grant --action A [--repo OWNER/NAME] --uses N
                     --expires 2h --reason TEXT [--apply]
    .venv/bin/python scripts/policy-admin.py caller CALLER_ID --kind lane|coordinator --repo OWNER/NAME|OWNER/*
                     [--repo ...] [--apply]

register  puts repositories under an ACP policy. It reads production's ACP_POLICY from
          Vercel, checks that the Keychain signing key reproduces every existing signature,
          adds or replaces one policy per repository (default protected actions, no pinned
          artifacts), signs it, loads the whole document with the gateway's own loader, and
          only with --apply writes ACP_POLICY on Vercel and policies/production.json here.
          The new policy takes effect on the next production deployment.

grant     authorizes the pinned-artifact changes a checkout's REF (default HEAD) makes for a governed
          repository whose policy has an artifact manifest. For every protected path whose
          content at HEAD differs from what ACP expects, it asks for a single-use grant from
          the expected digest to the new one (24 hours). ACP advances the baseline when a
          snapshot reports the new digest. Nothing is sent without --apply.

repin     rewrites a pinned policy for a project that moved to the contained layout
          (bootstrap 0.7): each pinned path is mapped to its new location and re-pinned at
          the digest REF has there; the policy is signed as version+1.

unregister removes a repository's policy, so ACP stops governing it.

meter     turns on metered actions (hosted_build, production_merge, manual_ci) for a governed
          repository and names its Vercel projects and Railway service, signed as version+1.

budget-policy signs the deployment-wide limits (defaults: 20 hosted builds per repository and 60
          in all per day, Vercel 40 / Railway 10 / Actions 30, 5 production merges per repository,
          10 manual CI runs, 6 heavy subagents per session) and writes ACP_BUDGET_POLICY.

budget-grant lets an action through past a budget or for production: a bounded number of uses
          for a bounded time, for one repository or deployment-wide. It needs the admin credential
          and takes effect at once; no deployment is needed.

caller    issues a per-caller credential for a lane or a coordinator: a new token goes into the
          Keychain under ACP_GATEWAY_TOKEN_<CALLER_ID>, and only its SHA-256 goes into the signed
          ACP_CALLERS. The token is never printed.

Every write goes to both production hosts: Vercel (loaded on its next production deployment)
and Railway (which restarts and loads it). If Railway refuses after Vercel accepted, the
command fails and prints how to finish, because the hosts would otherwise differ.

Owner credentials (ACP_POLICY_SIGNING_KEY, ACP_POLICY_ADMIN_TOKEN, ACP_GATEWAY_TOKEN) come from the
environment, as `latchkey run --env-file .env.local -- ...` supplies them, else the macOS Keychain
service "ACP Gateway Production". They are read into memory, never printed and never written to disk. Agents do not run this: it is the
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
# The second production host. Every signed document ACP loads goes to both, or the hosts drift.
RAILWAY_PROJECT = "a3dbbfc5-3fe7-4365-a754-9a7856766f05"
RAILWAY_SERVICE = "b2f28e52-a113-41c5-b29f-6dcb6a54d3aa"
RAILWAY_ENVIRONMENT = "dac18c6b-a1ce-485b-b3a4-a8949dc5ad6e"
RAILWAY_URL = "https://acp-gateway-production.up.railway.app"


def keychain(account: str) -> str:
    """An owner credential: the environment variable of that name (`latchkey run`), else the Keychain."""
    value = os.environ.get(account, "").strip()
    if value.startswith("latchkey://"):
        raise SystemExit(f"error: {account} is a Latchkey reference, not a value; run this under "
                         "latchkey run --env-file .env.local -- ...")
    if value:
        return value
    out = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        raise SystemExit(f"error: {account} is neither in the environment nor in the Keychain under "
                         f"{KEYCHAIN_SERVICE!r}; run this under latchkey run --env-file .env.local -- ...")
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


def gateway_call_at(base: str, path: str, bearer: str) -> dict:
    """GET one route on a named gateway host (the second production host, for drift checks)."""
    global GATEWAY
    saved, GATEWAY = GATEWAY, base.rstrip("/")
    try:
        return gateway_call(path, bearer)
    finally:
        GATEWAY = saved


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

    merged, changed = list(existing), False
    for spec in args.repositories:
        owner, _, name = spec.partition("/")
        if not owner or not name:
            raise SystemExit(f"error: repositories are OWNER/NAME, not {spec!r}")
        policy = rp.build_policy(argparse.Namespace(source=None, owner=owner, name=name, remote=None,
                                                    policy_id=None, board=args.board, actions=None))
        current = next((e for e in merged if isinstance(e, dict) and rp.same_repository(e, policy)), None)
        if current is not None and all(current.get(field) == policy.get(field)
                                       for field in ("status", "repository", "protected_actions")) \
                and (not args.board or current.get("boards") == policy.get("boards")):
            print(f"unchanged {current['policy_id']} v{current['version']} for {owner}/{name}")
            continue
        merged, replaced = rp.merge(merged, policy)
        merged[-1] = rp.sign(merged[-1], key, KEY_ID)
        changed = True
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
    if not changed:
        print("nothing to change")
        return 0
    if not args.apply:
        print("dry run: pass --apply to write ACP_POLICY on Vercel, Railway and policies/production.json")
        return 0
    write_document(entry, updated)
    return 0


# Pinned paths in the legacy layout and where bootstrap 0.7 moved them.
CONTAINED_PATHS = {
    "NEW_AGENT_PROMPT.md": ".agents/bootstrap/NEW_AGENT_PROMPT.md",
    "PROJECT_PROFILE.json": ".agents/project/profile.json",
    "PROJECT_INTENT.md": ".agents/project/intent.md",
    "bindings/PROJECT_BINDINGS.yaml": ".agents/project/bindings.yaml",
    "contracts/acp-protected-effects.yaml": ".agents/project/contracts/acp-protected-effects.yaml",
    "docs/ACP_INTEGRATION.md": ".agents/acp/README.md",
    "scripts/acp.py": ".agents/acp/lib/acp.py",
    "scripts/acp_endpoint_registry.py": ".agents/acp/lib/acp_endpoint_registry.py",
    "scripts/acp_override.py": ".agents/acp/lib/acp_override.py",
    "scripts/acp-check.py": ".agents/acp/lib/acp-check.py",
    "schemas/acp-endpoint-registry.schema.json": ".agents/acp/schemas/acp-endpoint-registry.schema.json",
    "scripts/upgrade-project.py": ".agents/bootstrap/scripts/upgrade-project.py",
    "scripts/reconcile-project.py": ".agents/bootstrap/scripts/reconcile-project.py",
    "records/deviations.jsonl": ".agents/records/deviations.jsonl",
}


def find_policy(policies, owner, name):
    return next((p for p in policies if (p.get("repository") or {}).get("owner", "").lower() == owner.lower()
                 and (p.get("repository") or {}).get("name", "").lower() == name.lower()), None)


def git(checkout: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(checkout), *args], capture_output=True)


def cmd_grant(args) -> int:
    owner, _, name = args.repository.partition("/")
    checkout = Path(args.checkout).expanduser().resolve()
    head = git(checkout, "rev-parse", "--verify", f"{args.ref}^{{commit}}").stdout.decode().strip()
    if not head:
        raise SystemExit(f"error: {args.ref} is not a commit in {checkout}")
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
    gateway = load_register_policy().gateway
    changes, released = [], []
    for item in pinned:
        path = item["path"]
        expected = (overrides.get(path) or {}).get("sha256") or item.get("expected_sha256")
        shown = git(checkout, "show", f"{head}:{path}")
        new = hashlib.sha256(shown.stdout).hexdigest() if shown.returncode == 0 else None
        if new and new != expected:
            version = gateway.released_client_version(path, new)
            if version:
                released.append((path, version))
            else:
                changes.append((path, expected, new))
    for path, version in released:
        print(f"  {path}: bootstrap {version} client file, accepted without a grant")
    print(f"{owner}/{name} at {head[:7]}: {len(changes)} pinned artifact(s) need a grant")
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


def cmd_repin(args) -> int:
    rp = load_register_policy()
    owner, _, name = args.repository.partition("/")
    checkout = Path(args.checkout).expanduser().resolve()
    head = git(checkout, "rev-parse", "--verify", f"{args.ref}^{{commit}}").stdout.decode().strip()
    if not head:
        raise SystemExit(f"error: {args.ref} is not a commit in {checkout}")
    key = keychain("ACP_POLICY_SIGNING_KEY")
    entry, document = production_policy_env()
    policies = list(document["policies"] if isinstance(document, dict) else document)
    policy = find_policy(policies, owner, name)
    if policy is None:
        raise SystemExit(f"error: no production policy governs {owner}/{name}")
    manifest = policy.get("artifact_manifest") or {}
    if not manifest.get("artifacts"):
        print(f"{owner}/{name} pins no artifacts; nothing to repin")
        return 0
    changed = []
    artifacts = []
    for item in manifest["artifacts"]:
        path = CONTAINED_PATHS.get(item["path"], item["path"])
        shown = git(checkout, "show", f"{head}:{path}")
        digest = hashlib.sha256(shown.stdout).hexdigest() if shown.returncode == 0 else None
        if digest is None:
            print(f"  {item['path']}: not present at {head[:7]} as {path}; dropped from the manifest")
            changed.append(item["path"])
            continue
        updated = {**item, "path": path, "id": path.replace("/", "-").lower(), "expected_sha256": digest}
        if updated != item:
            changed.append(item["path"])
            print(f"  {item['path']} -> {path} @ {digest[:12]}")
        artifacts.append(updated)
    patterns = [{**pattern, "pattern": CONTAINED_PATHS.get(pattern["pattern"], pattern["pattern"])}
                for pattern in manifest.get("patterns") or []]
    if not changed and patterns == (manifest.get("patterns") or []):
        print(f"{owner}/{name} is already pinned at {head[:7]}")
        return 0
    repinned = {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id", "sha256")}
    repinned["artifact_manifest"] = {**manifest, "artifacts": artifacts, "patterns": patterns}
    repinned["version"] = int(policy.get("version") or 1) + 1
    repinned = rp.sign(repinned, key, KEY_ID)
    policies = [repinned if p is policy else p for p in policies]
    updated = {**document, "policies": policies} if isinstance(document, dict) else policies
    try:
        states = rp.validate(updated, key, KEY_ID)
        bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    except ValueError as exc:
        bad = str(exc)
    if bad:
        raise SystemExit(f"error: the repinned document does not load cleanly: {bad}. Nothing was changed.")
    print(f"{repinned['policy_id']} v{repinned['version']}: {len(changed)} pinned path(s) updated; "
          f"the gateway loader accepts all {len(states)} policies")
    if not args.apply:
        print("dry run: pass --apply to write it")
        return 0
    write_document(entry, updated)
    return 0


def cmd_unregister(args) -> int:
    rp = load_register_policy()
    owner, _, name = args.repository.partition("/")
    key = keychain("ACP_POLICY_SIGNING_KEY")
    entry, document = production_policy_env()
    policies = list(document["policies"] if isinstance(document, dict) else document)
    policy = find_policy(policies, owner, name)
    if policy is None:
        print(f"no production policy governs {owner}/{name}; nothing to remove")
        return 0
    remaining = [p for p in policies if p is not policy]
    updated = {**document, "policies": remaining} if isinstance(document, dict) else remaining
    try:
        states = rp.validate(updated, key, KEY_ID)
        bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    except ValueError as exc:
        bad = str(exc)
    if bad:
        raise SystemExit(f"error: the remaining policies do not load cleanly: {bad}. Nothing was changed.")
    print(f"remove {policy['policy_id']} v{policy.get('version')}; {len(states)} policies remain")
    if not args.apply:
        print("dry run: pass --apply to write it")
        return 0
    write_document(entry, updated)
    return 0


def env_entry(key: str):
    envs = vercel_api(f"/v10/projects/{PROJECT}/env")["envs"]
    return next((e for e in envs if e["key"] == key and e.get("target") == ["production"]), None)


def write_railway(key: str, text: str) -> None:
    """Set one variable on the Railway host from stdin, so the value never reaches a process list.

    Setting a variable restarts the Railway service, which then loads it.
    """
    result = subprocess.run(["railway", "variable", "set", key, "--stdin", "-p", RAILWAY_PROJECT,
                             "-s", RAILWAY_SERVICE, "-e", RAILWAY_ENVIRONMENT],
                            input=text, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"error: Vercel has the new {key} but Railway refused it, so the hosts now differ. "
                         f"Re-run this command, or set it by hand: railway variable set {key} --stdin "
                         f"-p {RAILWAY_PROJECT} -s {RAILWAY_SERVICE} -e {RAILWAY_ENVIRONMENT}")
    print(f"wrote {key} on Railway; the service restarts and loads it")


def write_env(key: str, text: str) -> None:
    """Create or replace one encrypted production variable on both hosts. Its value is never printed."""
    entry = env_entry(key)
    if entry is None:
        vercel_api(f"/v10/projects/{PROJECT}/env", "POST",
                   {"key": key, "value": text, "type": "encrypted", "target": ["production"]})
    else:
        vercel_api(f"/v9/projects/{PROJECT}/env/{entry['id']}", "PATCH", {"value": text})
    print(f"wrote production {key} on Vercel; the next production deployment loads it")
    write_railway(key, text)


def signed_document(document: dict, key: str, loader_variable: str, rp) -> dict:
    """Sign a deployment document and load it with the gateway's own loader before anything is written."""
    signed = rp.sign(document, key, KEY_ID)
    overrides = {loader_variable: json.dumps(signed), "ACP_POLICY_SIGNING_KEY": key}
    saved = {name: os.environ.get(name) for name in overrides}
    os.environ.update(overrides)
    try:
        loaded = rp.gateway.budget_policy() if loader_variable == "ACP_BUDGET_POLICY"             else rp.gateway.callers_registry()
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    if loaded.get("error"):
        raise SystemExit(f"error: the signed {loader_variable} does not load: {loaded['error']}. "
                         "Nothing was changed.")
    return signed


def current_env_document(key: str):
    entry = env_entry(key)
    if entry is None:
        return None
    return json.loads(vercel_api(f"/v1/projects/{PROJECT}/env/{entry['id']}")["value"])


def cmd_meter(args) -> int:
    rp = load_register_policy()
    owner, _, name = args.repository.partition("/")
    key = keychain("ACP_POLICY_SIGNING_KEY")
    entry, document = production_policy_env()
    policies = list(document["policies"] if isinstance(document, dict) else document)
    policy = find_policy(policies, owner, name)
    if policy is None:
        raise SystemExit(f"error: no production policy governs {owner}/{name}; register it first")
    providers = {}
    if args.vercel:
        providers["vercel"] = {"project_ids": args.vercel, **({"team_id": args.vercel_team} if args.vercel_team else {})}
    if args.railway_project:
        providers["railway"] = {"project_id": args.railway_project, "service_ids": args.railway_service}
    updated_policy = {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id")}
    actions = list(updated_policy.get("protected_actions") or rp.gateway.DEFAULT_PROTECTED_ACTIONS)
    for action in ("hosted_build", "production_merge", "manual_ci", *args.protect):
        if not rp.gateway.ACTION_RE.match(action):
            raise SystemExit(f"error: {action!r} is not an action name")
        if action not in actions:
            actions.append(action)
    updated_policy.update(protected_actions=sorted(actions), version=int(policy["version"]) + 1,
                          metered={"production_branches": args.production_branch or ["main"],
                                   "providers": providers})
    signed = rp.sign(updated_policy, key, KEY_ID)
    remaining = [signed if p is policy else p for p in policies]
    updated = {**document, "policies": remaining} if isinstance(document, dict) else remaining
    states = rp.validate(updated, key, KEY_ID)
    bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    if bad:
        raise SystemExit(f"error: the new document does not load cleanly: {bad}. Nothing was changed.")
    print(f"meter {signed['policy_id']} v{signed['version']} for {owner}/{name}: "
          f"providers {sorted(providers) or 'none (GitHub Actions only)'}")
    if not args.apply:
        print("dry run: pass --apply to write it")
        return 0
    write_document(entry, updated)
    return 0


def cmd_budget_policy(args) -> int:
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    limits = json.loads(Path(args.limits).read_text(encoding="utf-8")) if args.limits else {}
    current = current_env_document("ACP_BUDGET_POLICY")
    version = int((current or {}).get("version", 0)) + 1
    document = {"budget_policy_id": "acp-budgets", "version": version, "limits": limits}
    signed = signed_document(document, key, "ACP_BUDGET_POLICY", rp)
    effective = rp.gateway.metering.validated_limits(limits)
    print(f"budget policy acp-budgets v{version}: {json.dumps(effective, sort_keys=True)}")
    if not args.apply:
        print("dry run: pass --apply to write ACP_BUDGET_POLICY")
        return 0
    write_env("ACP_BUDGET_POLICY", json.dumps(signed, separators=(",", ":"), sort_keys=True))
    return 0


def _duration_minutes(text: str) -> int:
    unit = text[-1:]
    if not text[:-1].isdigit() or unit not in ("m", "h"):
        raise SystemExit("error: --expires is like 30m or 2h")
    return int(text[:-1]) * (60 if unit == "h" else 1)


def cmd_budget_grant(args) -> int:
    owner, _, name = (args.repo or "").partition("/")
    body = {"action": args.action, "uses": args.uses, "expires_minutes": _duration_minutes(args.expires),
            "reason": args.reason, "request_id": hashlib.sha256(
                f"{args.action}|{args.repo}|{args.uses}|{args.expires}|{args.reason}".encode()).hexdigest()[:32]}
    if args.repo:
        body.update(owner=owner, name=name)
    print(f"grant {args.action} for {args.repo or 'any repository'}: {args.uses} use(s), {args.expires}")
    if not args.apply:
        print("dry run: pass --apply to issue it")
        return 0
    result = gateway_call("/internal/budget/grant", keychain("ACP_GATEWAY_TOKEN"),
                          keychain("ACP_POLICY_ADMIN_TOKEN"), body)
    print(f"issued {result['grant_id']}, expires {result['expires_at']}")
    return 0


def cmd_caller(args) -> int:
    import secrets
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    current = current_env_document("ACP_CALLERS") or {"callers_id": "acp-callers", "version": 0, "callers": []}
    account = "ACP_GATEWAY_TOKEN_" + args.caller_id.upper().replace("-", "_").replace(".", "_")
    print(f"{args.kind} {args.caller_id} for {', '.join(args.repo)}; token in Keychain account {account}")
    if not args.apply:
        print("dry run: pass --apply to create the token and write ACP_CALLERS")
        return 0
    token = secrets.token_urlsafe(32)
    callers = [c for c in current["callers"] if c["caller_id"] != args.caller_id]
    callers.append({"caller_id": args.caller_id, "kind": args.kind, "repos": args.repo,
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest()})
    document = {"callers_id": "acp-callers", "version": int(current.get("version", 0)) + 1, "callers": callers}
    signed = signed_document(document, key, "ACP_CALLERS", rp)
    stored = subprocess.run(["security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", account,
                             "-w", token], capture_output=True, text=True)
    if stored.returncode != 0:
        raise SystemExit("error: could not store the token in the Keychain; nothing was written to Vercel")
    write_env("ACP_CALLERS", json.dumps(signed, separators=(",", ":"), sort_keys=True))
    print(f"the caller's client reads it with keychainAccount {account} in its endpoint registry")
    return 0


def write_document(entry: dict, document) -> None:
    text = json.dumps(document, separators=(",", ":"), sort_keys=True)
    vercel_api(f"/v9/projects/{PROJECT}/env/{entry['id']}", "PATCH", {"value": text})
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(text + "\n", encoding="utf-8")
    print("wrote production ACP_POLICY on Vercel and policies/production.json; "
          "the next production deployment loads it")
    write_railway("ACP_POLICY", text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    register = sub.add_parser("register", help="put repositories under an ACP policy")
    register.add_argument("repositories", nargs="+", metavar="OWNER/NAME")
    register.add_argument("--board", action="append", default=[], help="OWNER:NUMBER board to bind")
    register.add_argument("--apply", action="store_true")
    grant = sub.add_parser("grant", help="authorize a checkout's pinned-artifact changes")
    grant.add_argument("repository", metavar="OWNER/NAME")
    grant.add_argument("--checkout", required=True, help="local Git checkout holding the new state")
    grant.add_argument("--ref", default="HEAD", help="commit, branch or tag whose files are the new state")
    grant.add_argument("--authorized-by", default="repository owner")
    grant.add_argument("--reason", default="formal-project-bootstrap client upgrade")
    grant.add_argument("--apply", action="store_true")
    repin = sub.add_parser("repin", help="move a pinned policy to bootstrap 0.7's contained paths")
    repin.add_argument("repository", metavar="OWNER/NAME")
    repin.add_argument("--checkout", required=True)
    repin.add_argument("--ref", default="HEAD")
    repin.add_argument("--apply", action="store_true")
    unregister = sub.add_parser("unregister", help="remove a repository's policy")
    unregister.add_argument("repository", metavar="OWNER/NAME")
    unregister.add_argument("--apply", action="store_true")
    meter = sub.add_parser("meter", help="turn on metered actions for a governed repository")
    meter.add_argument("repository", metavar="OWNER/NAME")
    meter.add_argument("--vercel", action="append", default=[], metavar="PROJECT_ID")
    meter.add_argument("--vercel-team", metavar="TEAM_ID", help="the Vercel team the projects belong to")
    meter.add_argument("--railway-project")
    meter.add_argument("--railway-service", action="append", default=[])
    meter.add_argument("--production-branch", action="append", default=[])
    meter.add_argument("--protect", action="append", default=[], metavar="ACTION",
                       help="also list this action, e.g. database.migrate")
    meter.add_argument("--apply", action="store_true")
    budget = sub.add_parser("budget-policy", help="sign the deployment-wide limits")
    budget.add_argument("--limits", help="JSON file of limits overriding the defaults")
    budget.add_argument("--apply", action="store_true")
    bgrant = sub.add_parser("budget-grant", help="let an action through past a budget or for production")
    bgrant.add_argument("--action", required=True, choices=["hosted_build", "production_merge", "manual_ci",
                                                            "local_heavy_build", "heavy_subagent"])
    bgrant.add_argument("--repo", metavar="OWNER/NAME")
    bgrant.add_argument("--uses", type=int, default=1)
    bgrant.add_argument("--expires", default="2h")
    bgrant.add_argument("--reason", required=True)
    bgrant.add_argument("--apply", action="store_true")
    caller = sub.add_parser("caller", help="issue a lane or coordinator credential")
    caller.add_argument("caller_id")
    caller.add_argument("--kind", required=True, choices=["lane", "coordinator"])
    caller.add_argument("--repo", action="append", required=True, metavar="OWNER/NAME|OWNER/*")
    caller.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not (HERE / "gateway.py").exists():
        raise SystemExit("error: run this from an acp-gateway checkout")
    return {"register": cmd_register, "grant": cmd_grant, "repin": cmd_repin,
            "unregister": cmd_unregister, "meter": cmd_meter, "budget-policy": cmd_budget_policy,
            "budget-grant": cmd_budget_grant, "caller": cmd_caller}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
