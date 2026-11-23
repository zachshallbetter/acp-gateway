#!/usr/bin/env python3
"""policy-admin.py -- the owner's policy and baseline changes for the Vercel deployment.

    .venv/bin/python scripts/policy-admin.py enroll OWNER/NAME [OWNER/NAME ...] [--vercel PRJ ... --vercel-team TEAM]
                     [--railway-project ID --railway-service ID | --railway-map FILE] [--apply]
    .venv/bin/python scripts/policy-admin.py register OWNER/NAME [OWNER/NAME ...] [--apply]
    .venv/bin/python scripts/policy-admin.py grant OWNER/NAME --checkout DIR [--ref REF] [--apply]
    .venv/bin/python scripts/policy-admin.py repin OWNER/NAME --checkout DIR [--ref REF] [--apply]
    .venv/bin/python scripts/policy-admin.py unregister OWNER/NAME [--apply]
    .venv/bin/python scripts/policy-admin.py meter OWNER/NAME [--vercel PRJ ... [--vercel-team TEAM]] [--railway-project ID
                     [--railway-service ID ...]] [--production-branch B] [--protect ACTION] [--apply]
    .venv/bin/python scripts/policy-admin.py protect OWNER/NAME ACTION [--apply]
    .venv/bin/python scripts/policy-admin.py budget-policy [--limits FILE] [--apply]
    .venv/bin/python scripts/policy-admin.py budget-grant --action A [--repo OWNER/NAME] --uses N
                     --expires 2h --reason TEXT [--apply]
    .venv/bin/python scripts/policy-admin.py caller CALLER_ID --kind lane|coordinator --repo OWNER/NAME|OWNER/*
                     [--repo ...] [--apply]

enroll    is how a project joins ACP: it registers each repository that isn't governed yet and meters
          it with the Vercel projects linked to it on GitHub across every team the signed-in Vercel
          account belongs to (or the projects and Railway service named with --vercel/--railway-*,
          for a site deployed from the CLI), all as one stored version. --railway-map names Railway
          services for many repositories at once. A provider not named or discovered keeps what the
          policy already meters, and a repository whose providers don't change is left as it is.

register  puts repositories under an ACP policy. It reads production's ACP_POLICY from
          Vercel, checks that the Keychain signing key reproduces every existing signature,
          adds or replaces one policy per repository (default protected actions, no pinned
          artifacts), signs it, loads the whole document with the gateway's own loader, and
          only with --apply stores it in ACP and mirrors it to policies/production.json here.
          Both hosts load it within seconds.

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

protect   adds one protected action (for example database.migrate) to a governed repository's policy,
          signed as version+1, and keeps its metered block exactly as it is. `meter` instead replaces the
          providers with the ones named on its command line.

Dry runs print the protected-action and provider changes. An --apply whose signed content would not
change stores nothing and says so: a new version would invalidate decisions made under the current one.
Errors that name a fix print the exact command, with absolute paths and the Latchkey reference for the
signing key; ACP_GRANT_COMMAND_PREFIX, when set, replaces the runner in it.

budget-policy signs the deployment-wide limits (defaults: 20 hosted builds per repository and 60
          in all per day, Vercel 40 / Railway 10 / Actions 30, 5 production merges per repository,
          10 manual CI runs, 6 heavy subagents per session) and writes ACP_BUDGET_POLICY.

budget-grant lets an action through past a budget or for production: a bounded number of uses
          for a bounded time, for one repository or deployment-wide. It needs the admin credential
          and takes effect at once; no deployment is needed.

caller    issues a per-caller credential for a lane or a coordinator: a new token goes into the
          Keychain under ACP_GATEWAY_TOKEN_<CALLER_ID>, and only its SHA-256 goes into the signed
          ACP_CALLERS. The token is never printed.

Every write is one signed document stored in ACP's shared database through
POST /internal/documents (administrative credential). The gateway verifies it with its own key and
loaders before storing it, refuses a write signed on a stale version, and both production hosts load
the new version within ACP_DOCUMENT_TTL_SECONDS (default 15): no redeploy, no deployment variables.

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
import shlex
import shutil
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Unresolved secret references: Latchkey's scheme, and Pistachio's after the rename (zachshallbetter/latchkey#122).
SECRET_SCHEMES = ("latchkey://", "pistachio://")

HERE = Path(__file__).resolve().parent.parent
# The bearer and admin tokens go only to ACP's own hosts over TLS (a loopback host over http for local
# tests), and never follow a redirect: urllib would resend the Authorization header to wherever it points.
# A self-hosted deployment names its own hosts in ACP_GATEWAY_HOSTS (comma-separated).
GATEWAY_HOSTS = tuple(h.strip().lower() for h in os.environ.get(
    "ACP_GATEWAY_HOSTS", "acp-gateway.vercel.app,acp-gateway-production.up.railway.app").split(",") if h.strip())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"refused redirect to {newurl}", headers, fp)


urllib.request.install_opener(urllib.request.build_opener(_NoRedirect))


def checked_gateway(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    if not ((parts.scheme == "https" and host in GATEWAY_HOSTS)
            or (parts.scheme in ("http", "https") and host in ("localhost", "127.0.0.1", "::1"))):
        raise SystemExit(f"error: ACP_GATEWAY_URL must be https:// on one of ACP_GATEWAY_HOSTS ({', '.join(GATEWAY_HOSTS)}) "
                         f"or a loopback host; refusing to send a token to {host or url!r}")
    return url.rstrip("/")


GATEWAY = checked_gateway(os.environ.get("ACP_GATEWAY_URL", f"https://{GATEWAY_HOSTS[0]}" if GATEWAY_HOSTS else ""))
KEYCHAIN_SERVICE = os.environ.get("ACP_KEYCHAIN_SERVICE", "ACP Gateway Production")
KEY_ID = "acp-policy-hmac-sha256"
POLICY_FILE = HERE / "policies/production.json"
# The second production host. Every signed document ACP loads goes to both, or the hosts drift.
# The second host whose policies posture-report compares (ACP_RAILWAY_URL); unset when a deployment has one host.
_RAILWAY_DEFAULT = "https://acp-gateway-production.up.railway.app"
RAILWAY_URL = (checked_gateway(os.environ["ACP_RAILWAY_URL"]) if os.environ.get("ACP_RAILWAY_URL")
               else _RAILWAY_DEFAULT if "acp-gateway-production.up.railway.app" in GATEWAY_HOSTS else None)


def owner_command(argv: list | None = None) -> str:
    """The command that works for the owner: this invocation (`argv`, default what was typed) run from any folder,
    with absolute paths and the Latchkey reference for the signing key, which .env.local does not hold. A
    deployment's ACP_GRANT_COMMAND_PREFIX, the way its operator runs this script, replaces the whole runner."""
    rest = shlex.join(sys.argv[1:] if argv is None else argv)
    prefix = os.environ.get("ACP_GRANT_COMMAND_PREFIX", "").strip()
    if prefix:
        return f"{prefix} {rest}".rstrip()
    return ("ACP_POLICY_SIGNING_KEY=latchkey://ACP_POLICY_SIGNING_KEY latchkey run --env-file "
            f"{shlex.quote(str(HERE / '.env.local'))} -- {shlex.quote(str(HERE / '.venv/bin/python'))} "
            f"{shlex.quote(str(HERE / 'scripts/policy-admin.py'))} {rest}").rstrip()


def keychain(account: str) -> str:
    """An owner credential: the environment variable of that name (`latchkey run`), else the Keychain."""
    value = os.environ.get(account, "").strip()
    if value.startswith(SECRET_SCHEMES):
        raise SystemExit(f"error: {account} is a Latchkey reference, not a value; run exactly: {owner_command()}")
    if value:
        return value
    if not shutil.which("security"):                      # not macOS: the environment is the only source
        raise SystemExit(f"error: {account} is not set in the environment (no macOS Keychain on this system)")
    out = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
                         capture_output=True, text=True)
    if out.returncode != 0 or not out.stdout.strip():
        raise SystemExit(f"error: {account} is neither in the environment nor in the Keychain under "
                         f"{KEYCHAIN_SERVICE!r}; run exactly: {owner_command()}")
    return out.stdout.strip()


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8]


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


def read_document(name: str) -> tuple[int, object]:
    """(stored version, document) of one signed document as ACP holds it; version 0 means the deployment
    variable that seeds it, before the first stored version."""
    view = gateway_call(f"/internal/documents/{name}", keychain("ACP_GATEWAY_TOKEN"), keychain("ACP_POLICY_ADMIN_TOKEN"))
    return int(view["version"]), view["document"]


def write_signed(name: str, version: int, document) -> dict:
    """Store the next version of a signed document, signed on `version`. Both hosts load it within seconds."""
    stored = gateway_call("/internal/documents", keychain("ACP_GATEWAY_TOKEN"), keychain("ACP_POLICY_ADMIN_TOKEN"),
                          {"name": name, "expected_version": version, "document": document})
    print(f"stored {name} v{stored['version']} in ACP; both hosts load it within seconds")
    return stored


def production_policy() -> tuple[int, object]:
    version, document = read_document("policy")
    if document is None:
        raise SystemExit("error: ACP holds no policy document yet")
    return version, document


def cmd_register(args) -> int:
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    version, document = production_policy()
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
        print("dry run: pass --apply to store it in ACP and mirror it to policies/production.json")
        return 0
    write_document(version, updated)
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
    _, document = production_policy()
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
    version, document = production_policy()
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
    write_document(version, updated)
    return 0


def cmd_unregister(args) -> int:
    rp = load_register_policy()
    owner, _, name = args.repository.partition("/")
    key = keychain("ACP_POLICY_SIGNING_KEY")
    version, document = production_policy()
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
    write_document(version, updated)
    return 0


def signed_document(document: dict, key: str, name: str, rp) -> dict:
    """Sign a callers or budget document and verify it with the gateway's own check before anything is sent."""
    signed = rp.sign(document, key, KEY_ID)
    saved = os.environ.get("ACP_POLICY_SIGNING_KEY")
    os.environ["ACP_POLICY_SIGNING_KEY"] = key
    try:
        error = rp.gateway.document_errors(name, json.dumps(signed, separators=(",", ":"), sort_keys=True))
    finally:
        if saved is None:
            os.environ.pop("ACP_POLICY_SIGNING_KEY", None)
        else:
            os.environ["ACP_POLICY_SIGNING_KEY"] = saved
    if error:
        raise SystemExit(f"error: the signed {name} document does not verify: {error}. Nothing was changed.")
    return signed


def _unsigned(policy: dict) -> dict:
    """A policy's content: everything the signature covers except the version the write bumps."""
    return {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id", "sha256", "version")}


def change_lines(old: dict, new: dict) -> list:
    """What a policy write changes: protected actions and metered providers, one line each."""
    lines = []
    before, after = set(old.get("protected_actions") or []), set(new.get("protected_actions") or [])
    if before != after:
        lines.append("  protected actions: " + " ".join([f"+{a}" for a in sorted(after - before)]
                                                         + [f"-{a}" for a in sorted(before - after)]))
    old_meter, new_meter = old.get("metered") or {}, new.get("metered") or {}
    if old_meter.get("production_branches") != new_meter.get("production_branches"):
        lines.append(f"  production branches: {old_meter.get('production_branches')} -> "
                     f"{new_meter.get('production_branches')}")
    old_providers, new_providers = old_meter.get("providers") or {}, new_meter.get("providers") or {}
    for provider in sorted(set(old_providers) | set(new_providers)):
        if old_providers.get(provider) != new_providers.get(provider):
            lines.append(f"  provider {provider}: {json.dumps(old_providers.get(provider), sort_keys=True)} -> "
                         f"{json.dumps(new_providers.get(provider), sort_keys=True)}")
    return lines


def report_change(old: dict, new: dict) -> bool:
    """Print the change from `old` to the signed `new`; True when its signed content differs."""
    changed = _unsigned(old) != _unsigned(new)
    for line in change_lines(old, new) if changed else []:
        print(line)
    return changed


def refuse_unchanged(apply: bool) -> int:
    """Nothing changed: a stored copy would only be a new version that invalidates decisions made under the last."""
    if apply:
        raise SystemExit("error: the signed content would not change, so nothing was stored; a new version would "
                         "invalidate decisions made under the current one")
    print("nothing to change")
    return 0


def cmd_meter(args) -> int:
    rp = load_register_policy()
    owner, _, name = args.repository.partition("/")
    key = keychain("ACP_POLICY_SIGNING_KEY")
    version, document = production_policy()
    policies = list(document["policies"] if isinstance(document, dict) else document)
    policy = find_policy(policies, owner, name)
    if policy is None:
        raise SystemExit(f"error: no production policy governs {owner}/{name}; register it first")
    providers = explicit_providers(args)
    signed = metered_policy(policy, providers, args.production_branch, args.protect, rp, key)
    remaining = [signed if p is policy else p for p in policies]
    updated = {**document, "policies": remaining} if isinstance(document, dict) else remaining
    states = rp.validate(updated, key, KEY_ID)
    bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    if bad:
        raise SystemExit(f"error: the new document does not load cleanly: {bad}. Nothing was changed.")
    print(f"meter {signed['policy_id']} v{signed['version']} for {owner}/{name}: "
          f"providers {sorted(providers) or 'none (GitHub Actions only)'}")
    if not report_change(policy, signed):
        return refuse_unchanged(args.apply)
    if not args.apply:
        print("dry run: pass --apply to write it")
        return 0
    write_document(version, updated)
    return 0


def cmd_protect(args) -> int:
    """Add one protected action to a governed repository's policy; its metered block stays as it is."""
    rp = load_register_policy()
    owner, _, name = args.repository.partition("/")
    if not owner or not name:
        raise SystemExit(f"error: repositories are OWNER/NAME, not {args.repository!r}")
    if not rp.gateway.ACTION_RE.match(args.action):
        raise SystemExit(f"error: {args.action!r} is not an action name")
    key = keychain("ACP_POLICY_SIGNING_KEY")
    version, document = production_policy()
    policies = list(document["policies"] if isinstance(document, dict) else document)
    policy = find_policy(policies, owner, name)
    if policy is None:
        raise SystemExit(f"error: no production policy governs {owner}/{name}; register it first")
    actions = list(policy.get("protected_actions") or rp.gateway.DEFAULT_PROTECTED_ACTIONS)
    if args.action not in actions:
        actions = sorted([*actions, args.action])
    updated_policy = {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id")}
    updated_policy.update(protected_actions=actions, version=int(policy["version"]) + 1)
    signed = rp.sign(updated_policy, key, KEY_ID)
    remaining = [signed if p is policy else p for p in policies]
    updated = {**document, "policies": remaining} if isinstance(document, dict) else remaining
    states = rp.validate(updated, key, KEY_ID)
    bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    if bad:
        raise SystemExit(f"error: the new document does not load cleanly: {bad}. Nothing was changed.")
    print(f"protect {signed['policy_id']} v{signed['version']} for {owner}/{name}: {args.action}")
    if not report_change(policy, signed):
        return refuse_unchanged(args.apply)
    if not args.apply:
        print("dry run: pass --apply to write it")
        return 0
    write_document(version, updated)
    return 0


def explicit_providers(args) -> dict:
    providers = {}
    if args.vercel:
        providers["vercel"] = {"project_ids": args.vercel, **({"team_id": args.vercel_team} if args.vercel_team else {})}
    if args.railway_project:
        providers["railway"] = {"project_id": args.railway_project, "service_ids": args.railway_service}
    return providers


def metered_policy(policy: dict, providers: dict, branches: list, protect: list, rp, key: str) -> dict:
    """The policy at version+1 with metered actions on and these providers named, signed."""
    updated = {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id")}
    actions = list(updated.get("protected_actions") or rp.gateway.DEFAULT_PROTECTED_ACTIONS)
    for action in ("hosted_build", "production_merge", "manual_ci", *protect):
        if not rp.gateway.ACTION_RE.match(action):
            raise SystemExit(f"error: {action!r} is not an action name")
        if action not in actions:
            actions.append(action)
    updated.update(protected_actions=sorted(actions), version=int(policy["version"]) + 1,
                   metered={"production_branches": branches or ["main"], "providers": providers})
    return rp.sign(updated, key, KEY_ID)


def vercel_json(*args: str) -> dict:
    """One read-only Vercel CLI call that prints JSON. The CLI may print a hint line first; it is skipped."""
    result = subprocess.run(["vercel", *args], capture_output=True, text=True, cwd=HERE)
    text = result.stdout
    try:
        return json.loads(text[text.index("{"):])
    except ValueError:
        raise SystemExit(f"error: `vercel {args[0]}` returned no JSON; run `vercel login` and retry")


def vercel_get(path: str) -> dict:
    """One read-only Vercel API call through the signed-in CLI. The path names its team (teamId)."""
    return vercel_json("api", path, "--raw")


def vercel_projects_by_repo() -> dict:
    """{owner/name (lowercase): [(team id, project id), ...]} for every Vercel project linked to a GitHub repo,
    across every team the signed-in Vercel account belongs to."""
    found = {}
    teams = vercel_json("teams", "ls", "--format", "json").get("teams") or []
    for team in teams:
        until = None
        while True:
            page = vercel_get(f"/v9/projects?teamId={team['id']}&limit=100" + (f"&until={until}" if until else ""))
            for project in page.get("projects") or []:
                link = project.get("link") or {}
                if link.get("type") == "github" and link.get("org") and link.get("repo"):
                    found.setdefault(f"{link['org']}/{link['repo']}".lower(), []).append((team["id"], project["id"]))
            until = (page.get("pagination") or {}).get("next")
            if not until:
                break
    return found


def cmd_enroll(args) -> int:
    """Register each repository (when it isn't yet) and meter it with the providers that build it, in one write."""
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    version, document = production_policy()
    policies = list(document["policies"] if isinstance(document, dict) else document)
    states = rp.validate(policies, key, KEY_ID)
    bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    if bad:
        raise SystemExit(f"error: the signing key (fingerprint {fingerprint(key)}) does not verify ACP's policies: "
                         f"{bad}. Nothing was changed.")
    explicit = explicit_providers(args)
    if explicit and len(args.repositories) != 1:
        raise SystemExit("error: --vercel and --railway-* name one repository's projects; enroll it on its own, "
                         "or name Railway services for many with --railway-map")
    railway_map = {}
    if args.railway_map:
        raw = json.loads(Path(args.railway_map).read_text(encoding="utf-8"))
        railway_map = {repo.lower(): block for repo, block in raw.items()}
    linked = {} if "vercel" in explicit else vercel_projects_by_repo()
    changed = False
    for spec in args.repositories:
        owner, _, name = spec.partition("/")
        if not owner or not name:
            raise SystemExit(f"error: repositories are OWNER/NAME, not {spec!r}")
        policy = find_policy(policies, owner, name)
        if policy is None:
            built = rp.build_policy(argparse.Namespace(source=None, owner=owner, name=name, remote=None,
                                                       policy_id=None, board=[], actions=None))
            policies, _ = rp.merge(policies, rp.sign(built, key, KEY_ID))
            policy = policies[-1]
        current = (policy.get("metered") or {}).get("providers") or {}
        providers = {}
        # Each provider: named on the command line, else discovered (Vercel) or mapped (Railway), else what the
        # policy already names, so a site deployed from the CLI keeps the project it was metered with.
        if "vercel" in explicit:
            providers["vercel"] = explicit["vercel"]
        else:
            projects = linked.get(spec.lower(), [])
            teams = sorted({team for team, _ in projects}, key=lambda t: -sum(1 for x, _ in projects if x == t))
            if teams:
                providers["vercel"] = {"project_ids": sorted(p for t, p in projects if t == teams[0])[:10],
                                       "team_id": teams[0]}
                if len(teams) > 1:
                    print(f"note: {spec} has Vercel projects in {len(teams)} teams; metering those in {teams[0]}")
            elif current.get("vercel"):
                providers["vercel"] = current["vercel"]
        railway = explicit.get("railway") or railway_map.get(spec.lower()) or current.get("railway")
        if railway:
            providers["railway"] = {"project_id": railway["project_id"], "service_ids": sorted(railway["service_ids"])}
        if policy.get("metered") and providers == current and not args.production_branch:
            print(f"unchanged {policy['policy_id']} v{policy['version']} for {owner}/{name}")
            continue
        signed = metered_policy(policy, providers, args.production_branch or
                                (policy.get("metered") or {}).get("production_branches"), [], rp, key)
        policies = [signed if p is policy else p for p in policies]
        print(f"enroll {signed['policy_id']} v{signed['version']} for {owner}/{name}: "
              f"providers {sorted(providers) or 'none (GitHub Actions only)'}")
        changed = report_change(policy, signed) or changed
    updated = {**document, "policies": policies} if isinstance(document, dict) else policies
    states = rp.validate(updated, key, KEY_ID)
    bad = {pid: r["state"] for pid, r in states.items() if r["state"] != "ACTIVE"}
    if bad:
        raise SystemExit(f"error: the new document does not load cleanly: {bad}. Nothing was changed.")
    print(f"the gateway loader accepts all {len(states)} policies")
    if not changed:
        return refuse_unchanged(args.apply)
    if not args.apply:
        print("dry run: pass --apply to store it in ACP")
        return 0
    write_document(version, updated)
    if len(args.repositories) == 1:
        # The gateway loads the new document within seconds; show what it now sees for this repository.
        time.sleep(5)
        print_coverage(args.repositories[0])
    return 0


def cmd_budget_policy(args) -> int:
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    limits = json.loads(Path(args.limits).read_text(encoding="utf-8")) if args.limits else {}
    stored_version, current = read_document("budget")
    version = int((current or {}).get("version", 0)) + 1
    document = {"budget_policy_id": "acp-budgets", "version": version, "limits": limits}
    signed = signed_document(document, key, "budget", rp)
    effective = rp.gateway.metering.validated_limits(limits)
    print(f"budget policy acp-budgets v{version}: {json.dumps(effective, sort_keys=True)}")
    if not args.apply:
        print("dry run: pass --apply to store it in ACP")
        return 0
    write_signed("budget", stored_version, signed)
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
                f"{args.action}|{args.repo}|{args.uses}|{args.expires}|{args.reason}|{int(time.time()) // 600}"
                .encode()).hexdigest()[:32]}
    if args.repo:
        body.update(owner=owner, name=name)
    print(f"grant {args.action} for {args.repo or 'any repository'}: {args.uses} use(s), {args.expires}")
    if not args.apply:
        print("dry run: pass --apply to issue it")
        return 0
    result = gateway_call("/internal/budget/grant", keychain("ACP_GATEWAY_TOKEN"),
                          keychain("ACP_POLICY_ADMIN_TOKEN"), body)
    if result.get("existing"):
        print(f"already issued {result['grant_id']} ({result['uses_left']} of {result['uses']} use(s) left), "
              f"expires {result['expires_at']}")
    else:
        print(f"issued {result['grant_id']}, expires {result['expires_at']}")
    return 0


def cmd_caller(args) -> int:
    import secrets
    rp = load_register_policy()
    key = keychain("ACP_POLICY_SIGNING_KEY")
    stored_version, current = read_document("callers")
    current = current or {"callers_id": "acp-callers", "version": 0, "callers": []}
    account = "ACP_GATEWAY_TOKEN_" + args.caller_id.upper().replace("-", "_").replace(".", "_")
    token_file = getattr(args, "token_file", None)
    where = f"file {token_file}" if token_file else f"Keychain account {account}"
    if token_file and os.path.lexists(token_file):
        raise SystemExit(f"error: {token_file} already exists; name a new file for the token")
    print(f"{args.kind} {args.caller_id} for {', '.join(args.repo)}; token in {where}")
    if not args.apply:
        print("dry run: pass --apply to create the token and store the caller list in ACP")
        return 0
    token = secrets.token_urlsafe(32)
    callers = [c for c in current["callers"] if c["caller_id"] != args.caller_id]
    callers.append({"caller_id": args.caller_id, "kind": args.kind, "repos": args.repo,
                    "token_sha256": hashlib.sha256(token.encode()).hexdigest()})
    document = {"callers_id": "acp-callers", "version": int(current.get("version", 0)) + 1, "callers": callers}
    signed = signed_document(document, key, "callers", rp)
    if token_file:
        # A new file only the owner can read; O_EXCL refuses to follow a link or overwrite anything.
        fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")
        write_signed("callers", stored_version, signed)
        print(f"give the caller the token in {token_file} through its own secret store, then delete the file")
        return 0
    # The token goes to `security -i` on stdin, never on argv where `ps` would show it.
    quoted = [json.dumps(v) for v in (KEYCHAIN_SERVICE, account, token)]
    stored = subprocess.run(["security", "-i"], capture_output=True, text=True,
                            input=f"add-generic-password -U -s {quoted[0]} -a {quoted[1]} -w {quoted[2]}\n")
    # `security -i` can exit 0 when the command it read failed, so read the item back (on stdout, not argv).
    readback = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
                              capture_output=True, text=True)
    if stored.returncode != 0 or readback.returncode != 0 or readback.stdout.strip() != token:
        raise SystemExit("error: could not store the token in the Keychain; nothing was stored in ACP")
    write_signed("callers", stored_version, signed)
    print(f"the caller's client reads it with keychainAccount {account} in its endpoint registry")
    return 0


def print_coverage(repository: str | None = None) -> int:
    """The coverage audit from the gateway: every live Vercel project, metered or flagged with its fix."""
    query = ""
    if repository:
        owner, _, name = repository.partition("/")
        query = "?" + urllib.parse.urlencode({"owner": owner, "name": name})
    result = gateway_call("/internal/coverage" + query, keychain("ACP_GATEWAY_TOKEN"),
                          keychain("ACP_POLICY_ADMIN_TOKEN"))
    print("coverage: " + ", ".join(f"{count} {status.lower()}" for status, count in result["summary"].items() if count))
    teams = result.get("teams", [])
    print(f"teams: {sum(1 for t in teams if t['read'])} read of {len(teams)} the gateway knows")
    for team in teams:
        if not team["read"]:
            print(f"  NOT READ {team['slug'] or team['team_id']}: {team['reason']}")
    for row in result["projects"]:
        if row["status"] == "METERED":
            continue
        print(f"  {row['status']:<19} {row['name'] or row['project_id']:<32} "
              f"{row['linked_repository'] or row['metered_for'] or '(no repository)'}")
        if row.get("remedy"):
            print(f"      {row['remedy']}")
    for repo, command in sorted({(r["linked_repository"] or r["metered_for"], r["command"])
                                 for r in result["projects"] if r.get("command")}):
        print(f"  fix {repo}: {command}")
    for error in result["errors"]:
        print(f"  error reading {error['provider']} {error.get('team_id') or '(team list)'}: {error['detail']}")
    return 1 if any(r["status"] != "METERED" for r in result["projects"]) or result["errors"] else 0


def cmd_coverage(args) -> int:
    return print_coverage(args.repository)


def write_document(version: int, document) -> None:
    """Store the policy document signed on `version`, and mirror it to policies/production.json."""
    write_signed("policy", version, document)
    POLICY_FILE.parent.mkdir(parents=True, exist_ok=True)
    POLICY_FILE.write_text(json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")


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
    protect = sub.add_parser("protect", help="add one protected action; the metered block is kept")
    protect.add_argument("repository", metavar="OWNER/NAME")
    protect.add_argument("action", metavar="ACTION", help="for example database.migrate")
    protect.add_argument("--apply", action="store_true")
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
    enroll = sub.add_parser("enroll", help="register repositories and meter the providers that build them")
    enroll.add_argument("repositories", nargs="+", metavar="OWNER/NAME")
    enroll.add_argument("--vercel", action="append", default=[], metavar="PROJECT_ID")
    enroll.add_argument("--vercel-team")
    enroll.add_argument("--railway-project")
    enroll.add_argument("--railway-service", action="append", default=[])
    enroll.add_argument("--railway-map", metavar="FILE",
                        help='JSON {"OWNER/NAME": {"project_id": ID, "service_ids": [ID, ...]}} for many repositories')
    enroll.add_argument("--production-branch", action="append", default=[])
    enroll.add_argument("--apply", action="store_true")
    coverage = sub.add_parser("coverage", help="every live Vercel project, metered or flagged with its fix")
    coverage.add_argument("repository", nargs="?", metavar="OWNER/NAME")
    caller = sub.add_parser("caller", help="issue a lane or coordinator credential")
    caller.add_argument("caller_id")
    caller.add_argument("--kind", required=True, choices=["lane", "coordinator"])
    caller.add_argument("--repo", action="append", required=True, metavar="OWNER/NAME|OWNER/*")
    caller.add_argument("--token-file", metavar="PATH",
                        help="write the new token to this new file (mode 0600) instead of the macOS Keychain")
    caller.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if not (HERE / "gateway.py").exists():
        raise SystemExit("error: run this from an acp-gateway checkout")
    return {"register": cmd_register, "grant": cmd_grant, "repin": cmd_repin,
            "unregister": cmd_unregister, "meter": cmd_meter, "protect": cmd_protect, "budget-policy": cmd_budget_policy,
            "budget-grant": cmd_budget_grant, "caller": cmd_caller, "enroll": cmd_enroll,
            "coverage": cmd_coverage}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
