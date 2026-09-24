#!/usr/bin/env python3
"""register-policy.py -- put one repository under an ACP policy.

    scripts/register-policy.py --owner O --name N [--board O:N ...] [--apply]
    scripts/register-policy.py --from candidate.json [--apply]

Until a policy names a repository, ACP has nothing to enforce there: inside
ACP_POLICY_SCOPE every protected action is refused with POLICY_NOT_FOUND, and
outside it every action comes back ALLOW / OUT_OF_POLICY_SCOPE. A project that
declares itself fail-closed is therefore not actually governed until this runs.

What it does:

  1. Reads the deployment's current ACP_POLICY (Railway, or --local FILE).
  2. Builds the policy for this repository -- or takes the candidate a
     formal-project-bootstrap project emits with `scripts/acp.py policy` --
     and replaces any existing policy for the same repository at version+1.
  3. Signs it when the deployment holds ACP_POLICY_SIGNING_KEY, because a
     deployment that has a key refuses unsigned policy (fail-closed, INVALID).
  4. Validates the whole document with the gateway's own loader, so what is
     written is exactly what `main()` will accept at startup.
  5. Prints the summary. Nothing is written without --apply.

Setting ACP_POLICY on Railway redeploys the service; that is how the new
policy is loaded. No secret is ever printed: the signing key is read into
memory and used there.
"""
from __future__ import annotations

import argparse, copy, hashlib, hmac, json, os, subprocess, sys
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "register-policy-offline")
import gateway  # noqa: E402


def railway_vars(service, environment):
    out = subprocess.run(["railway", "variables", "--service", service, "--environment", environment,
                          "--json"], capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("error: could not read Railway variables "
                         f"({service}/{environment}): {out.stderr.strip()[:200]}\n"
                         "remedy: `railway link` to the agent-control-plane project first")
    return json.loads(out.stdout)


def load_document(text):
    """Every policy in ACP_POLICY, as the list the gateway would iterate."""
    if not (text or "").strip():
        return []
    document = json.loads(text)
    if isinstance(document, dict) and "policies" in document:
        return list(document["policies"])
    return [document] if isinstance(document, dict) else list(document)


def build_policy(args):
    if args.source:
        text = sys.stdin.read() if args.source == "-" else Path(args.source).read_text(encoding="utf-8")
        policy = json.loads(text)
        policy.pop("signature", None)
        policy.pop("signing_key_id", None)
        return policy
    if not (args.owner and args.name):
        raise SystemExit("error: pass --owner and --name, or --from a candidate policy")
    policy = {"policy_id": args.policy_id or f"{args.owner}-{args.name}".lower(),
              "version": 1, "status": "active",
              "repository": {"owner": args.owner, "name": args.name,
                             "canonical_remote": args.remote
                             or f"https://github.com/{args.owner}/{args.name}.git"},
              "protected_actions": sorted(args.actions.split(",")) if args.actions
              else list(gateway.DEFAULT_PROTECTED_ACTIONS)}
    boards = []
    for spec in args.board:
        owner, _, number = spec.rpartition(":")
        if not owner or not number.isdigit():
            raise SystemExit(f"error: --board takes OWNER:NUMBER, not {spec!r}")
        boards.append({"owner": owner, "number": int(number)})
    if boards:
        policy["boards"] = boards
    return policy


def same_repository(a, b):
    ra, rb = a.get("repository") or {}, b.get("repository") or {}
    return (str(ra.get("owner", "")).lower(), str(ra.get("name", "")).lower()) == \
           (str(rb.get("owner", "")).lower(), str(rb.get("name", "")).lower())


CARRIED_FIELDS = ("boards", "notice", "artifact_manifest", "recovery_authorizations")


def merge(existing, policy):
    """Replace the policy for this repository (version+1), or append it."""
    merged, replaced = [], None
    for entry in existing:
        if isinstance(entry, dict) and (same_repository(entry, policy)
                                        or entry.get("policy_id") == policy.get("policy_id")):
            replaced = entry
            continue
        merged.append(entry)
    if replaced is not None:
        # What this run does not restate is kept: silently dropping a board
        # binding, a notice digest or a recovery grant would weaken the policy.
        for field in CARRIED_FIELDS:
            if field not in policy and field in replaced:
                policy[field] = copy.deepcopy(replaced[field])
        policy["policy_id"] = replaced.get("policy_id", policy["policy_id"])
        policy["version"] = max(int(policy.get("version") or 1), int(replaced.get("version") or 0) + 1)
    merged.append(policy)
    return merged, replaced


def sign(policy, key, key_id):
    body = {k: v for k, v in policy.items() if k not in ("signature", "signing_key_id", "sha256")}
    digest = gateway.policy_digest(body)
    signed = dict(body)
    signed["signature"] = hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest()
    if key_id:
        signed["signing_key_id"] = key_id
    return signed


def validate(document, key, key_id):
    """Load it exactly as the deployment will, with the deployment's key."""
    env = {"ACP_POLICY": json.dumps(document), "ACP_POLICY_FILE": "",
           "ACP_POLICY_SIGNING_KEY": key or ""}
    if key_id:
        env["ACP_POLICY_SIGNING_KEY_ID"] = key_id
    with patch.dict(os.environ, env):
        gateway._REGISTRY.update(key=None, value=None)
        registry = gateway.policy_registry(strict=True)
        return {pid: {"version": r["policy"]["version"], "state": r["state"], "digest": r["digest"],
                      "repository": f"{r['policy']['repository']['owner']}/{r['policy']['repository']['name']}",
                      "boards": r["policy"].get("boards", [])}
                for pid, r in registry["policies"].items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--owner")
    parser.add_argument("--name")
    parser.add_argument("--remote", help="canonical remote; default https://github.com/OWNER/NAME.git")
    parser.add_argument("--policy-id")
    parser.add_argument("--board", action="append", default=[], help="OWNER:NUMBER; gates the board read")
    parser.add_argument("--actions", help="comma-separated protected actions (default: ACP's defaults)")
    parser.add_argument("--from", dest="source", help="a candidate policy JSON, or - for stdin (e.g. from `acp.py policy`)")
    parser.add_argument("--local", help="read and write this JSON file instead of Railway")
    parser.add_argument("--service", default=os.getenv("ACP_RAILWAY_SERVICE", "acp-gateway"))
    parser.add_argument("--environment", default=os.getenv("ACP_RAILWAY_ENV", "production"))
    parser.add_argument("--sign-all", action="store_true",
                        help="re-sign every policy, e.g. when ACP_POLICY_SIGNING_KEY is first introduced")
    parser.add_argument("--apply", action="store_true", help="write it; without this nothing changes")
    args = parser.parse_args()

    if args.local:
        path = Path(args.local)
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        key, key_id = os.getenv("ACP_POLICY_SIGNING_KEY", ""), os.getenv("ACP_POLICY_SIGNING_KEY_ID", "")
    else:
        variables = railway_vars(args.service, args.environment)
        current = variables.get("ACP_POLICY", "")
        key, key_id = variables.get("ACP_POLICY_SIGNING_KEY", ""), variables.get("ACP_POLICY_SIGNING_KEY_ID", "")
        if variables.get("ACP_POLICY_FILE"):
            raise SystemExit("error: this deployment loads ACP_POLICY_FILE, which this tool does not edit")

    try:
        existing = load_document(current)
    except ValueError as exc:
        raise SystemExit(f"error: the deployment's current ACP_POLICY is not valid JSON ({exc}); "
                         "refusing to merge into it")
    policy = build_policy(args)
    merged, replaced = merge(copy.deepcopy(existing), policy)
    if key:
        for index in (range(len(merged)) if args.sign_all else [len(merged) - 1]):
            merged[index] = sign(merged[index], key, key_id)
    try:
        summary = validate(merged, key, key_id)
    except ValueError as exc:
        raise SystemExit(f"error: the result would not load: {exc}")

    target = merged[-1]
    print(json.dumps({"target": f"{args.local or args.service + '/' + args.environment}",
                      "policy_id": target["policy_id"], "version": target["version"],
                      "replaces_version": (replaced or {}).get("version"),
                      "signed": "signature" in target,
                      "registry": summary}, indent=2))
    document = json.dumps(merged, sort_keys=True, separators=(",", ":"))
    if not args.apply:
        print("dry run: nothing written. Re-run with --apply to register it.", file=sys.stderr)
        return 0
    if args.local:
        Path(args.local).write_text(document + "\n", encoding="utf-8")
    else:
        out = subprocess.run(["railway", "variables", "--service", args.service, "--environment",
                              args.environment, "--set", f"ACP_POLICY={document}"],
                             capture_output=True, text=True)
        if out.returncode != 0:
            raise SystemExit(f"error: railway refused the update: {out.stderr.strip()[:300]}")
    print(f"registered {target['policy_id']} v{target['version']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
