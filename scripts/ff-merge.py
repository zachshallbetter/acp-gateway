#!/usr/bin/env python3
"""Fast-forward a protected branch to a reviewed revision under an exact ACP ALLOW.

    scripts/ff-merge.py --work-item OWNER/NAME#N [--rev REV] [--ref refs/heads/main]
                        [--remote origin] [--token-account ACP_GATEWAY_TOKEN] [--dry-run]

REV (default HEAD) must already be on GitHub as the tip of a branch, usually its pull request's,
and must descend from the remote's current REF. The script asks ACP for a
`git.protected_ref.update` naming exactly the current and new SHA, then pushes REV to REF
straight away, inside the decision's lifetime, and never with --force. --dry-run checks
everything local and prints the plan without asking ACP or pushing.

Exit 0 when the ref was updated (or the dry run passed), 1 otherwise. A refusal prints ACP's
reason and remedy; the ref is untouched.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import acp_ops
from acp_ops import Stop, git

AGENT_ID = "acp-release-operator"


def plan(checkout: Path, remote: str, ref: str, rev: str) -> dict:
    """The exact update: owner, name, ref, the remote's current SHA and the reviewed SHA."""
    if not ref.startswith("refs/heads/"):
        raise Stop(f"{ref} is not a full branch ref; use refs/heads/<name>")
    owner, name = acp_ops.github_repository(checkout, remote)
    branch = ref.removeprefix("refs/heads/")
    git(checkout, "fetch", "--quiet", remote, f"+{ref}:refs/remotes/{remote}/{branch}")
    old = git(checkout, "rev-parse", f"refs/remotes/{remote}/{branch}")
    new = git(checkout, "rev-parse", "--verify", f"{rev}^{{commit}}")
    if new == old:
        raise Stop(f"{ref} is already at {new[:12]}; there is nothing to fast-forward")
    if acp_ops.run("git", "merge-base", "--is-ancestor", old, new, cwd=checkout).returncode != 0:
        raise Stop(f"{new[:12]} does not descend from {remote}/{branch} ({old[:12]}). "
                   f"Rebase onto {remote}/{branch}, push the branch, and run this again")
    published = {line.split()[0] for line in git(checkout, "ls-remote", "--heads", remote).splitlines() if line}
    if new not in published:
        raise Stop(f"GitHub has no branch at {new[:12]}, so ACP cannot confirm the fast-forward. "
                   "Push the branch (its pull request branch is fine), then run this again")
    return {"owner": owner, "name": name, "remote": remote, "ref": ref, "old_sha": old, "new_sha": new}


def merge(checkout: Path, update: dict, token: str, work_item: str) -> dict:
    """Ask ACP for this exact update and push it at once. Returns the decision."""
    context = {"ref": update["ref"], "old_sha": update["old_sha"], "new_sha": update["new_sha"],
               "work_item": work_item}
    decision = acp_ops.authorize(token, update["owner"], update["name"], "git.protected_ref.update",
                                 update["new_sha"], context, f"fast-forward {update['ref']} for {work_item}",
                                 AGENT_ID)
    print(json.dumps({"step": "authorize", **decision}))
    acp_ops.require_allow(decision, "git.protected_ref.update", ref=update["ref"],
                          old_sha=update["old_sha"], new_sha=update["new_sha"])
    push = acp_ops.run("git", "push", "--porcelain", update["remote"], f"{update['new_sha']}:{update['ref']}",
                       cwd=checkout)
    if push.returncode != 0:
        raise Stop(f"the push was refused after ACP allowed it ({push.stderr.strip() or push.stdout.strip()}); "
                   f"{update['ref']} is unchanged unless the output above says otherwise")
    return decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--work-item", required=True, help="the reviewed work item, e.g. owner/name#59")
    parser.add_argument("--rev", default="HEAD")
    parser.add_argument("--ref", default="refs/heads/main")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--token-account", default="ACP_GATEWAY_TOKEN")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    checkout = Path.cwd()
    try:
        update = plan(checkout, args.remote, args.ref, args.rev)
        print(json.dumps({"step": "plan", **update}))
        if args.dry_run:
            return 0
        print(json.dumps({"step": "harness", "allowed_by": acp_ops.harness_gate(update["name"])}))
        merge(checkout, update, acp_ops.bearer(args.token_account), args.work_item)
    except Stop as exc:
        print(f"ff-merge: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"step": "pushed", "ref": update["ref"], "new_sha": update["new_sha"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
