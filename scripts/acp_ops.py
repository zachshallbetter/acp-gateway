"""What scripts/ff-merge.py and scripts/release.py share: git, the ACP decision and the owner's harness.

A script that pushes or deploys from a subprocess is invisible to the local Bash guards, which
read only the command line. So before any push or deploy these scripts ask the same two
questions the guards would: is the machine on hold, and has the owner opened an approval
window for this repository (`python3 ~/.claude/hooks/approve.py hosted <repo> [minutes]`)?
On a machine without the harness, ACP's decision is the only gate.

The bearer token comes from the environment (`latchkey run --env-file .env.local` supplies it),
falling back to the macOS Keychain service "ACP Gateway Production", and is never printed.
Database connection strings stay in the environment of the process that uses them.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
GATEWAY = os.environ.get("ACP_GATEWAY_URL", "https://acp-gateway.vercel.app").rstrip("/")
KEYCHAIN_SERVICE = "ACP Gateway Production"
DECISION_FIELDS = ("decision", "reason", "request_id", "policy_id", "policy_version", "repository_trust",
                   "remedy", "detail", "authorized_action")
FULL_SHA = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
urlopen = urllib.request.urlopen


class Stop(Exception):
    """A refusal or failure the caller can act on: the message says what happened and what to do."""


def run(*args: str, cwd: Path | str = ROOT, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=cwd, input=input, capture_output=True, text=True)


def git(checkout: Path | str, *args: str) -> str:
    result = run("git", *args, cwd=checkout)
    if result.returncode != 0:
        raise Stop(f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


def github_repository(checkout: Path | str, remote: str) -> tuple[str, str]:
    """(owner, name) of a remote that points at github.com, from its URL alone."""
    url = git(checkout, "remote", "get-url", remote)
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
                         r"([A-Za-z0-9-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?", url)
    if not match:
        raise Stop(f"remote {remote!r} does not point at a github.com repository")
    return match.group(1), match.group(2)


def bearer(account: str) -> str:
    """The caller's token: the environment variable of that name (as `latchkey run` supplies it), else the Keychain."""
    value = os.environ.get(account, "").strip()
    if value.startswith("latchkey://"):
        raise Stop(f"{account} is a Latchkey reference, not a value. Run this under "
                   "latchkey run --env-file .env.local -- ...")
    if value:
        return value
    result = run("security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w")
    if result.returncode != 0 or not result.stdout.strip():
        raise Stop(f"{account} is neither in the environment nor in the Keychain under {KEYCHAIN_SERVICE!r}. "
                   "Run this under latchkey run --env-file .env.local -- ...")
    return result.stdout.strip()


def harness_gate(repo_name: str, scope: str = "hosted") -> str:
    """Refuse while the machine is on hold or no owner approval covers this repository.

    Returns a short note on what allowed it. The harness's own reader is used, so an approval
    means exactly what it means to the guards (and its use is logged the same way).
    """
    home = Path(os.path.expanduser(os.environ.get("HARNESS_HOME", "~/.claude/hooks")))
    source = home / "guard_common.py"
    if not source.is_file():
        return "no owner harness on this machine; ACP is the only gate"
    spec = importlib.util.spec_from_file_location("acp_harness_guard_common", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    hold = module.held()
    if hold:
        raise Stop(f"the machine is on hold ({hold}); nothing was pushed or deployed")
    if not module.approved(scope, repo_name):
        raise Stop(f"no owner approval covers {scope} actions for {repo_name}. The owner opens one from their own "
                   f"terminal: python3 ~/.claude/hooks/approve.py {scope} {repo_name} 30")
    return f"owner approval for {scope} {repo_name}"


def authorize(token: str, owner: str, name: str, action: str, head_sha: str, context: dict, summary: str,
              agent_id: str) -> dict:
    """One POST /internal/authorize. Returns the decision fields worth printing (never a token)."""
    body = {"action": action, "agent_id": agent_id,
            "repository_claim": {"owner": owner, "name": name,
                                 "remote_url": f"https://github.com/{owner}/{name}.git", "head_sha": head_sha},
            "context": context,
            "principal": {"client_type": "acp-gateway-operator", "client_version": "1"},
            "request_provenance": {"source": "automation", "request_summary": summary}}
    request = urllib.request.Request(GATEWAY + "/internal/authorize", data=json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            decision = json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            detail = json.load(exc)
        except ValueError:
            detail = {}
        raise Stop(f"ACP answered {exc.code} {detail.get('error', '')}: {detail.get('detail', '')} "
                   f"{detail.get('remedy', '')}".rstrip())
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise Stop(f"ACP could not be reached ({type(exc).__name__}); nothing was changed")
    return {key: decision.get(key) for key in DECISION_FIELDS}


def require_allow(decision: dict, action: str, **exact: str) -> None:
    """Pass only an ALLOW whose authorized_action names this action and every exact field."""
    allowed = decision.get("authorized_action") or {}
    if (decision.get("decision") == "ALLOW" and allowed.get("action") == action
            and all(allowed.get(key) == value for key, value in exact.items())):
        return
    reason = decision.get("reason") or "no reason given"
    remedy = decision.get("remedy") or decision.get("detail") or ""
    raise Stop(f"ACP did not authorize {action}: {decision.get('decision')} {reason}. {remedy}".rstrip())


def get_json(url: str, timeout: float = 10) -> tuple[int, dict]:
    """GET an unauthenticated JSON route: (status, body), with an empty body when it isn't JSON."""
    try:
        with urlopen(urllib.request.Request(url), timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.load(exc)
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, {}
