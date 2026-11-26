"""Metered actions: what costs money or reaches production, decided against budgets.

ACP records every metered action it allows, once, under a key built from
explicit fields. It budgets each provider project (a Vercel project, a Railway
project, a workflow) on its own, caps each service against what the provider
itself reports, and paces builds of one project. Every repository decision
carries advice on volume and process. Past a budget it asks the owner
(AUTH_REQUIRED) unless an owner grant covers the action; an agent that needs a
push to keep working may ask for priority, and ACP decides. Everyday work inside
a budget needs no one's approval.

Every refusal carries a remedy the caller can act on. Where the caller can fix
the problem itself (bound a workflow, use a light model, wait for a slot), the
remedy says exactly how; the owner is named only past a budget or for
production.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

METERED_ACTIONS = ("hosted_build", "production_merge", "manual_ci", "local_heavy_build", "heavy_subagent",
                   "build_admission")
REPO_ACTIONS = frozenset({"hosted_build", "production_merge", "manual_ci"})
LOCAL_ACTIONS = frozenset({"local_heavy_build", "heavy_subagent", "build_admission"})
HOSTED_PROVIDERS = ("vercel", "railway", "github_actions")
TRIGGERS = {"hosted_build": frozenset({"push", "cli_deploy", "railway_up"}),
            "production_merge": frozenset({"merge", "promote"}),
            "manual_ci": frozenset({"workflow_dispatch", "rerun"})}
# A CLI deploy targets whatever the linked project deploys, not a branch, so the
# claimed ref says nothing about whether it reaches production.
BRANCH_INDEPENDENT_TRIGGERS = frozenset({"cli_deploy", "railway_up"})
# The provider these triggers start; every other trigger builds every connected provider.
TRIGGER_PROVIDER = {"cli_deploy": "vercel", "railway_up": "railway"}
# Each request with these triggers starts a new paid run of the same commit.
INVOCATION_TRIGGERS = frozenset({"cli_deploy", "railway_up", "workflow_dispatch", "rerun"})
# How long the caller that made an invocation's record may retry it and be answered from the record.
INVOCATION_REPLAY_SECONDS = 600
# Daily counts that record and report for the coordinator and the owner instead of refusing.
# Hosted builds and manual CI cost money per run and stay enforced.
AWARE_BUDGETS = frozenset({"production_merge"})
CALLER_KINDS = ("shared", "lane", "coordinator", "owner")
PRODUCTION_CALLERS = frozenset({"coordinator", "owner"})
HEAVY_MODEL = re.compile(r"opus|fable", re.I)
LEASE_SECONDS = 2 * 3600
FULL_SHA = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
WORKFLOW_PATH = re.compile(r"\A\.github/workflows/[A-Za-z0-9._-]+\.ya?ml\Z")

# Used when the signed budget policy leaves a limit out.
# hosted_build: each provider project has its own daily budget (per_project_per_day, or when that is
# null, 1.5x the project's busiest day of the last week, kept within project_floor..project_ceiling).
# per_provider_per_day caps a whole service against the provider's own count of today's deployments
# where it can be read live (ACP's ledger otherwise); per_provider_concurrent is builds in flight.
# per_repo_per_day and per_day_total are reported, never enforced: one project's builds must not
# refuse another's.
DEFAULT_LIMITS = {
    "hosted_build": {"per_repo_per_day": 20, "per_day_total": 60,
                     "per_provider_per_day": {"vercel": 150, "railway": 30, "github_actions": 100},
                     "per_provider_concurrent": {"vercel": 4},
                     "per_project_per_day": None, "project_floor": 15, "project_ceiling": 40,
                     "min_spacing_seconds": 120, "burst_builds": 5, "burst_minutes": 30,
                     "priority_per_project_per_day": 3},
    "production_merge": {"per_repo_per_day": 5},
    "manual_ci": {"per_day_total": 10},
    "heavy_subagent": {"concurrent_per_session": 6},
    "local_heavy_build": {},
    "build_admission": {},
}

# The machine register asks build_admission before a build takes a slot. The signed budget policy may
# carry a build_admission block; these are its defaults, so a policy without one still decides.
ADMISSION_CONTRACT = {"version": 1,
                      "project_slots_while_others_wait": 1,   # slots one project may hold while others queue
                      "duplicates": "refuse",                 # a build identical to one running: refuse | note
                      "unattributed": "refuse_unless_interactive",  # no session recorded: refuse... | note
                      "private_cache": "note"}                # a cargo build off the shared cache: refuse | note
ADMISSION_CHOICES = {"duplicates": ("refuse", "note"), "unattributed": ("refuse_unless_interactive", "note"),
                     "private_cache": ("refuse", "note")}
ADMISSION_FIELDS = frozenset({"contract", "project", "repo", "label", "command", "cache", "attribution",
                              "running", "queued_projects"})
ATTRIBUTION_FIELDS = frozenset({"session_id", "host_session_id", "message_address", "subagent", "interactive"})
RUNNING_FIELDS = frozenset({"project", "command", "session_id", "receipt_id", "since"})

CONTEXT_FIELDS = frozenset({"trigger", "provider", "workflow", "run_id", "tool_use_id", "model",
                            "reason", "machine_id", "admission", "priority"})
PRIORITY_BLOCKING = ("continue_work", "release", "fix")
HOSTED = ("hosted_build", "production_merge")
CONTEXT_LIMITS = {"context.trigger": 32, "context.provider": 32, "context.workflow": 256,
                  "context.run_id": 32, "context.tool_use_id": 128, "context.model": 64,
                  "context.reason": 512, "context.machine_id": 128}


class MeteringError(ValueError):
    """A metered request is malformed. field names the offending field."""

    def __init__(self, message, field=None, remedy=None):
        super().__init__(message)
        self.field, self.remedy = field, remedy


def _valid_ref(ref):
    return bool(ref) and ref.startswith("refs/heads/") and ".." not in ref and \
        not any(part in ("", ".", "..") or part.startswith(".") or part.endswith((".", ".lock"))
                for part in ref.split("/")) and \
        not any(ord(c) < 33 or ord(c) == 127 or c in "\\~^:?*[" for c in ref) and "@{" not in ref


def validate_context(action, context, session_id):
    """Required fields per metered action, checked before anything is evaluated."""
    reason = context.get("reason") or ""
    if len(reason.strip()) < 8:
        raise MeteringError(f"{action} needs context.reason: one sentence on why this is needed.",
                            "context.reason", "Say what the build, merge or subagent is for, in 8 to 512 characters.")
    if action in REPO_ACTIONS:
        trigger = context.get("trigger")
        if trigger not in TRIGGERS[action]:
            raise MeteringError(f"{action} needs context.trigger, one of {', '.join(sorted(TRIGGERS[action]))}.",
                                "context.trigger", f"Send trigger: {sorted(TRIGGERS[action])[0]} or another listed value.")
        # A CLI deploy targets whatever the linked project deploys, so it may come from a detached
        # checkout with no branch; a ref, when sent, still has to be a real one.
        if not (trigger in BRANCH_INDEPENDENT_TRIGGERS and not context.get("ref")) and \
                not _valid_ref(context.get("ref")):
            raise MeteringError(f"{action} needs context.ref as a full refs/heads/... name.", "context.ref",
                                "Send the branch the push, merge or run targets, e.g. refs/heads/main.")
        if not FULL_SHA.match(context.get("new_sha") or ""):
            raise MeteringError(f"{action} needs context.new_sha as a full commit id.", "context.new_sha",
                                "Send the exact 40-character commit the build would use (git rev-parse HEAD).")
        priority = context.get("priority")
        if priority is not None:
            if action != "hosted_build":
                raise MeteringError("context.priority is for hosted_build only.", "context.priority",
                                    "Leave it out: merges and manual runs are not paced.")
            if not isinstance(priority, dict) or set(priority) - {"reason", "blocking"} or \
                    priority.get("blocking") not in PRIORITY_BLOCKING or \
                    not isinstance(priority.get("reason"), str) or not 8 <= len(priority["reason"].strip()) <= 512:
                raise MeteringError("context.priority must be {reason: 8..512 characters, blocking: "
                                    + "|".join(PRIORITY_BLOCKING) + "}.", "context.priority",
                                    "Say what work this push unblocks, e.g. {\"blocking\": \"continue_work\", "
                                    "\"reason\": \"the lane needs CI on this branch to continue\"}.")
        provider = context.get("provider")
        if provider is not None and provider not in HOSTED_PROVIDERS:
            raise MeteringError("context.provider must be vercel, railway or github_actions.", "context.provider")
        if provider is not None and trigger in TRIGGER_PROVIDER and provider != TRIGGER_PROVIDER[trigger]:
            raise MeteringError(f"trigger {trigger} deploys to {TRIGGER_PROVIDER[trigger]}, not {provider}.",
                                "context.provider", f"Send provider: {TRIGGER_PROVIDER[trigger]}, or leave it out.")
        if action == "manual_ci":
            if not WORKFLOW_PATH.match(context.get("workflow") or ""):
                raise MeteringError("manual_ci needs context.workflow as .github/workflows/<file>.yml.",
                                    "context.workflow", "Send the workflow file's path in the repository.")
            if trigger == "rerun" and not (context.get("run_id") or "").isdigit():
                raise MeteringError("A rerun needs context.run_id, the numeric run id.", "context.run_id",
                                    "Take it from gh run list or the run's URL.")
    elif action == "local_heavy_build":
        for name in ("tool_use_id", "machine_id"):
            if not context.get(name):
                raise MeteringError(f"local_heavy_build needs context.{name}.", f"context.{name}",
                                    "The hook supplies tool_use_id from the tool call and machine_id from the host.")
    elif action == "build_admission":
        for name in ("tool_use_id", "machine_id"):
            if not context.get(name):
                raise MeteringError(f"build_admission needs context.{name}.", f"context.{name}",
                                    "The register supplies its ticket as tool_use_id and machine_id from the host.")
        validated_admission(context.get("admission"))
    elif action == "heavy_subagent":
        if not context.get("tool_use_id"):
            raise MeteringError("heavy_subagent needs context.tool_use_id.", "context.tool_use_id",
                                "The hook supplies it from the Agent tool call.")
        if not HEAVY_MODEL.search(context.get("model") or ""):
            raise MeteringError("heavy_subagent is for opus or fable models only.", "context.model",
                                "A sonnet or haiku subagent needs no ACP decision: start it directly.")
        if not session_id:
            raise MeteringError("heavy_subagent needs session_id, so concurrency is counted per session.",
                                "session_id", "Send the Claude Code session id.")


def validated_metered(raw, policy_id):
    """A policy's optional `metered` block, or a precise error."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError(f"{policy_id}: metered must be an object")
    unknown = set(raw) - {"production_branches", "hosted_build", "production_merge", "providers", "projects"}
    if unknown:
        raise ValueError(f"{policy_id}: metered carries unknown field(s): {', '.join(sorted(unknown))}")
    branches = raw.get("production_branches") or ["main"]
    if not isinstance(branches, list) or not branches or \
            not all(isinstance(b, str) and _valid_ref("refs/heads/" + b) for b in branches):
        raise ValueError(f"{policy_id}: metered.production_branches must be a list of branch names")
    out = {"production_branches": branches}
    for action in ("hosted_build", "production_merge"):
        block = raw.get(action)
        if block is None:
            continue
        if not isinstance(block, dict) or set(block) - {"per_day"} or \
                not isinstance(block.get("per_day"), int) or isinstance(block.get("per_day"), bool) or \
                not 0 <= block["per_day"] <= 500:
            raise ValueError(f"{policy_id}: metered.{action} must be {{\"per_day\": 0..500}}")
        out[action] = {"per_day": block["per_day"]}
    projects = raw.get("projects")
    if projects is not None:
        if not isinstance(projects, dict) or len(projects) > 20 or not all(
                isinstance(pid, str) and re.fullmatch(r"[A-Za-z0-9_./-]{1,256}", pid) and isinstance(block, dict)
                and set(block) == {"per_day"} and isinstance(block["per_day"], int)
                and not isinstance(block["per_day"], bool) and 0 <= block["per_day"] <= 500
                for pid, block in projects.items()):
            raise ValueError(f"{policy_id}: metered.projects must map provider project ids to {{\"per_day\": 0..500}}")
        out["projects"] = {pid: {"per_day": block["per_day"]} for pid, block in sorted(projects.items())}
    providers = raw.get("providers") or {}
    if not isinstance(providers, dict) or set(providers) - {"vercel", "railway"}:
        raise ValueError(f"{policy_id}: metered.providers may name vercel and railway only")
    clean = {}
    if "vercel" in providers:
        block = providers["vercel"] if isinstance(providers["vercel"], dict) else {}
        ids, team = block.get("project_ids"), block.get("team_id")
        if not isinstance(ids, list) or not ids or len(ids) > 10 or \
                not all(isinstance(i, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", i) for i in ids) or \
                set(block) - {"project_ids", "team_id"} or \
                (team is not None and not (isinstance(team, str) and re.fullmatch(r"team_[A-Za-z0-9]{1,64}", team))):
            raise ValueError(f"{policy_id}: metered.providers.vercel must be "
                             f"{{\"project_ids\": [...], \"team_id\": \"team_...\" (optional)}}")
        clean["vercel"] = {"project_ids": ids, **({"team_id": team} if team else {})}
    if "railway" in providers:
        block = providers["railway"]
        if not isinstance(block, dict) or set(block) - {"project_id", "service_ids"} or \
                not isinstance(block.get("project_id"), str) or \
                not re.fullmatch(r"[0-9a-f-]{36}", block["project_id"]) or \
                not isinstance(block.get("service_ids", []), list) or \
                not all(isinstance(s, str) and re.fullmatch(r"[0-9a-f-]{36}", s) for s in block.get("service_ids", [])):
            raise ValueError(f"{policy_id}: metered.providers.railway must be {{\"project_id\": uuid, \"service_ids\": [uuid]}}")
        clean["railway"] = {"project_id": block["project_id"], "service_ids": list(block.get("service_ids", []))}
    out["providers"] = clean
    return out


def _short_text(value, field, limit):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise MeteringError(f"{field} must be text of at most {limit} characters.", field)
    return value


def validated_admission(raw):
    """The register's facts about one build admission, checked field by field (context.admission)."""
    field = "context.admission"
    if not isinstance(raw, dict) or set(raw) - ADMISSION_FIELDS:
        raise MeteringError(f"{field} must be an object of {', '.join(sorted(ADMISSION_FIELDS))}.", field,
                            "The register builds it; update the harness if this persists.")
    for name, limit in (("contract", 64), ("project", 128), ("repo", 512), ("label", 128), ("command", 400)):
        _short_text(raw.get(name), f"{field}.{name}", limit)
    if not raw.get("project") or not raw.get("command"):
        raise MeteringError(f"{field} needs project and command.", field)
    if raw.get("cache") not in (None, "shared", "private", "not_cargo"):
        raise MeteringError(f"{field}.cache must be shared, private or not_cargo.", f"{field}.cache")
    attribution = raw.get("attribution") or {}
    if not isinstance(attribution, dict) or set(attribution) - ATTRIBUTION_FIELDS:
        raise MeteringError(f"{field}.attribution may carry only {', '.join(sorted(ATTRIBUTION_FIELDS))}.",
                            f"{field}.attribution")
    for name in ("session_id", "host_session_id", "message_address"):
        _short_text(attribution.get(name), f"{field}.attribution.{name}", 256)
    for name in ("subagent", "interactive"):
        if attribution.get(name) is not None and not isinstance(attribution[name], bool):
            raise MeteringError(f"{field}.attribution.{name} must be true or false.", f"{field}.attribution.{name}")
    running = raw.get("running") or []
    if not isinstance(running, list) or len(running) > 32 or \
            any(not isinstance(r, dict) or set(r) - RUNNING_FIELDS for r in running):
        raise MeteringError(f"{field}.running must list at most 32 builds of "
                            f"{', '.join(sorted(RUNNING_FIELDS))}.", f"{field}.running")
    for r in running:
        for name, limit in (("project", 128), ("command", 400), ("session_id", 256), ("receipt_id", 64)):
            _short_text(r.get(name), f"{field}.running.{name}", limit)
    queued = raw.get("queued_projects") or []
    if not isinstance(queued, list) or len(queued) > 64 or not all(isinstance(q, str) and len(q) <= 128 for q in queued):
        raise MeteringError(f"{field}.queued_projects must list at most 64 project names.", f"{field}.queued_projects")
    return raw


def validated_admission_contract(raw):
    """The signed budget policy's build_admission block over ADMISSION_CONTRACT, or a precise error."""
    if raw is None:
        return dict(ADMISSION_CONTRACT)
    if not isinstance(raw, dict) or set(raw) - set(ADMISSION_CONTRACT):
        raise ValueError(f"build_admission may carry only {', '.join(sorted(ADMISSION_CONTRACT))}")
    merged = {**ADMISSION_CONTRACT, **raw}
    if not isinstance(merged["version"], int) or isinstance(merged["version"], bool) or merged["version"] < 1:
        raise ValueError("build_admission.version must be a positive integer")
    slots = merged["project_slots_while_others_wait"]
    if not isinstance(slots, int) or isinstance(slots, bool) or not 1 <= slots <= 16:
        raise ValueError("build_admission.project_slots_while_others_wait must be 1..16")
    for name, choices in ADMISSION_CHOICES.items():
        if merged[name] not in choices:
            raise ValueError(f"build_admission.{name} must be one of {', '.join(choices)}")
    return merged


def admission_state(admission):
    """Each required property of taking a slot: SATISFIED, VIOLATED or GRAY, on the register's facts."""
    attribution = admission.get("attribution") or {}
    running = admission.get("running") or []
    mine = [r for r in running if r.get("project") == admission["project"]]
    others_waiting = [q for q in admission.get("queued_projects") or [] if q != admission["project"]]
    cache = admission.get("cache")
    return {"attributable": "SATISFIED" if attribution.get("session_id") or attribution.get("interactive") else "GRAY",
            "not_duplicate": "VIOLATED" if any(r.get("command") == admission["command"] for r in mine) else "SATISFIED",
            "within_project_share": None,   # filled against the contract's slot count
            "shared_cache": {"shared": "SATISFIED", "private": "VIOLATED"}.get(cache, "GRAY"),
            "_mine": len(mine), "_others_waiting": bool(others_waiting)}


def decide_admission(admission, contract):
    """Γ for a build admission: the contract maps the state vector to a decision. Returns an Outcome."""
    state = admission_state(admission)
    mine, waiting = state.pop("_mine"), state.pop("_others_waiting")
    state["within_project_share"] = "VIOLATED" if waiting and mine >= contract["project_slots_while_others_wait"] \
        else "SATISFIED"
    extra = {"admission_state": state, "admission_contract": contract["version"]}
    if state["not_duplicate"] == "VIOLATED" and contract["duplicates"] == "refuse":
        same = next(r for r in admission.get("running") or []
                    if r.get("project") == admission["project"] and r.get("command") == admission["command"])
        return Outcome("DENY", "BUILD_DUPLICATE",
                       f"{admission['project']} is already running this exact build"
                       + (f" (receipt {same['receipt_id']})" if same.get("receipt_id") else "") + ".",
                       "Wait for it and use its result, or put the distinct steps in one build: "
                       "reg build -- sh -c \"step1 && step2 && step3\".", **extra)
    if state["attributable"] == "GRAY" and contract["unattributed"] == "refuse_unless_interactive":
        return Outcome("DENY", "BUILD_UNATTRIBUTED",
                       "No agent session was recorded for this build and it is not interactive, so nobody could "
                       "be told about it.",
                       "Run it from the agent session that needs it (the register reads CLAUDE_CODE_SESSION_ID), "
                       "or set REG_SESSION_ID to the session it belongs to.", **extra)
    if state["shared_cache"] == "VIOLATED" and contract["private_cache"] == "refuse":
        return Outcome("DENY", "BUILD_PRIVATE_CACHE",
                       "This cargo build sets its own CARGO_TARGET_DIR, so it compiles cold beside the shared cache.",
                       "Drop CARGO_TARGET_DIR and let the register place the build on its shared target.", **extra)
    if state["within_project_share"] == "VIOLATED":
        return Outcome("REVERIFY_REQUIRED", "PROJECT_SHARE_EXCEEDED",
                       f"{admission['project']} already holds {mine} slot(s) while other projects wait.",
                       "The register keeps this build queued and asks again when a slot frees; combining this "
                       "project's builds into one gets it through sooner.", **extra)
    noted = [name for name, value in state.items() if value != "SATISFIED"]
    return Outcome("ALLOW", "BUILD_ADMITTED",
                   "Admitted" + (f"; recorded: {', '.join(noted)}." if noted else "."), **extra)


def validated_limits(raw):
    """The signed budget policy's limits merged over the defaults, or a precise error."""
    if not isinstance(raw, dict):
        raise ValueError("limits must be an object")
    unknown = set(raw) - set(DEFAULT_LIMITS)
    if unknown:
        raise ValueError(f"limits name unknown action(s): {', '.join(sorted(unknown))}")
    allowed = {"per_repo_per_day", "per_day_total", "per_provider_per_day", "concurrent_per_session",
               "per_provider_concurrent", "per_project_per_day", "project_floor", "project_ceiling",
               "min_spacing_seconds", "burst_builds", "burst_minutes", "priority_per_project_per_day"}
    merged = json.loads(json.dumps(DEFAULT_LIMITS))
    for action, block in raw.items():
        if not isinstance(block, dict) or set(block) - allowed:
            raise ValueError(f"limits.{action} may carry only {', '.join(sorted(allowed))}")
        for key, value in block.items():
            if key in ("per_provider_per_day", "per_provider_concurrent"):
                if not isinstance(value, dict) or set(value) - set(HOSTED_PROVIDERS) or \
                        not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1000
                                for v in value.values()):
                    raise ValueError(f"limits.{action}.{key} must map providers to 0..1000")
                merged[action][key] = {**(merged[action].get(key) or {}), **value}
            elif value is None:
                merged[action].pop(key, None)                # explicitly unlimited
            elif not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 86400:
                raise ValueError(f"limits.{action}.{key} must be an integer 0..86400 or null")
            else:
                merged[action][key] = value
    hb = merged["hosted_build"]
    if hb.get("project_floor") is not None and hb.get("project_ceiling") is not None and \
            hb["project_floor"] > hb["project_ceiling"]:
        raise ValueError("limits.hosted_build.project_floor must not exceed project_ceiling")
    return merged


def record_key(*fields):
    """sha256 of the explicit key fields, in the order given. No time, no randomness."""
    canonical = json.dumps([("" if f is None else str(f)) for f in fields], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def budget_day(now):
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")


# How the operator runs policy-admin. A deployment sets ACP_GRANT_COMMAND_PREFIX to its own form (for example
# with the operator's secret runner and checkout path); the default assumes the repository root.
GRANT_COMMAND_PREFIX = "python3 scripts/policy-admin.py"


def grant_request(action, owner=None, name=None, reason=None):
    """The one-use owner grant that would let this request through: its fields, and the exact command
    that issues it, complete and ready to run (no placeholders), with the request's own reason."""
    import os
    import shlex
    why = " ".join(str(reason or "").split())[:200]
    if len(why) < 8:
        why = f"approve one {action}" + (f" for {owner}/{name}" if owner and name else "")
    prefix = os.environ.get("ACP_GRANT_COMMAND_PREFIX", "").strip() or GRANT_COMMAND_PREFIX
    repo = f" --repo {shlex.quote(f'{owner}/{name}')}" if owner and name else ""
    return {"action": action, "repository": f"{owner}/{name}" if owner and name else None, "uses": 1,
            "expires": "2h", "reason": why,
            "command": f"{prefix} budget-grant --action {action}{repo} --uses 1 --expires 2h "
                       f"--reason {shlex.quote(why)} --apply"}


def grant_command(action, owner=None, name=None, reason=None):
    return grant_request(action, owner, name, reason)["command"]


# Said to every agent past a budget: hosted builds are shared, so batching them is the agents' job.
COLLABORATE = ("Collaborate with other agents working on this project to prioritize pushes and PR merges: "
               "keep less important work in local commits and bundle it into one push and one merge when it is "
               "ready; push alone only what development or operation needs now.")


class Outcome:
    """One metered decision, before the gateway wraps it in its response envelope."""

    def __init__(self, decision, reason, detail, remedy=None, **extra):
        self.decision, self.reason, self.detail, self.remedy, self.extra = decision, reason, detail, remedy, extra


def _caller_may_reach_production(caller):
    return caller["kind"] in PRODUCTION_CALLERS


CI_PENDING_RETRY_SECONDS = 60
MISSING_CREDENTIAL_RETRY_SECONDS = 3600   # the owner has to act, so agents are told to wait an hour


def release_refusal(release, owner, name, builds):
    """The refusal for a production CLI deploy whose commit is not merged or whose CI is not green, else None.

    `release` is the provider evidence's readiness of the named commit; None when this is not such a deploy."""
    if release is None:
        return None
    branch = release["branch"]
    if not release.get("sha"):
        return Outcome("DENY", "DEPLOY_COMMIT_REQUIRED",
                       f"A production deploy of {owner}/{name} must name the commit it ships (context.new_sha), "
                       "so ACP can check it is merged and its CI is green.",
                       f"Deploy from a checkout of {branch}, or run `acp deploy` with the commit, then ask again.",
                       builds=builds)
    sha = release["sha"]
    if not release["merged"]:
        return Outcome("DENY", "NOT_ON_PRODUCTION_BRANCH",
                       f"Commit {sha[:12]} is not on {branch} of {owner}/{name}, so it has not been merged. "
                       "Production deploys ship only merged commits.",
                       f"Merge the change into {branch}, then deploy that commit.", builds=builds, release=release)
    checks = release["checks"]
    if checks["failed"]:
        return Outcome("DENY", "CI_FAILED",
                       f"CI failed on {sha[:12]}: {', '.join(checks['failed'][:10])}.",
                       f"Fix it on {branch} and deploy the commit whose checks pass.", builds=builds, release=release)
    if checks["pending"] or release.get("ci_expected"):
        waiting = ", ".join(checks["pending"][:10]) or "CI has not started on this commit"
        return Outcome("REVERIFY_REQUIRED", "CI_PENDING",
                       f"CI on {sha[:12]} has not finished: {waiting}.",
                       f"Ask again in {CI_PENDING_RETRY_SECONDS} seconds; `acp deploy` waits for it.",
                       builds=builds, release=release, retry_after=CI_PENDING_RETRY_SECONDS)
    return None


def evaluate_repo(action, policy, claim, context, caller, limits, evidence, ledger, now, request_id):
    """Decide hosted_build, production_merge or manual_ci for a verified, governed repository."""
    if ledger is None:
        return Outcome("REVERIFY_REQUIRED", "BUDGET_LEDGER_UNAVAILABLE",
                       "This ACP deployment has no shared budget ledger (file storage), so it cannot count "
                       "paid builds against the deployment-wide limits.",
                       "Send this request to the ACP endpoint that runs on PostgreSQL, or have the owner set "
                       "ACP_STORAGE_BACKEND=postgres with the shared database on this deployment.")
    if limits is None:
        return Outcome("DENY", "BUDGET_POLICY_UNAVAILABLE",
                       "No valid signed budget policy is loaded, so ACP cannot decide paid builds.",
                       "The owner signs and sets ACP_BUDGET_POLICY (scripts/policy-admin.py budget-policy).")
    owner, name = claim["owner"], claim["name"]
    metered = policy.get("metered") or {"production_branches": ["main"], "providers": {}}
    branch = (context.get("ref") or "")[len("refs/heads/"):] or "no branch: a CLI deploy"
    trigger = context.get("trigger")
    production = action == "production_merge" or branch in metered["production_branches"] \
        or trigger in BRANCH_INDEPENDENT_TRIGGERS

    if not evidence.get("available"):
        reason = "PROVIDER_RESPONSE_DIVERGED" if evidence.get("kind") == "DIVERGED" else "PROVIDER_EVIDENCE_UNAVAILABLE"
        setting = evidence.get("missing_setting")
        if setting:
            # No credential at all: asking again cannot help until the owner adds it.
            return Outcome("REVERIFY_REQUIRED", reason,
                           f"ACP has no {evidence.get('provider')} credential, so it cannot tell whether this would "
                           "start a paid build. No paid build is authorized without that evidence.",
                           f"Do not retry: only the owner can fix this. The owner adds {setting} to the ACP "
                           "deployment on every host that serves ACP. Tell your coordinator, commit locally, "
                           "and ask again once it is set.",
                           provider_error={"provider": evidence.get("provider"), "kind": evidence.get("kind"),
                                           "missing_setting": setting},
                           retry_after=MISSING_CREDENTIAL_RETRY_SECONDS)
        return Outcome("REVERIFY_REQUIRED", reason,
                       f"ACP could not read {evidence.get('provider') or 'provider'} evidence "
                       f"({evidence.get('detail') or 'unavailable'}), so it cannot tell whether this would "
                       "start a paid build. No paid build is authorized without that evidence.",
                       "Retry in a minute. If it persists, the owner checks the provider credential "
                       "(ACP_VERCEL_TOKEN / ACP_RAILWAY_TOKEN by name) and GET /internal/posture for the error.",
                       provider_error={"provider": evidence.get("provider"), "kind": evidence.get("kind")})

    # What builds is the repository's evidence for this trigger, never the caller's choice of
    # provider: a push builds every connected provider whichever one the caller names.
    building = [dict(b, repository=(owner.lower(), name.lower())) if b["provider"] == "github_actions" else b
                for b in evidence["builds"] if b["would_build"]]
    if trigger in TRIGGER_PROVIDER and not building:
        return Outcome("DENY", "PROVIDER_NOT_METERED",
                       f"{trigger} deploys to {TRIGGER_PROVIDER[trigger]}, but the policy meters no "
                       f"{TRIGGER_PROVIDER[trigger]} project for {owner}/{name}, so ACP cannot count it.",
                       f"The owner enrolls the {TRIGGER_PROVIDER[trigger]} project for this repository "
                       f"(scripts/policy-admin.py enroll), then ask again.",
                       builds=evidence["builds"])
    refused = release_refusal(evidence.get("release"), owner, name, evidence["builds"])
    if refused:
        return refused
    # A push of one commit builds once, so asking again is a replay. A CLI deploy or a manual
    # dispatch starts a new run each time, so each invocation is its own record.
    invocation = (context.get("tool_use_id") or request_id) if trigger in INVOCATION_TRIGGERS else None
    keys = _record_keys(action, owner, name, context, invocation, building)
    # Replay: the same action asked again is answered from the record, never counted twice.
    # Authority is per caller: a record made for a coordinator does not authorize a lane.
    prior = [ledger.ledger_get(k) for k in keys.values()]
    if invocation and any(prior) and any(p and (p["caller_id"] != caller["id"]
                                                or now - p["created_at"] > INVOCATION_REPLAY_SECONDS)
                                         for p in prior):
        # A tool_use_id names one tool call. Reused by another caller or after the retry window, it
        # is a second deploy wearing the first one's id, and answering it from the record would
        # let every later deploy through uncounted.
        return Outcome("DENY", "INVOCATION_REUSED",
                       f"This {trigger} reuses tool_use_id {context.get('tool_use_id')!r}, already recorded for "
                       "an earlier deploy. A new deploy is a new invocation.",
                       "Send the id of this tool call (or omit tool_use_id and ACP counts each request), "
                       "then ask again.", builds=evidence["builds"])
    own = all(prior) and all(p["caller_id"] == caller["id"] for p in prior)
    if all(prior) and production and not own and not _caller_may_reach_production(caller):
        return Outcome("AUTH_REQUIRED", "OWNER_REQUIRED",
                       f"This deploys production ({branch}). It is already authorized for another caller, and that "
                       f"authorization is not transferable; this caller is a {caller['kind']} caller.",
                       f"Leave it to the caller that holds the authorization, or ask the owner for a grant: "
                       f"{grant_command(action, owner, name, context.get('reason'))}",
                       builds=evidence["builds"], caller_kind=caller["kind"],
                       grant_request=grant_request(action, owner, name, context.get("reason")))
    if all(prior):
        # A retry by the caller that holds the record, a grant's included, is the same push.
        return Outcome("ALLOW", prior[0]["reason_code"],
                       "Already authorized for this exact commit; the earlier record stands and is not counted again.",
                       builds=evidence["builds"], replayed=True)
    if any(prior):
        # Part of this was recorded before (the building set grew): count only what is new.
        keys = {slot: key for (slot, key), seen in zip(keys.items(), prior) if not seen}
        building = [b for b in building if (b["provider"], project_id(b)) in keys]
    if action in HOSTED and building:
        # A merge and the push of the same commit start the same builds: whichever ACP heard of first
        # counted them, and the other is answered from that record.
        sibling = _sibling_counted(ledger, action, owner, name, context, building)
        if sibling:
            keys = {slot: key for slot, key in keys.items() if slot not in sibling}
            building = [b for b in building if (b["provider"], project_id(b)) not in sibling]
            if not building:
                return Outcome("ALLOW", "WITHIN_BUDGET",
                               "These builds were already counted when ACP authorized the "
                               f"{'push' if action == 'production_merge' else 'merge'} of this commit; "
                               "they are not counted again.", builds=evidence["builds"], replayed=True)
    capacity = {c["provider"]: c for c in evidence.get("capacity") or []}
    advice = advise(ledger, limits, metered, claim, context, action, building, capacity, now)

    if not building:
        _record(ledger, keys, action, None, claim, context, caller, now, request_id, False, evidence)
        return Outcome("ALLOW", "NO_HOSTED_BUILD",
                       "No connected provider builds this. Nothing is counted against a budget.",
                       builds=evidence["builds"], advice=advice)

    # Unbounded workflows are what burned 4,000 Actions hours. The caller can bound them itself.
    unbounded = [w for w in evidence.get("workflows", [])
                 if w.get("would_run") and (w.get("jobs_without_timeout") or not w.get("has_concurrency"))]
    # Workflows read at the branch (`read_at`: the commit is not on GitHub yet) are the ones this push may
    # be fixing, so they inform but never refuse; a merge, whose commit GitHub has, is checked exactly.
    if any(w.get("read_at") for w in unbounded):
        advice.setdefault("recommendations", []).append({
            "code": "WORKFLOW_UNBOUNDED_ON_BRANCH",
            "text": "On " + str(unbounded[0]["read_at"]) + ", " + ", ".join(w["path"] for w in unbounded) +
                    " lack a timeout or a concurrency group; if this push does not bound them, the merge is "
                    "refused until it does."})
        unbounded = [w for w in unbounded if not w.get("read_at")]
    if unbounded:
        lines = []
        for w in unbounded:
            if w.get("jobs_without_timeout"):
                lines.append(f"{w['path']}: add `timeout-minutes: 15` to job(s) {', '.join(w['jobs_without_timeout'])}")
            if not w.get("has_concurrency"):
                lines.append(f"{w['path']}: add at the top level `concurrency: {{group: ${{{{ github.workflow }}}}-"
                             f"${{{{ github.ref }}}}, cancel-in-progress: true}}`")
        return Outcome("DENY", "WORKFLOW_UNBOUNDED",
                       "A GitHub Actions workflow this would run has no timeout or no concurrency group, so one "
                       "push can run without limit.",
                       "Commit these changes on your branch, then ask again with the new commit: " + "; ".join(lines) + ".",
                       workflows=[{"path": w["path"], "jobs_without_timeout": w.get("jobs_without_timeout", []),
                                   "has_concurrency": w.get("has_concurrency")} for w in unbounded],
                       builds=evidence["builds"], advice=advice)

    day = budget_day(now)
    priority = context.get("priority") if action == "hosted_build" else None
    common = {"builds": evidence["builds"], "advice": advice}

    # Pacing comes before anything is spent: a request pacing defers takes no grant and no priority
    # use, and a grant or a coordinator credential does not excuse a burst of builds.
    prioritized = False
    if action == "hosted_build":
        paced = _pacing(ledger, limits, building, capacity, now, priority_ok=False)
        if paced and paced["reason"] in ("BUILD_PACED", "BUILD_IN_FLIGHT") and \
                _priority_open(ledger, limits, caller, priority, building, day):
            paced = _pacing(ledger, limits, building, capacity, now, priority_ok=True)
            prioritized = paced is None
        if paced:
            usage, exceeded = _usage(ledger, action, limits, metered, owner, name, building, capacity, day, now)
            open_ = _priority_open(ledger, limits, caller, {"blocking": "continue_work", "reason": "-" * 8},
                                   building, day) if paced["reason"] in ("BUILD_PACED", "BUILD_IN_FLIGHT") \
                else None
            return Outcome("REVERIFY_REQUIRED", paced["reason"], paced["detail"], paced["remedy"],
                           retry_after=paced["retry_after"],
                           budget={"day": day, "usage": usage, "exceeded": exceeded},
                           **({"priority_request": _priority_request(open_)} if open_ else {}), **common)

    grant = None
    if production and not _caller_may_reach_production(caller):
        grant = ledger.grant_take(action, owner, name, now)
        if grant is None:
            return Outcome("AUTH_REQUIRED", "OWNER_REQUIRED",
                           f"This {'merge' if action == 'production_merge' else 'build'} deploys production "
                           f"({branch}). Production needs the coordinator's credential or an owner grant; this "
                           f"caller is a {caller['kind']} caller.",
                           f"Hand the {'merge' if action == 'production_merge' else 'push'} to your coordinator, "
                           f"or ask the owner for a one-use grant: "
                           f"{grant_command(action, owner, name, context.get('reason'))}",
                           builds=evidence["builds"], caller_kind=caller["kind"],
                           grant_request=grant_request(action, owner, name, context.get("reason")), advice=advice)

    usage, exceeded = _usage(ledger, action, limits, metered, owner, name, building, capacity, day, now)
    if exceeded and grant is None and action in AWARE_BUDGETS and _caller_may_reach_production(caller):
        # A merge's daily count is awareness for the coordinator or the owner, not a gate: counted,
        # reported and flagged, never refused. The builds it starts are counted once (see _sibling_counted).
        _record(ledger, keys, action, None, claim, context, caller, now, request_id, True, evidence)
        return Outcome("ALLOW", "OVER_BUDGET_NOTED",
                       f"Allowed and counted past today's {exceeded['scope']} count for {action} "
                       f"({exceeded['used']} of {exceeded['limit']}). The count is shown in GET /internal/budget; "
                       "nothing is refused for it. " + COLLABORATE,
                       budget={"day": day, "usage": _usage(ledger, action, limits, metered, owner, name, building,
                                                           capacity, day, now)[0], "exceeded": exceeded}, **common)

    # A service at its real limit: only the owner clears it, whatever the agent's priority.
    if exceeded and exceeded["kind"] == "service" and grant is None:
        grant = ledger.grant_take(action, owner, name, now)
        if grant is None:
            return _budget_refusal(ledger, action, owner, name, context, exceeded, usage, day, now, common,
                                   priority_open=None)

    if prioritized and (exceeded is None or grant is not None or exceeded["kind"] == "project"):
        return _allow_priority(ledger, keys, action, claim, context, caller, now, request_id, evidence,
                               limits, metered, owner, name, building, capacity, day, common)

    if exceeded and grant is None:
        if exceeded["kind"] == "project" and _priority_open(ledger, limits, caller, priority, building, day):
            return _allow_priority(ledger, keys, action, claim, context, caller, now, request_id, evidence,
                                   limits, metered, owner, name, building, capacity, day, common)
        grant = ledger.grant_take(action, owner, name, now)
        if grant is None:
            open_ = _priority_open(ledger, limits, caller, {"blocking": "continue_work", "reason": "-" * 8},
                                   building, day) if exceeded["kind"] == "project" and \
                action == "hosted_build" else None
            return _budget_refusal(ledger, action, owner, name, context, exceeded, usage, day, now, common,
                                   priority_open=open_)
    _record(ledger, keys, action, grant, claim, context, caller, now, request_id, True, evidence)
    reason = "GRANT_APPLIED" if grant else "WITHIN_BUDGET"
    return Outcome("ALLOW", reason,
                   "Allowed under an owner grant." if grant else "Allowed within today's budget.",
                   budget={"day": day, "usage": _usage(ledger, action, limits, metered, owner, name, building,
                                                       capacity, day, now)[0]},
                   grant_id=grant, **common)


def _sibling_counted(ledger, action, owner, name, context, building):
    """Slots (provider, project) whose builds of this commit the other hosted action already counted."""
    other = "hosted_build" if action == "production_merge" else "production_merge"
    keys = _record_keys(other, owner, name, context, None, building)
    return {slot for slot, key in keys.items() if (ledger.ledger_get(key) or {}).get("counted")}


def _record_keys(action, owner, name, context, invocation, building):
    """One ledger key per provider project this would build, or one local key when nothing builds.

    A provider with one building project keeps the key it always had (no project in it), so every
    record made before per-project budgets still replays. A provider building several projects of
    one repository adds each project's id, so each build has its own record."""
    base = (owner.lower(), name.lower(), context.get("ref"), context["new_sha"], context.get("workflow"),
            context.get("run_id"), *([invocation] if invocation else []))
    if not building:
        return {("local", ""): record_key(action, "local", *base)}
    per_provider = {}
    for b in building:
        per_provider.setdefault(b["provider"], []).append(b)
    keys = {}
    for provider, builds in per_provider.items():
        for b in builds:
            extra = [project_id(b)] if len(builds) > 1 else []
            keys[(provider, project_id(b))] = record_key(action, provider, *base, *extra)
    return keys


def project_id(build):
    """The provider project a build belongs to: Vercel or Railway project id, or workflow path."""
    return build.get("project_id") or build["project"]


def ledger_scope(build):
    """The ledger filters, beyond provider and project, that pick out one project's own builds.

    A Vercel or Railway project id names one project everywhere. A workflow path names a file that many
    repositories have, so a workflow's builds are counted, budgeted and paced per repository: otherwise
    every repository's .github/workflows/ci.yml shares one daily budget."""
    if build["provider"] == "github_actions":
        owner, name = build["repository"]
        return {"owner": owner, "name": name}
    return {}


def project_limit(ledger, limits, metered, build, now):
    """(limit, source) for one provider project's builds today."""
    pid = project_id(build)
    override = ((metered.get("projects") or {}).get(pid) or {}).get("per_day")
    if override is not None:
        return override, "repository policy: this project"
    repo = (metered.get("hosted_build") or {}).get("per_day")
    if repo is not None:
        return repo, "repository policy: each project"
    hb = limits["hosted_build"]
    if hb.get("per_project_per_day") is not None:
        return hb["per_project_per_day"], "budget policy"
    days = [budget_day(now - 86400 * back) for back in range(1, 8)]
    peak = max(ledger.ledger_project_days(HOSTED, build["provider"], pid, days, **ledger_scope(build)).values(),
               default=0)
    floor, ceiling = hb.get("project_floor") or 0, hb.get("project_ceiling")
    derived = max(floor, -(-peak * 3 // 2))
    return (derived if ceiling is None else min(ceiling, derived)), "history: 1.5x the busiest day this week"


def _usage(ledger, action, limits, metered, owner, name, building, capacity, day, now):
    """Usage after this request would be counted, and the first enforced limit it would cross.

    Enforced: each building project's own budget, each service's ceiling (the provider's own count
    where it can be read live), and production merges per repository. Reported only: the
    repository and deployment-wide totals."""
    checks = []
    if action == "production_merge":
        per_repo = (metered.get("production_merge") or {}).get("per_day",
                                                                limits["production_merge"].get("per_repo_per_day"))
        checks.append({"scope": "repository", "kind": "repository", "limit": per_repo, "adding": 1,
                       "used": ledger.ledger_count(day, ["production_merge"], owner=owner, name=name,
                                                   distinct_sha=True)})
    if action in HOSTED:
        hb = limits["hosted_build"]
        for b in building:
            limit, source = project_limit(ledger, limits, metered, b, now)
            checks.append({"scope": f"project {b['provider']}/{b['project']}", "kind": "project", "build": b,
                           "limit": limit, "limit_source": source, "adding": 1,
                           "used": ledger.ledger_count(day, list(HOSTED), provider=b["provider"],
                                                       project=project_id(b), **ledger_scope(b))})
        for provider in sorted({b["provider"] for b in building}):
            live = capacity.get(provider) or {}
            from_provider = live.get("source") == "live" and "deployments_today" in live
            used = live["deployments_today"] if from_provider else ledger.ledger_count(day, list(HOSTED),
                                                                                         provider=provider)
            checks.append({"scope": f"service {provider}", "kind": "service", "provider": provider,
                           "limit": (hb.get("per_provider_per_day") or {}).get(provider),
                           "adding": sum(1 for b in building if b["provider"] == provider), "used": used,
                           "source": "provider" if from_provider else "ledger",
                           "over_limit": bool(live.get("over_limit"))})
        checks.append({"scope": "repository hosted-build", "kind": "repository_total", "enforced": False,
                       "limit": hb.get("per_repo_per_day"), "adding": len(building),
                       "used": ledger.ledger_count(day, list(HOSTED), owner=owner, name=name)})
        checks.append({"scope": "deployment-wide hosted-build", "kind": "deployment_total", "enforced": False,
                       "limit": hb.get("per_day_total"), "adding": len(building),
                       "used": ledger.ledger_count(day, list(HOSTED))})
    if action == "manual_ci":
        checks.append({"scope": "deployment-wide manual CI", "kind": "manual_ci", "adding": 1,
                       "limit": limits["manual_ci"].get("per_day_total"),
                       "used": ledger.ledger_count(day, ["manual_ci"])})
    usage, exceeded = [], None
    for check in checks:
        enforced = check.get("enforced", True)
        usage.append({"scope": check["scope"], "used": check["used"], "limit": check["limit"],
                      **({"limit_source": check["limit_source"]} if "limit_source" in check else {}),
                      **({"source": check["source"]} if "source" in check else {}),
                      **({} if enforced else {"enforced": False})})
        over = check.get("over_limit") or (check["limit"] is not None and
                                          check["used"] + check["adding"] > check["limit"])
        # A service at its limit outranks a project over its budget: priority may waive the second,
        # never the first, so the service overrun is the one reported when both apply.
        if enforced and over and (exceeded is None or (check["kind"] == "service" and exceeded["kind"] != "service")):
            exceeded = {"scope": check["scope"], "used": check["used"], "limit": check["limit"],
                        "kind": "service" if check["kind"] == "service" else
                        "project" if check["kind"] == "project" else check["kind"],
                        **({"build": check["build"]} if "build" in check else {}),
                        **({"provider": check["provider"]} if "provider" in check else {}),
                        **({"over_limit": True} if check.get("over_limit") else {})}
    return usage, exceeded


def _pacing(ledger, limits, building, capacity, now, priority_ok):
    """The first pacing rule this request breaks, or None. A burst is never waived; spacing and a
    build already in flight are waived for an ACP-granted priority (priority_ok)."""
    hb = limits["hosted_build"]
    window = (hb.get("burst_minutes") or 0) * 60
    spacing = hb.get("min_spacing_seconds") or 0
    for provider in sorted({b["provider"] for b in building}):
        live = capacity.get(provider) or {}
        concurrent = (hb.get("per_provider_concurrent") or {}).get(provider)
        if concurrent and live.get("source") == "live" and (live.get("in_flight") or 0) >= concurrent:
            build = next(b for b in building if b["provider"] == provider)
            return {"reason": "SERVICE_AT_CAPACITY", "build": build, "retry_after": 120,
                    "detail": f"{provider} already has {live['in_flight']} builds running (this deployment allows "
                              f"{concurrent} at once); another one now only queues behind them.",
                    "remedy": "Commit locally and keep working; ask again in about two minutes with everything "
                              "batched. A priority request does not jump a saturated service."}
    for b in building:
        pid = project_id(b)
        recent = ledger.ledger_recent(HOSTED, b["provider"], pid, now - max(window, spacing, 1), **ledger_scope(b))
        in_window = [t for t in recent if t >= now - window] if window else []
        if hb.get("burst_builds") and len(in_window) >= hb["burst_builds"]:
            # Below the burst again once the oldest build that keeps it at burst_builds leaves the window.
            wait = int(in_window[-hb["burst_builds"]] + window - now) + 1
            return {"reason": "BUILD_BURST", "build": b, "retry_after": max(wait, 1),
                    "detail": f"{len(in_window)} builds of {b['provider']} project {b['project']} in the last "
                              f"{window // 60} minutes: that is a burst, not a release cadence.",
                    "remedy": f"Commit locally and keep working; push once, with everything batched, in "
                              f"{max(wait, 1)} seconds or later. A priority request does not waive a burst."}
        if priority_ok:
            continue
        live = capacity.get(b["provider"]) or {}
        flying = live.get("projects_in_flight") or {}
        if live.get("source") == "live" and (flying.get(pid) or flying.get(b["project"])):
            return {"reason": "BUILD_IN_FLIGHT", "build": b, "retry_after": 60,
                    "detail": f"A build of {b['provider']} project {b['project']} is already running; another "
                              "push now starts a second build behind it.",
                    "remedy": "Commit locally and push when it finishes (ask again in about a minute); your next "
                              "push carries every commit made meanwhile. If you cannot continue without this "
                              "push, ask for priority (see priority_request)."}
        if spacing and recent and now - recent[-1] < spacing:
            wait = int(recent[-1] + spacing - now) + 1
            return {"reason": "BUILD_PACED", "build": b, "retry_after": wait,
                    "detail": f"{b['provider']} project {b['project']} built {int(now - recent[-1])} seconds ago; "
                              f"builds of one project are spaced at least {spacing} seconds apart.",
                    "remedy": f"Commit locally and push in {wait} seconds with everything batched. If you cannot "
                              "continue without this push, ask for priority (see priority_request)."}
    return None


def _priority_open(ledger, limits, caller, priority, builds, day):
    """{remaining} when ACP grants priority for these builds now, else None.

    Granted only to a caller bound to the repository (lane, coordinator or owner; never the shared
    bearer), with a valid request, while each project has priority uses left today."""
    if not priority or caller["kind"] == "shared":
        return None
    cap = limits["hosted_build"].get("priority_per_project_per_day")
    if not cap:
        return None
    remaining = min(cap - ledger.ledger_count(day, ["hosted_build"], provider=b["provider"],
                                              project=project_id(b), reason_code="PRIORITY_GRANTED",
                                              **ledger_scope(b))
                    for b in builds)
    return {"remaining": remaining} if remaining > 0 else None


def _priority_request(open_):
    return {"field": "context.priority", "blocking": list(PRIORITY_BLOCKING), "remaining_today": open_["remaining"],
            "example": {"blocking": "continue_work", "reason": "the lane needs this branch built to continue"}}


def _allow_priority(ledger, keys, action, claim, context, caller, now, request_id, evidence, limits, metered,
                    owner, name, building, capacity, day, common):
    _record(ledger, keys, action, None, claim, context, caller, now, request_id, True, evidence, priority=True)
    return Outcome("ALLOW", "PRIORITY_GRANTED",
                   f"Allowed ahead of pacing and this project's budget: {context['priority']['blocking']}. "
                   "Counted, and recorded as a priority push.",
                   budget={"day": day, "usage": _usage(ledger, action, limits, metered, owner, name, building,
                                                       capacity, day, now)[0]}, **common)


def _budget_refusal(ledger, action, owner, name, context, exceeded, usage, day, now, common, priority_open):
    resets = datetime.fromtimestamp(now, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    resets_at = datetime.fromtimestamp(resets.timestamp() + 86400, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    advice = dict(common["advice"])
    advice["usage_by_repository"] = ledger.ledger_repositories(
        day, list(HOSTED) if action in HOSTED else [action], provider=exceeded.get("provider") or
        (exceeded.get("build") or {}).get("provider"),
        project=project_id(exceeded["build"]) if exceeded.get("build") else None)
    if exceeded.get("over_limit"):
        detail = f"The {exceeded.get('provider')} workspace is over its usage limit, so no build is started there."
        reason = "SERVICE_OVER_LIMIT"
    elif exceeded["kind"] == "service":
        detail = (f"{exceeded['provider']} has made {exceeded['used']} deployments today against this deployment's "
                  f"ceiling of {exceeded['limit']} for that service.")
        reason = "SERVICE_LIMIT_REACHED"
    else:
        detail = f"Today's {exceeded['scope']} budget for {action} is used up ({exceeded['used']} of {exceeded['limit']})."
        reason = "BUDGET_EXCEEDED"
    remedy = (f"{COLLABORATE} Commit locally and keep working; push once the budget resets at {resets_at}, "
              "with everything batched"
              + ("; if you cannot continue without this push, ask for priority (see priority_request)"
                 if priority_open else "")
              + f"; or ask the owner for a grant: {grant_command(action, owner, name, context.get('reason'))}")
    return Outcome("AUTH_REQUIRED", reason, detail, remedy,
                   budget={"day": day, "usage": usage, "exceeded": {k: v for k, v in exceeded.items() if k != "build"}},
                   grant_request=grant_request(action, owner, name, context.get("reason")), resets_at=resets_at,
                   **({"priority_request": _priority_request(priority_open)} if priority_open else {}),
                   **{**common, "advice": advice})


def advise(ledger, limits, metered, claim, context, action, building, capacity, now):
    """What the agent should know about volume and process for this request. Information only: it never
    changes the decision, and the same ledger and provider state give the same advice."""
    owner, name = claim["owner"], claim["name"]
    day = budget_day(now)
    project_usage, recommendations = [], []

    def recommend(code, text):
        if not any(r["code"] == code for r in recommendations):
            recommendations.append({"code": code, "text": text})

    for b in building:
        pid = project_id(b)
        limit, source = project_limit(ledger, limits, metered, b, now)
        used = ledger.ledger_count(day, list(HOSTED), provider=b["provider"], project=pid, **ledger_scope(b))
        hour = ledger.ledger_recent(HOSTED, b["provider"], pid, now - 3600, **ledger_scope(b))
        project_usage.append({"provider": b["provider"], "project": b["project"], "used_today": used,
                              "limit": limit, "limit_source": source,
                              "builds_last_30m": sum(1 for t in hour if t >= now - 1800),
                              "last_build_seconds_ago": int(now - hour[-1]) if hour else None})
        if len(hour) >= 3:
            recommend("BATCH_PUSHES", f"{len(hour)} builds of {b['project']} in the last hour: batch commits and "
                                      "push once when the work is ready.")
        if limit and used + 1 >= 0.8 * limit:
            recommend("NEAR_LIMIT", f"{b['project']} is at {used} of {limit} builds today: bundle the remaining "
                                    "changes into one release.")
        live = capacity.get(b["provider"]) or {}
        flying = live.get("projects_in_flight") or {}
        if flying.get(pid) or flying.get(b["project"]):
            recommend("WAIT_FOR_INFLIGHT", f"A build of {b['project']} is running: wait for it, and your next "
                                           "push carries every commit made meanwhile.")
    production = (metered.get("production_branches") or ["main"])
    branch = (context.get("ref") or "")[len("refs/heads/"):]
    if action == "hosted_build" and context.get("trigger") == "push" and branch and branch not in production and \
            any(b["provider"] == "vercel" and "every push" in (b.get("why") or "") for b in building):
        recommend("PREVIEW_BUILDS", f"This branch push builds a Vercel preview, and the merge builds production "
                                    "again. If nobody opens the preview, turn branch builds off (vercel.json "
                                    f"git.deploymentEnabled {{\"{branch}\": false}} or an ignoreCommand) and let "
                                    "the merge be the one build.")
    sha, ref = context.get("new_sha"), context.get("ref")
    other_refs = [r for r in ledger.ledger_sha_refs(list(HOSTED), owner, name, sha) if r != ref] if sha else []
    if other_refs:
        recommend("SAME_COMMIT", f"This commit was already built as {', '.join(other_refs)}: pushing the same commit "
                                 "under another branch builds it again.")
    if len(building) > 1:
        recommend("MULTI_SERVICE", "This push starts " + str(len(building)) + " builds (" +
                  ", ".join(f"{b['provider']} {b['project']}" for b in building) + "): batch commits so each "
                  "push is worth all of them.")
    hb = limits["hosted_build"]
    service = []
    for provider in sorted({b["provider"] for b in building}):
        live = capacity.get(provider) or {"source": "ledger"}
        concurrent = (hb.get("per_provider_concurrent") or {}).get(provider)
        entry = {"provider": provider, "source": live.get("source", "ledger"),
                 "ceiling": (hb.get("per_provider_per_day") or {}).get(provider),
                 "deployments_today": live["deployments_today"] if "deployments_today" in live
                 else ledger.ledger_count(day, list(HOSTED), provider=provider),
                 "in_flight": live.get("in_flight"),
                 **({"lower_bound": True} if live.get("truncated") else {})}
        service.append(entry)
        if live.get("source") == "unavailable":
            recommend("CAPACITY_UNREAD", f"ACP could not read {provider}'s live activity ({live.get('kind')}), so its "
                      "in-flight cap is not applied and its count is ACP's own ledger, which misses dashboard "
                      "redeploys: push only what must build now.")
        elif live.get("truncated"):
            recommend("CAPACITY_UNREAD", f"{provider} has more deployments today than ACP reads in one pass; "
                      f"{entry['deployments_today']} is a lower bound.")
        if concurrent and (live.get("in_flight") or 0) >= max(concurrent - 1, 1):
            recommend("SERVICE_BUSY", f"{provider} has {live['in_flight']} builds running: push later or batch.")
    resets = datetime.fromtimestamp(now, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return {"project_usage": project_usage, "service": service,
            "triggers": [{"provider": b["provider"], "project": b["project"], "would_build": True,
                          "why": b.get("why")} for b in building],
            "recommendations": recommendations,
            "resets_at": datetime.fromtimestamp(resets.timestamp() + 86400, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _record(ledger, keys, action, grant, claim, context, caller, now, request_id, counted, evidence,
            priority=False):
    for index, ((provider, project), key) in enumerate(sorted(keys.items())):
        ledger.ledger_insert({
            "record_key": key, "request_id": request_id if index == 0 else f"{request_id}.{index}",
            "action": action, "provider": provider, "project": project or None,
            "resource_owner": (claim.get("owner") or "").lower() or None,
            "resource_name": (claim.get("name") or "").lower() or None,
            "ref": context.get("ref"), "sha": context.get("new_sha"),
            "caller_kind": caller["kind"], "caller_id": caller["id"],
            "reason": context["reason"].strip(), "counted": counted,
            "reason_code": ("PRIORITY_GRANTED" if priority else "GRANT_APPLIED" if grant else "WITHIN_BUDGET")
            if counted else "NO_HOSTED_BUILD",
            "budget_day": budget_day(now), "grant_id": grant,
            "evidence_digest": evidence.get("digest"), "created_at": now})


def evaluate_local(action, claim, context, caller, limits, ledger, now, request_id, session_id,
                   admission_contract=None):
    """local_heavy_build and heavy_subagent. Local work is never blocked outright: every refusal
    names a way to keep working."""
    if ledger is None:
        fallback = ("Run it through the build register instead: reg build --label <lane/ticket> -- <command>."
                    if action == "local_heavy_build" else "Use a sonnet or haiku subagent instead.")
        return Outcome("REVERIFY_REQUIRED", "BUDGET_LEDGER_UNAVAILABLE",
                       "This ACP deployment has no shared ledger, so it cannot record this.", fallback)
    if limits is None:
        return Outcome("DENY", "BUDGET_POLICY_UNAVAILABLE",
                       "No valid signed budget policy is loaded.",
                       "Run heavy builds through reg build and use light subagents until the owner sets "
                       "ACP_BUDGET_POLICY.")
    owner, name = claim.get("owner"), claim.get("name")
    if action == "build_admission":
        key = record_key(action, context["machine_id"], context["tool_use_id"])
        outcome = decide_admission(context["admission"], admission_contract or dict(ADMISSION_CONTRACT))
        if outcome.decision == "ALLOW" and not ledger.ledger_get(key):
            _record(ledger, {("local", ""): key}, action, None, {"owner": owner, "name": name}, context, caller,
                    now, request_id, True, {})
        return outcome
    if action == "local_heavy_build":
        key = record_key(action, context["machine_id"], session_id, context["tool_use_id"])
        if ledger.ledger_get(key):
            return Outcome("ALLOW", "WITHIN_BUDGET", "Already recorded.", replayed=True)
        cap = limits["local_heavy_build"].get("per_day_total")
        used = ledger.ledger_count(budget_day(now), ["local_heavy_build"])
        if cap is not None and used >= cap:
            return Outcome("DENY", "BUDGET_EXCEEDED",
                           f"Today's heavy local builds outside the register are used up ({used} of {cap}).",
                           "Run it through the build register: reg build --label <lane/ticket> -- <command>.")
        _record(ledger, {("local", ""): key}, action, None, {"owner": owner, "name": name}, context, caller,
                now, request_id, True, {})
        return Outcome("ALLOW", "WITHIN_BUDGET", "Recorded with its reason.")

    key = record_key(action, session_id, context["tool_use_id"])
    lease = ledger.lease_get(key)
    if lease and not lease.get("released_at"):
        return Outcome("ALLOW", "WITHIN_BUDGET", "Already leased.", lease_id=key, replayed=True)
    if lease:
        return Outcome("DENY", "INVOCATION_REUSED",
                       "This tool_use_id already ran a heavy subagent, and that lease was released.",
                       "Send the id of this tool call, then ask again.")
    cap = limits["heavy_subagent"].get("concurrent_per_session")
    open_now = ledger.leases_open(session_id, now)
    if cap is not None and open_now >= cap:
        return Outcome("DENY", "SUBAGENT_LIMIT_REACHED",
                       f"This session already has {open_now} heavy subagents running (limit {cap}).",
                       "Wait for one to finish (its lease is released when it stops), or start this one on "
                       "sonnet or haiku, which needs no ACP decision.")
    ledger.lease_open({"lease_key": key, "session_id": session_id, "model": context["model"],
                       "reason": context["reason"].strip(), "opened_at": now, "expires_at": now + LEASE_SECONDS})
    _record(ledger, {("claude", ""): key}, action, None, {"owner": owner, "name": name}, context, caller,
            now, request_id, True, {})
    return Outcome("ALLOW", "WITHIN_BUDGET", f"Leased for up to {LEASE_SECONDS // 3600} hours.",
                   lease_id=key, lease_expires_in=LEASE_SECONDS)


class MemoryLedger:
    """The ledger contract, in process. The file backend has no shared ledger and does not use this;
    tests and single-process tools do."""

    def __init__(self):
        self.rows, self.grants, self.leases = {}, {}, {}

    def ledger_get(self, key):
        return self.rows.get(key)

    def ledger_insert(self, row):
        if row["record_key"] in self.rows or any(r["request_id"] == row["request_id"] for r in self.rows.values()):
            raise ValueError("ledger row already exists")
        self.rows[row["record_key"]] = dict(row)

    def ledger_count(self, day, actions, owner=None, name=None, provider=None, distinct_sha=False,
                     project=None, reason_code=None):
        rows = [r for r in self.rows.values() if r["counted"] and r["budget_day"] == day
                and r["action"] in actions
                and (owner is None or (r["resource_owner"] or "").lower() == owner.lower())
                and (name is None or (r["resource_name"] or "").lower() == name.lower())
                and (provider is None or r["provider"] == provider)
                and (project is None or r.get("project") == project)
                and (reason_code is None or r["reason_code"] == reason_code)]
        return len({r["sha"] for r in rows}) if distinct_sha else len(rows)

    def _in_repository(self, row, owner, name):
        return (owner is None or (row["resource_owner"] or "").lower() == owner.lower()) and \
            (name is None or (row["resource_name"] or "").lower() == name.lower())

    def ledger_recent(self, actions, provider, project, since, owner=None, name=None):
        return sorted(r["created_at"] for r in self.rows.values()
                      if r["counted"] and r["action"] in actions and r["provider"] == provider
                      and r.get("project") == project and r["created_at"] >= since
                      and self._in_repository(r, owner, name))

    def ledger_project_days(self, actions, provider, project, days, owner=None, name=None):
        counts = {}
        for r in self.rows.values():
            if r["counted"] and r["action"] in actions and r["provider"] == provider and \
                    r.get("project") == project and r["budget_day"] in days and self._in_repository(r, owner, name):
                counts[r["budget_day"]] = counts.get(r["budget_day"], 0) + 1
        return counts

    def ledger_sha_refs(self, actions, owner, name, sha):
        return sorted({r["ref"] for r in self.rows.values()
                       if r["counted"] and r["action"] in actions and r["ref"] and r["sha"] == sha
                       and (r["resource_owner"] or "") == (owner or "").lower()
                       and (r["resource_name"] or "") == (name or "").lower()})

    def ledger_repositories(self, day, actions, provider=None, project=None):
        counts = {}
        for r in self.rows.values():
            if r["counted"] and r["budget_day"] == day and r["action"] in actions and r["resource_owner"] and \
                    (provider is None or r["provider"] == provider) and (project is None or r.get("project") == project):
                slug = f"{r['resource_owner']}/{r['resource_name']}"
                counts[slug] = counts.get(slug, 0) + 1
        return [{"repository": k, "used": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))][:20]

    def grant_issue(self, row):
        created = row["grant_id"] not in self.grants
        self.grants.setdefault(row["grant_id"], dict(row))
        return {**self.grants[row["grant_id"]], "created": created}

    def grant_take(self, action, owner, name, now):
        for grant_id in sorted(self.grants):
            g = self.grants[grant_id]
            if g["action"] == action and g["uses_left"] > 0 and g["expires_at"] > now and \
                    (g["resource_owner"] is None or ((g["resource_owner"] or "").lower() == (owner or "").lower()
                                                     and (g["resource_name"] or "").lower() == (name or "").lower())):
                g["uses_left"] -= 1
                return grant_id
        return None

    def lease_get(self, key):
        return self.leases.get(key)

    def lease_open(self, row):
        if row["lease_key"] in self.leases:                  # as the database's primary key does
            raise ValueError("lease already exists")
        self.leases[row["lease_key"]] = {**row, "released_at": None}

    def leases_open(self, session_id, now):
        return sum(1 for l in self.leases.values()
                   if l["session_id"] == session_id and l["released_at"] is None and l["expires_at"] > now)

    def lease_release(self, key, now):
        lease = self.leases.get(key)
        if not lease or lease["released_at"] is not None:
            return False
        lease["released_at"] = now
        return True

    def ledger_day(self, day):
        return [r for r in self.rows.values() if r["budget_day"] == day]
