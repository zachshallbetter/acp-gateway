"""Metered actions: what costs money or reaches production, decided against budgets.

ACP records every metered action it allows, once, under a key built from
explicit fields. It counts those records against per-repository, per-provider
and deployment-wide daily limits. Past a limit it asks the owner (AUTH_REQUIRED)
unless an owner grant covers the action. Everyday work inside a budget needs no
one's approval.

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
INVOCATION_TRIGGERS = frozenset({"cli_deploy", "railway_up", "workflow_dispatch"})
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
DEFAULT_LIMITS = {
    "hosted_build": {"per_repo_per_day": 20, "per_day_total": 60,
                     "per_provider_per_day": {"vercel": 40, "railway": 10, "github_actions": 30}},
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
                            "reason", "machine_id", "admission"})
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
        if not _valid_ref(context.get("ref")):
            raise MeteringError(f"{action} needs context.ref as a full refs/heads/... name.", "context.ref",
                                "Send the branch the push, merge or run targets, e.g. refs/heads/main.")
        if not FULL_SHA.match(context.get("new_sha") or ""):
            raise MeteringError(f"{action} needs context.new_sha as a full commit id.", "context.new_sha",
                                "Send the exact 40-character commit the build would use (git rev-parse HEAD).")
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
    unknown = set(raw) - {"production_branches", "hosted_build", "production_merge", "providers"}
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
    allowed = {"per_repo_per_day", "per_day_total", "per_provider_per_day", "concurrent_per_session"}
    merged = json.loads(json.dumps(DEFAULT_LIMITS))
    for action, block in raw.items():
        if not isinstance(block, dict) or set(block) - allowed:
            raise ValueError(f"limits.{action} may carry only {', '.join(sorted(allowed))}")
        for key, value in block.items():
            if key == "per_provider_per_day":
                if not isinstance(value, dict) or set(value) - set(HOSTED_PROVIDERS) or \
                        not all(isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1000
                                for v in value.values()):
                    raise ValueError(f"limits.{action}.per_provider_per_day must map providers to 0..1000")
                merged[action][key] = dict(value)
            elif value is None:
                merged[action].pop(key, None)                # explicitly unlimited
            elif not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 1000:
                raise ValueError(f"limits.{action}.{key} must be an integer 0..1000 or null")
            else:
                merged[action][key] = value
    return merged


def record_key(*fields):
    """sha256 of the explicit key fields, in the order given. No time, no randomness."""
    canonical = json.dumps([("" if f is None else str(f)) for f in fields], separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def budget_day(now):
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")


def grant_command(action, owner=None, name=None):
    repo = f" --repo {owner}/{name}" if owner and name else ""
    return (f"python3 scripts/policy-admin.py budget-grant --action {action}{repo} --uses 1 --expires 2h "
            f"--reason \"<why>\" --apply")


class Outcome:
    """One metered decision, before the gateway wraps it in its response envelope."""

    def __init__(self, decision, reason, detail, remedy=None, **extra):
        self.decision, self.reason, self.detail, self.remedy, self.extra = decision, reason, detail, remedy, extra


def _caller_may_reach_production(caller):
    return caller["kind"] in PRODUCTION_CALLERS


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
    branch = context["ref"][len("refs/heads/"):]
    trigger = context.get("trigger")
    production = action == "production_merge" or branch in metered["production_branches"] \
        or trigger in BRANCH_INDEPENDENT_TRIGGERS

    if not evidence.get("available"):
        reason = "PROVIDER_RESPONSE_DIVERGED" if evidence.get("kind") == "DIVERGED" else "PROVIDER_EVIDENCE_UNAVAILABLE"
        return Outcome("REVERIFY_REQUIRED", reason,
                       f"ACP could not read {evidence.get('provider') or 'provider'} evidence "
                       f"({evidence.get('detail') or 'unavailable'}), so it cannot tell whether this would "
                       "start a paid build. No paid build is authorized without that evidence.",
                       "Retry in a minute. If it persists, the owner checks the provider credential "
                       "(ACP_VERCEL_TOKEN / ACP_RAILWAY_TOKEN by name) and GET /internal/posture for the error.",
                       provider_error={"provider": evidence.get("provider"), "kind": evidence.get("kind")})

    # What builds is the repository's evidence for this trigger, never the caller's choice of
    # provider: a push builds every connected provider whichever one the caller names.
    building = [b for b in evidence["builds"] if b["would_build"]]
    if trigger in TRIGGER_PROVIDER and not building:
        return Outcome("DENY", "PROVIDER_NOT_METERED",
                       f"{trigger} deploys to {TRIGGER_PROVIDER[trigger]}, but the policy meters no "
                       f"{TRIGGER_PROVIDER[trigger]} project for {owner}/{name}, so ACP cannot count it.",
                       f"The owner enrolls the {TRIGGER_PROVIDER[trigger]} project for this repository "
                       f"(scripts/policy-admin.py enroll), then ask again.",
                       builds=evidence["builds"])
    # A push of one commit builds once, so asking again is a replay. A CLI deploy or a manual
    # dispatch starts a new run each time, so each invocation is its own record.
    invocation = (context.get("tool_use_id") or request_id) if trigger in INVOCATION_TRIGGERS else None
    keys = {b["provider"]: record_key(action, b["provider"], owner.lower(), name.lower(), context["ref"],
                                      context["new_sha"], context.get("workflow"), context.get("run_id"),
                                      *([invocation] if invocation else []))
            for b in building}
    if not building:
        keys = {"local": record_key(action, "local", owner.lower(), name.lower(), context["ref"],
                                    context["new_sha"], context.get("workflow"), context.get("run_id"),
                                    *([invocation] if invocation else []))}
    # Replay: the same action asked again is answered from the record, never counted twice.
    # Authority is per caller: a record made for a coordinator does not authorize a lane.
    prior = [ledger.ledger_get(k) for k in keys.values()]
    if all(prior) and production and not _caller_may_reach_production(caller):
        return Outcome("AUTH_REQUIRED", "OWNER_REQUIRED",
                       f"This deploys production ({branch}). It is already authorized for another caller, and that "
                       f"authorization is not transferable; this caller is a {caller['kind']} caller.",
                       f"Leave it to the caller that holds the authorization, or ask the owner for a grant: "
                       f"{grant_command(action, owner, name)}",
                       builds=evidence["builds"], caller_kind=caller["kind"])
    if all(prior):
        return Outcome("ALLOW", prior[0]["reason_code"],
                       "Already authorized for this exact commit; the earlier record stands and is not counted again.",
                       builds=evidence["builds"], replayed=True)

    if not building:
        _record(ledger, keys, action, None, claim, context, caller, now, request_id, False, evidence)
        return Outcome("ALLOW", "NO_HOSTED_BUILD",
                       "No connected provider builds this. Nothing is counted against a budget.",
                       builds=evidence["builds"])

    # Unbounded workflows are what burned 4,000 Actions hours. The caller can bound them itself.
    unbounded = [w for w in evidence.get("workflows", [])
                 if w.get("would_run") and (w.get("jobs_without_timeout") or not w.get("has_concurrency"))]
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
                       builds=evidence["builds"])

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
                           f"{grant_command(action, owner, name)}",
                           builds=evidence["builds"], caller_kind=caller["kind"])

    day = budget_day(now)
    usage, exceeded = _usage(ledger, action, limits, metered, owner, name, building, day)
    if exceeded and grant is None and action in AWARE_BUDGETS and _caller_may_reach_production(caller):
        # A merge costs nothing by itself (the builds it starts are metered as hosted_build), so
        # for the coordinator or the owner its daily count is awareness, not a gate: counted,
        # reported and flagged, never refused.
        _record(ledger, keys, action, None, claim, context, caller, now, request_id, True, evidence)
        return Outcome("ALLOW", "OVER_BUDGET_NOTED",
                       f"Allowed and counted past today's {exceeded['scope']} count for {action} "
                       f"({exceeded['used']} of {exceeded['limit']}). The count is shown in GET /internal/budget; "
                       "nothing is refused for it.",
                       budget={"day": day, "usage": _usage(ledger, action, limits, metered, owner, name, building,
                                                           day)[0], "exceeded": exceeded},
                       builds=evidence["builds"])
    if exceeded and grant is None:
        grant = ledger.grant_take(action, owner, name, now)
        if grant is None:
            return Outcome("AUTH_REQUIRED", "BUDGET_EXCEEDED",
                           f"Today's {exceeded['scope']} budget for {action} is used up "
                           f"({exceeded['used']} of {exceeded['limit']}).",
                           f"Batch this with later work and push once the budget resets at 00:00 UTC, or ask the "
                           f"owner for a grant: {grant_command(action, owner, name)}",
                           budget={"day": day, "usage": usage, "exceeded": exceeded}, builds=evidence["builds"])
    _record(ledger, keys, action, grant, claim, context, caller, now, request_id, True, evidence)
    reason = "GRANT_APPLIED" if grant else "WITHIN_BUDGET"
    return Outcome("ALLOW", reason,
                   "Allowed under an owner grant." if grant else "Allowed within today's budget.",
                   budget={"day": day, "usage": _usage(ledger, action, limits, metered, owner, name, building, day)[0]},
                   builds=evidence["builds"], grant_id=grant)


def _usage(ledger, action, limits, metered, owner, name, building, day):
    """Usage after this request would be counted, and the first limit it would cross."""
    hosted = ("hosted_build", "production_merge")
    checks = []
    if action == "production_merge":
        per_repo = (metered.get("production_merge") or {}).get("per_day",
                                                                limits["production_merge"].get("per_repo_per_day"))
        checks.append(("repository", per_repo, ledger.ledger_count(day, ["production_merge"], owner=owner,
                                                                    name=name, distinct_sha=True), 1))
    if action in hosted:
        hb = limits["hosted_build"]
        per_repo = (metered.get("hosted_build") or {}).get("per_day", hb.get("per_repo_per_day"))
        checks.append(("repository hosted-build", per_repo,
                       ledger.ledger_count(day, list(hosted), owner=owner, name=name), len(building)))
        checks.append(("deployment-wide hosted-build", hb.get("per_day_total"),
                       ledger.ledger_count(day, list(hosted)), len(building)))
        for b in building:
            checks.append((f"{b['provider']}", (hb.get("per_provider_per_day") or {}).get(b["provider"]),
                           ledger.ledger_count(day, list(hosted), provider=b["provider"]), 1))
    if action == "manual_ci":
        checks.append(("deployment-wide manual CI", limits["manual_ci"].get("per_day_total"),
                       ledger.ledger_count(day, ["manual_ci"]), 1))
    usage, exceeded = [], None
    for scope, limit, used, adding in checks:
        usage.append({"scope": scope, "used": used, "limit": limit})
        if limit is not None and used + adding > limit and exceeded is None:
            exceeded = {"scope": scope, "used": used, "limit": limit}
    return usage, exceeded


def _record(ledger, keys, action, grant, claim, context, caller, now, request_id, counted, evidence):
    for index, (provider, key) in enumerate(sorted(keys.items())):
        ledger.ledger_insert({
            "record_key": key, "request_id": request_id if index == 0 else f"{request_id}.{index}",
            "action": action, "provider": provider,
            "resource_owner": (claim.get("owner") or "").lower() or None,
            "resource_name": (claim.get("name") or "").lower() or None,
            "ref": context.get("ref"), "sha": context.get("new_sha"),
            "caller_kind": caller["kind"], "caller_id": caller["id"],
            "reason": context["reason"].strip(), "counted": counted,
            "reason_code": ("GRANT_APPLIED" if grant else "WITHIN_BUDGET") if counted else "NO_HOSTED_BUILD",
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
            _record(ledger, {"local": key}, action, None, {"owner": owner, "name": name}, context, caller,
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
        _record(ledger, {"local": key}, action, None, {"owner": owner, "name": name}, context, caller,
                now, request_id, True, {})
        return Outcome("ALLOW", "WITHIN_BUDGET", "Recorded with its reason.")

    key = record_key(action, session_id, context["tool_use_id"])
    lease = ledger.lease_get(key)
    if lease and not lease.get("released_at"):
        return Outcome("ALLOW", "WITHIN_BUDGET", "Already leased.", lease_id=key, replayed=True)
    cap = limits["heavy_subagent"].get("concurrent_per_session")
    open_now = ledger.leases_open(session_id, now)
    if cap is not None and open_now >= cap:
        return Outcome("DENY", "SUBAGENT_LIMIT_REACHED",
                       f"This session already has {open_now} heavy subagents running (limit {cap}).",
                       "Wait for one to finish (its lease is released when it stops), or start this one on "
                       "sonnet or haiku, which needs no ACP decision.")
    ledger.lease_open({"lease_key": key, "session_id": session_id, "model": context["model"],
                       "reason": context["reason"].strip(), "opened_at": now, "expires_at": now + LEASE_SECONDS})
    _record(ledger, {"claude": key}, action, None, {"owner": owner, "name": name}, context, caller,
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

    def ledger_count(self, day, actions, owner=None, name=None, provider=None, distinct_sha=False):
        rows = [r for r in self.rows.values() if r["counted"] and r["budget_day"] == day
                and r["action"] in actions
                and (owner is None or (r["resource_owner"] or "").lower() == owner.lower())
                and (name is None or (r["resource_name"] or "").lower() == name.lower())
                and (provider is None or r["provider"] == provider)]
        return len({r["sha"] for r in rows}) if distinct_sha else len(rows)

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
