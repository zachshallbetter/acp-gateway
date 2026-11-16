"""Metered actions: budgets, idempotent recording, caller identity and remedies.

Provider evidence and GitHub verification are injected; the ledger is the
in-process MemoryLedger. Nothing here touches the network or a real credential.
"""
import hashlib, hmac, http.client, json, os, sys, threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402
import metering  # noqa: E402

OWNER, REPO = "Example-Org", "Widget"
REMOTE = f"https://github.com/{OWNER}/{REPO}.git"
KEY = "policy-signing-key-that-is-long-enough"
SHA = "a" * 40
SHA2 = "b" * 40
NOW = 1_800_000_000.0
TOKEN = "test-token-long-enough-to-scrub"


def signed(body):
    digest = gateway.policy_digest(body)
    return {**body, "signature": hmac.new(KEY.encode(), digest.encode(), hashlib.sha256).hexdigest()}


def policy(**overrides):
    body = {"policy_id": "widget", "version": 1, "status": "active",
            "repository": {"owner": OWNER, "name": REPO, "canonical_remote": REMOTE},
            "protected_actions": list(gateway.DEFAULT_PROTECTED_ACTIONS) +
                                 ["hosted_build", "production_merge", "manual_ci"],
            "metered": {"production_branches": ["main"], "providers": {"vercel": {"project_ids": ["prj_widget"]}}}}
    body.update(overrides)
    return body


def budget(limits=None):
    return signed({"budget_policy_id": "acp-budgets", "version": 1, "limits": limits or {}})


def env(policy_body=None, limits=None, budget_doc=True, **extra):
    base = {"ACP_GATEWAY_TOKEN": TOKEN, "ACP_POLICY": json.dumps(signed(policy_body or policy())),
            "ACP_POLICY_SIGNING_KEY": KEY, "ACP_POLICY_SCOPE": OWNER,
            "ACP_BUDGET_POLICY": json.dumps(budget(limits)) if budget_doc else ""}
    base.update(extra)
    return patch.dict(os.environ, base, clear=False)


# Builds of one project are paced, so a test that makes several in a row advances a clock between them
# (ten minutes each, well inside one budget day) unless it passes `now` itself.
_CLOCK = {"now": NOW}


def tick():
    _CLOCK["now"] += 600
    return _CLOCK["now"]


def fresh():
    _CLOCK["now"] = NOW
    gateway._REGISTRY.update(key=None, value=None)
    gateway._BUDGETS.update(key=None, value=None)
    gateway._CALLERS.update(key=None, value=None)
    gateway._TRUST_STATE.update(loaded=True, repositories={})
    gateway._SECURITY.update(loaded=True, records={}, degraded=None)
    gateway._LAST_DENIAL.clear()
    gateway._PROVIDER.update(status="UNKNOWN", changed_at=None)
    del gateway.AUDIT[:]


def verifier():
    def verify(claimed, context=None, policy_body=None):
        return {"available": True, "installed": True,
                "repository": {"owner": OWNER, "name": REPO, "default_branch": "main"}}
    return verify


def evidence(builds=None, workflows=None, available=True, kind=None, capacity=None):
    def provide(action, policy_body, claim, context):
        if not available:
            return {"available": False, "kind": kind or "UNAVAILABLE", "provider": "vercel", "detail": "HTTP 503"}
        rows = builds if builds is not None else [
            {"provider": "vercel", "project": "widget", "would_build": True, "why": "builds every push"}]
        out = {"available": True, "builds": rows, "workflows": workflows or [], "digest": "d" * 64}
        if capacity is not None:
            out["capacity"] = capacity
        return out
    return provide


def request(action="hosted_build", ref="refs/heads/feature", sha=SHA, **context):
    ctx = {"trigger": {"hosted_build": "push", "production_merge": "merge", "manual_ci": "workflow_dispatch"}
           .get(action), "ref": ref, "new_sha": sha, "reason": "ship the feature branch preview"}
    ctx.update(context)
    return {"agent_id": "lane-a", "actor_id": "github-user:1", "session_id": "session-1", "action": action,
            "repository_claim": {"owner": OWNER, "name": REPO, "remote_url": REMOTE, "head_sha": sha},
            "context": {k: v for k, v in ctx.items() if v is not None}}


def decide(body, ledger, caller=None, provide=None, now=None):
    now = tick() if now is None else now
    return gateway.authorize(body, verifier=verifier(), now=now, caller=caller,
                             provider_evidence=provide or evidence(), ledger=ledger)


COORDINATOR = {"kind": "coordinator", "id": "coord", "repos": [f"{OWNER}/*"]}
LANE = {"kind": "lane", "id": "lane-a", "repos": [f"{OWNER}/{REPO}"]}


# ---- shape -----------------------------------------------------------------
def test_metered_request_without_reason_is_a_400_with_remedy():
    with env():
        fresh()
        body = request(reason=None)
        body["context"].pop("reason", None)
        try:
            decide(body, metering.MemoryLedger())
        except gateway.TargetError as exc:
            assert exc.status == 400 and "context.reason" in str(exc.context.get("field"))
            assert exc.remedy
        else:
            raise AssertionError("expected INVALID_REQUEST")


def test_hosted_build_needs_full_sha_and_ref():
    with env():
        fresh()
        for bad in (request(sha="abc123"), request(ref="feature")):
            try:
                decide(bad, metering.MemoryLedger())
            except gateway.TargetError as exc:
                assert exc.status == 400 and exc.remedy
            else:
                raise AssertionError("expected INVALID_REQUEST")


# ---- allow, record once, count -------------------------------------------
def test_within_budget_allows_and_records_once():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        first = decide(request(), ledger)
        assert first["decision"] == "ALLOW" and first["reason"] == "WITHIN_BUDGET", first
        assert first["authorized_action"]["action"] == "hosted_build"
        assert first["authorized_action"]["new_sha"] == SHA
        again = decide(request(), ledger, now=NOW + 5)
        assert again["decision"] == "ALLOW" and again.get("replayed") is True
        assert ledger.ledger_count(metering.budget_day(NOW), ["hosted_build"]) == 1


def test_no_provider_builds_is_allowed_and_not_counted():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        result = decide(request(), ledger, provide=evidence(builds=[
            {"provider": "vercel", "project": "widget", "would_build": False, "why": "branch turned off"}]))
        assert result["decision"] == "ALLOW" and result["reason"] == "NO_HOSTED_BUILD"
        assert ledger.ledger_count(metering.budget_day(NOW), ["hosted_build"]) == 0


def test_repository_budget_past_limit_asks_the_owner_with_a_grant_command():
    with env(policy_body=policy(metered={"production_branches": ["main"], "hosted_build": {"per_day": 2},
                                         "providers": {"vercel": {"project_ids": ["prj_widget"]}}})):
        fresh()
        ledger = metering.MemoryLedger()
        for sha in ("1" * 40, "2" * 40):
            assert decide(request(sha=sha), ledger)["decision"] == "ALLOW"
        over = decide(request(sha="3" * 40), ledger)
        assert over["decision"] == "AUTH_REQUIRED" and over["reason"] == "BUDGET_EXCEEDED", over
        assert "budget-grant --action hosted_build --repo Example-Org/Widget" in over["remedy"]
        assert over["budget"]["exceeded"]["limit"] == 2
        grant = over["grant_request"]
        assert grant["repository"] == "Example-Org/Widget" and grant["reason"] == "ship the feature branch preview"
        assert grant["command"] in over["remedy"] and "<" not in grant["command"], "no placeholder to fill in"
        assert grant["command"].startswith(metering.GRANT_COMMAND_PREFIX)
        assert "--reason 'ship the feature branch preview' --apply" in grant["command"]
        with patch.dict(os.environ, {"ACP_GRANT_COMMAND_PREFIX": "python3 /opt/acp/policy-admin.py"}):
            assert metering.grant_command("hosted_build", OWNER, REPO, "x").startswith(
                "python3 /opt/acp/policy-admin.py budget-grant --action hosted_build")
        assert "approve one hosted_build" in metering.grant_command("hosted_build", OWNER, REPO, "")


def test_owner_grant_lets_one_more_through_and_is_used_up():
    with env(policy_body=policy(metered={"production_branches": ["main"], "hosted_build": {"per_day": 1},
                                         "providers": {"vercel": {"project_ids": ["prj_widget"]}}})):
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40), ledger)["decision"] == "ALLOW"
        ledger.grant_issue({"grant_id": "g-0000000000000001", "action": "hosted_build",
                            "resource_owner": OWNER.lower(), "resource_name": REPO.lower(), "uses_total": 1,
                            "uses_left": 1, "issued_at": NOW, "expires_at": NOW + 3600, "issued_by": "owner",
                            "reason": "release day"})
        granted = decide(request(sha="2" * 40), ledger)
        assert granted["decision"] == "ALLOW" and granted["reason"] == "GRANT_APPLIED", granted
        assert decide(request(sha="3" * 40), ledger)["decision"] == "AUTH_REQUIRED"


def test_a_service_ceiling_counts_every_repository_on_that_service():
    with env(limits={"hosted_build": {"per_provider_per_day": {"vercel": 1}}}):
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40), ledger)["decision"] == "ALLOW"
        over = decide(request(sha="2" * 40), ledger, provide=evidence(builds=[
            {"provider": "vercel", "project": "other-site", "project_id": "prj_other", "would_build": True,
             "why": "builds every push"}]))
        assert over["decision"] == "AUTH_REQUIRED" and over["reason"] == "SERVICE_LIMIT_REACHED", over
        assert over["budget"]["exceeded"]["scope"] == "service vercel"
        assert "priority_request" not in over, "priority never waives a service ceiling"


# ---- per-project budgets, pacing, priority and advice ----------------------
SITE = {"provider": "vercel", "project": "site", "project_id": "prj_site", "would_build": True,
        "why": "Vercel builds every push to a connected repository"}
DOCS = {"provider": "vercel", "project": "docs", "project_id": "prj_docs", "would_build": True,
        "why": "Vercel builds every push to a connected repository"}


def test_one_projects_budget_never_refuses_another_project():
    with env(limits={"hosted_build": {"per_project_per_day": 2}}):
        fresh()
        ledger = metering.MemoryLedger()
        for sha in ("1" * 40, "2" * 40):
            assert decide(request(sha=sha), ledger, provide=evidence(builds=[SITE]))["decision"] == "ALLOW"
        site = decide(request(sha="3" * 40), ledger, provide=evidence(builds=[SITE]))
        assert site["reason"] == "BUDGET_EXCEEDED" and site["budget"]["exceeded"]["scope"] == "project vercel/site"
        docs = decide(request(sha="4" * 40), ledger, provide=evidence(builds=[DOCS]))
        assert docs["decision"] == "ALLOW" and docs["reason"] == "WITHIN_BUDGET", docs
        totals = {u["scope"]: u for u in docs["budget"]["usage"]}
        assert totals["deployment-wide hosted-build"]["enforced"] is False, "totals are reported, not enforced"


def test_a_projects_default_budget_follows_its_own_history():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        for index in range(20):                                   # 20 builds of prj_site yesterday
            ledger.ledger_insert({"record_key": f"{index:064x}", "request_id": f"r{index}", "action": "hosted_build",
                                  "provider": "vercel", "project": "prj_site", "resource_owner": "example-org",
                                  "resource_name": "widget", "ref": "refs/heads/x", "sha": "c" * 40,
                                  "caller_kind": "lane", "caller_id": "l", "reason": "earlier work today",
                                  "counted": True, "reason_code": "WITHIN_BUDGET",
                                  "budget_day": metering.budget_day(NOW - 86400), "grant_id": None,
                                  "evidence_digest": None, "created_at": NOW - 86400})
        out = decide(request(), ledger, provide=evidence(builds=[SITE]))
        usage = {u["scope"]: u for u in out["budget"]["usage"]}["project vercel/site"]
        assert usage["limit"] == 30 and usage["limit_source"].startswith("history"), usage
        quiet = decide(request(sha="2" * 40), ledger, provide=evidence(builds=[DOCS]))
        assert {u["scope"]: u for u in quiet["budget"]["usage"]}["project vercel/docs"]["limit"] == 15, "the floor"


def test_a_project_override_in_the_repository_policy_wins():
    metered = {"production_branches": ["main"], "projects": {"prj_site": {"per_day": 1}},
               "providers": {"vercel": {"project_ids": ["prj_site", "prj_docs"]}}}
    with env(policy_body=policy(metered=metered)):
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40), ledger, provide=evidence(builds=[SITE]))["decision"] == "ALLOW"
        assert decide(request(sha="2" * 40), ledger, provide=evidence(builds=[SITE]))["reason"] == "BUDGET_EXCEEDED"


def test_record_keys_are_unchanged_for_one_project_and_distinct_for_several():
    context = {"ref": "refs/heads/feature", "new_sha": SHA}
    before = metering.record_key("hosted_build", "vercel", OWNER.lower(), REPO.lower(), "refs/heads/feature", SHA,
                                 None, None)
    keys = metering._record_keys("hosted_build", OWNER, REPO, context, None, [SITE])
    assert keys == {("vercel", "prj_site"): before}, "a single project keeps the key every earlier record has"
    both = metering._record_keys("hosted_build", OWNER, REPO, context, None, [SITE, DOCS])
    assert len(set(both.values())) == 2 and before not in both.values()


def test_two_projects_of_one_repository_are_two_records():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        out = decide(request(), ledger, provide=evidence(builds=[SITE, DOCS]))
        assert out["decision"] == "ALLOW", out
        rows = ledger.ledger_day(metering.budget_day(NOW))
        assert sorted(r["project"] for r in rows) == ["prj_docs", "prj_site"]
        assert any(r["code"] == "MULTI_SERVICE" for r in out["advice"]["recommendations"])


def test_builds_of_one_project_are_spaced_and_priority_waives_the_spacing():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40), ledger, caller=LANE, now=NOW)["decision"] == "ALLOW"
        paced = decide(request(sha="2" * 40), ledger, caller=LANE, now=NOW + 30)
        assert paced["decision"] == "REVERIFY_REQUIRED" and paced["reason"] == "BUILD_PACED", paced
        assert paced["retry_after"] == 91 and paced["priority_request"]["remaining_today"] == 3
        ask = {"blocking": "continue_work", "reason": "the lane needs CI on this branch to continue"}
        granted = decide(request(sha="2" * 40, priority=ask), ledger, caller=LANE, now=NOW + 31)
        assert granted["decision"] == "ALLOW" and granted["reason"] == "PRIORITY_GRANTED", granted
        row = [r for r in ledger.ledger_day(metering.budget_day(NOW)) if r["sha"] == "2" * 40][0]
        assert row["reason_code"] == "PRIORITY_GRANTED" and row["counted"]
        later = decide(request(sha="3" * 40, priority=ask), ledger, caller=LANE, now=NOW + 1000)
        assert later["reason"] == "WITHIN_BUDGET", "priority is not spent when nothing needed waiving"


def test_priority_is_bounded_per_project_and_never_for_the_shared_bearer():
    ask = {"blocking": "fix", "reason": "the production fix cannot wait for spacing"}
    with env(limits={"hosted_build": {"priority_per_project_per_day": 1}}):
        fresh()
        ledger = metering.MemoryLedger()
        decide(request(sha="1" * 40), ledger, caller=LANE, now=NOW)
        assert decide(request(sha="2" * 40, priority=ask), ledger, caller=LANE, now=NOW + 10)["reason"] == \
            "PRIORITY_GRANTED"
        spent = decide(request(sha="3" * 40, priority=ask), ledger, caller=LANE, now=NOW + 20)
        assert spent["reason"] == "BUILD_PACED" and "priority_request" not in spent, spent
        shared = decide(request(sha="4" * 40, priority=ask), ledger, caller=None, now=NOW + 30)
        assert shared["reason"] == "BUILD_PACED" and "priority_request" not in shared


def test_a_burst_is_deferred_even_with_priority():
    ask = {"blocking": "continue_work", "reason": "the lane needs this branch built to continue"}
    with env(limits={"hosted_build": {"min_spacing_seconds": 0}}):
        fresh()
        ledger = metering.MemoryLedger()
        for n in range(5):
            assert decide(request(sha=str(n) * 40), ledger, caller=LANE, now=NOW + n * 60)["decision"] == "ALLOW"
        burst = decide(request(sha="9" * 40, priority=ask), ledger, caller=LANE, now=NOW + 300)
        assert burst["decision"] == "REVERIFY_REQUIRED" and burst["reason"] == "BUILD_BURST", burst
        assert burst["retry_after"] == 1501 and "priority_request" not in burst


def test_a_build_already_running_defers_the_next_push():
    flying = [{"provider": "vercel", "source": "live", "deployments_today": 3, "in_flight": 1,
               "projects_in_flight": {"prj_site": 1}}]
    with env():
        fresh()
        out = decide(request(), metering.MemoryLedger(), caller=LANE, provide=evidence(builds=[SITE], capacity=flying))
        assert out["decision"] == "REVERIFY_REQUIRED" and out["reason"] == "BUILD_IN_FLIGHT", out
        assert out["retry_after"] == 60 and out["priority_request"]
        assert any(r["code"] == "WAIT_FOR_INFLIGHT" for r in out["advice"]["recommendations"])


def test_the_service_ceiling_uses_the_providers_own_count_and_railway_over_limit():
    busy = [{"provider": "vercel", "source": "live", "deployments_today": 150, "in_flight": 0, "projects_in_flight": {}}]
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        out = decide(request(), ledger, caller=COORDINATOR, provide=evidence(builds=[SITE], capacity=busy))
        assert out["reason"] == "SERVICE_LIMIT_REACHED", out
        assert {u["scope"]: u for u in out["budget"]["usage"]}["service vercel"]["source"] == "provider"
        railway = {"provider": "railway", "project": "api", "project_id": "rw-1", "would_build": True, "why": "x"}
        over = decide(request(trigger="railway_up", ref=None), ledger, caller=COORDINATOR,
                      provide=evidence(builds=[railway], capacity=[
                          {"provider": "railway", "source": "live", "deployments_today": 1, "over_limit": True}]))
        assert over["decision"] == "AUTH_REQUIRED" and over["reason"] == "SERVICE_OVER_LIMIT", over
        down = [{"provider": "vercel", "source": "unavailable", "detail": "HTTP 503"}]
        fallback = decide(request(sha="5" * 40), ledger, caller=COORDINATOR,
                          provide=evidence(builds=[SITE], capacity=down))
        assert fallback["decision"] == "ALLOW", "an unreadable service falls back to ACP's ledger"


def test_a_build_slot_is_deferred_when_the_service_is_saturated():
    full = [{"provider": "vercel", "source": "live", "deployments_today": 10, "in_flight": 4, "projects_in_flight": {}}]
    with env():
        fresh()
        out = decide(request(), metering.MemoryLedger(), caller=LANE, provide=evidence(builds=[SITE], capacity=full))
        assert out["decision"] == "REVERIFY_REQUIRED" and out["reason"] == "SERVICE_AT_CAPACITY", out
        assert out["retry_after"] == 120 and "priority_request" not in out
        assert any(r["code"] == "SERVICE_BUSY" for r in out["advice"]["recommendations"])


def test_advice_names_previews_repeat_commits_and_batching():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        first = decide(request(sha="1" * 40), ledger, caller=LANE, provide=evidence(builds=[SITE]))
        assert any(r["code"] == "PREVIEW_BUILDS" for r in first["advice"]["recommendations"]), first["advice"]
        assert first["advice"]["resets_at"] == "2027-01-16T00:00:00Z"
        for sha in ("2" * 40, "3" * 40):
            decide(request(sha=sha), ledger, caller=LANE, provide=evidence(builds=[SITE]))
        again = decide(request(ref="refs/heads/other", sha="3" * 40), ledger, caller=LANE,
                       provide=evidence(builds=[SITE]))
        codes = [r["code"] for r in again["advice"]["recommendations"]]
        assert "SAME_COMMIT" in codes and "BATCH_PUSHES" in codes, codes
        usage = again["advice"]["project_usage"][0]
        assert usage["used_today"] == 3 and usage["builds_last_30m"] == 3 and usage["last_build_seconds_ago"] == 600


def test_a_budget_refusal_says_who_used_the_scope():
    with env(limits={"hosted_build": {"per_provider_per_day": {"vercel": 1}}}):
        fresh()
        ledger = metering.MemoryLedger()
        decide(request(sha="1" * 40), ledger, provide=evidence(builds=[SITE]))
        over = decide(request(sha="2" * 40), ledger, provide=evidence(builds=[DOCS]))
        assert over["advice"]["usage_by_repository"] == [{"repository": "example-org/widget", "used": 1}], over
        assert over["resets_at"] == "2027-01-16T00:00:00Z"


def test_priority_is_validated():
    with env():
        fresh()
        for bad in ({"blocking": "whenever", "reason": "long enough reason"}, {"blocking": "fix", "reason": "x"},
                    "continue_work"):
            try:
                decide(request(priority=bad), metering.MemoryLedger(), caller=LANE)
            except (gateway.TargetError, metering.MeteringError) as exc:
                assert "priority" in str(exc) or "priority" in str(getattr(exc, "context", ""))
            else:
                raise AssertionError(f"accepted priority {bad!r}")


# ---- production ------------------------------------------------------------
def test_shared_or_lane_caller_cannot_merge_to_production_without_a_grant():
    with env():
        fresh()
        for caller in (None, LANE):
            result = decide(request("production_merge", ref="refs/heads/main"), metering.MemoryLedger(),
                            caller=caller)
            assert result["decision"] == "AUTH_REQUIRED" and result["reason"] == "OWNER_REQUIRED", result
            assert "coordinator" in result["remedy"] and "budget-grant" in result["remedy"]


def test_a_coordinators_authorization_does_not_transfer_to_a_lane():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        first = decide(request(ref="refs/heads/main"), ledger, caller=COORDINATOR)
        assert first["decision"] == "ALLOW", first
        for caller in (LANE, None):
            again = decide(request(ref="refs/heads/main"), ledger, caller=caller, now=NOW + 5)
            assert again["decision"] == "AUTH_REQUIRED" and again["reason"] == "OWNER_REQUIRED", again
            assert "not transferable" in again["detail"]
        replay = decide(request(ref="refs/heads/main"), ledger, caller=COORDINATOR, now=NOW + 10)
        assert replay["decision"] == "ALLOW" and replay.get("replayed") is True
        assert ledger.ledger_count(metering.budget_day(NOW), ["hosted_build"]) == 1


def test_push_to_production_branch_is_production_too():
    with env():
        fresh()
        result = decide(request(ref="refs/heads/main"), metering.MemoryLedger(), caller=LANE)
        assert result["reason"] == "OWNER_REQUIRED"


def test_coordinator_merges_past_five_a_day_are_counted_not_refused():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        for index in range(5):
            result = decide(request("production_merge", ref="refs/heads/main", sha=str(index) * 40), ledger,
                            caller=COORDINATOR)
            assert result["decision"] == "ALLOW", result
        sixth = decide(request("production_merge", ref="refs/heads/main", sha="9" * 40), ledger, caller=COORDINATOR)
        assert sixth["decision"] == "ALLOW" and sixth["reason"] == "OVER_BUDGET_NOTED", sixth
        assert sixth["budget"]["exceeded"]["limit"] == 5 and sixth["capability_token"]
        assert ledger.ledger_count(metering.budget_day(NOW), ["production_merge"]) == 6, "still counted"
        lane = decide(request("production_merge", ref="refs/heads/main", sha="8" * 40), ledger, caller=LANE)
        assert lane["decision"] == "AUTH_REQUIRED", "a lane still needs a grant for production"


def test_hosted_builds_past_budget_are_still_refused():
    with env(limits={"hosted_build": {"per_project_per_day": 1}}):
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(ref="refs/heads/main", sha="1" * 40), ledger, caller=COORDINATOR)["decision"] == "ALLOW"
        over = decide(request(ref="refs/heads/main", sha="2" * 40), ledger, caller=COORDINATOR)
        assert over["decision"] == "AUTH_REQUIRED" and over["reason"] == "BUDGET_EXCEEDED", over


def test_a_repeated_grant_request_returns_the_grant_it_made():
    ledger = metering.MemoryLedger()
    body = {"action": "production_merge", "owner": OWNER, "name": REPO, "uses": 1, "expires_minutes": 120,
            "reason": "merge the sites table wiring", "request_id": "req-0123456789"}
    with env(), patch.object(gateway, "store_ledger", return_value=ledger):
        fresh()
        first = gateway.issue_grant(dict(body), now=NOW)
        again = gateway.issue_grant(dict(body), now=NOW + 30)
        other = gateway.issue_grant({**body, "request_id": "req-9876543210"}, now=NOW + 60)
    assert first["existing"] is False and again["existing"] is True, (first, again)
    assert again["grant_id"] == first["grant_id"] and again["expires_at"] == first["expires_at"]
    assert other["grant_id"] != first["grant_id"] and len(ledger.grants) == 2


def test_a_grant_for_a_repository_acp_does_not_govern_is_refused():
    ledger = metering.MemoryLedger()
    body = {"action": "hosted_build", "owner": "OWNER", "name": "NAME", "uses": 1, "expires_minutes": 120,
            "reason": "<what and why>", "request_id": "req-0123456789"}
    with env(), patch.object(gateway, "store_ledger", return_value=ledger):
        fresh()
        try:
            gateway.issue_grant(dict(body), now=NOW)
            raise AssertionError("granted a repository nothing governs")
        except gateway.TargetError as exc:
            assert exc.status == 404 and exc.code == "REPOSITORY_NOT_GOVERNED", exc
        anywhere = gateway.issue_grant({k: v for k, v in body.items() if k not in ("owner", "name")}, now=NOW)
    assert anywhere["repository"] is None and len(ledger.grants) == 1


def test_manual_ci_is_coordinator_only_and_capped():
    with env(limits={"manual_ci": {"per_day_total": 1}}):
        fresh()
        ledger = metering.MemoryLedger()
        ci = lambda sha: request("manual_ci", ref="refs/heads/main", sha=sha, workflow=".github/workflows/ci.yml")
        builds = evidence(builds=[{"provider": "github_actions", "project": ".github/workflows/ci.yml",
                                   "would_build": True, "why": "manual runs are enabled"}],
                          workflows=[{"path": ".github/workflows/ci.yml", "would_run": True,
                                      "jobs_without_timeout": [], "has_concurrency": True}])
        assert decide(ci("1" * 40), ledger, caller=LANE, provide=builds)["reason"] == "OWNER_REQUIRED"
        assert decide(ci("1" * 40), ledger, caller=COORDINATOR, provide=builds)["decision"] == "ALLOW"
        assert decide(ci("2" * 40), ledger, caller=COORDINATOR, provide=builds)["reason"] == "BUDGET_EXCEEDED"


def test_the_caller_cannot_choose_which_builds_are_counted():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        named = decide(request(provider="railway"), ledger)            # vercel builds this push all the same
        assert named["decision"] == "ALLOW" and named["reason"] == "WITHIN_BUDGET", named
        assert ledger.ledger_count(metering.budget_day(NOW), ["hosted_build"]) == 1
        absent = decide(request(trigger="railway_up", sha="3" * 40), ledger, caller=COORDINATOR,
                        provide=evidence(builds=[]))
        assert absent["decision"] == "DENY" and absent["reason"] == "PROVIDER_NOT_METERED", absent
        try:
            gateway.parse_authorization_request(request(trigger="cli_deploy", provider="railway"))
            raise AssertionError("a CLI deploy named a provider it does not deploy to")
        except (gateway.TargetError, metering.MeteringError):
            pass


def test_a_cli_deploy_is_production_whatever_ref_it_claims():
    with env():
        fresh()
        out = decide(request(trigger="cli_deploy", ref="refs/heads/feature-x"), metering.MemoryLedger(),
                     caller=LANE)
        assert out["decision"] == "AUTH_REQUIRED" and out["reason"] == "OWNER_REQUIRED", out


def test_a_cli_deploy_from_a_detached_checkout_needs_no_branch():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        lane = decide(request(trigger="cli_deploy", ref=None), ledger, caller=LANE)
        assert lane["decision"] == "AUTH_REQUIRED" and lane["reason"] == "OWNER_REQUIRED", lane
        assert lane["grant_request"]["command"] in lane["remedy"]
        owner = decide(request(trigger="railway_up", ref=None), ledger, caller=COORDINATOR,
                       provide=evidence(builds=[{"provider": "railway", "project": "api", "would_build": True,
                                                 "why": "railway up deploys the linked service"}]))
        assert owner["decision"] == "ALLOW", owner
        try:
            gateway.parse_authorization_request(request(trigger="push", ref=""))
            raise AssertionError("a push without a branch was accepted")
        except (gateway.TargetError, metering.MeteringError):
            pass
        try:
            gateway.parse_authorization_request(request(trigger="cli_deploy", ref="refs/heads/../x"))
            raise AssertionError("a malformed ref was accepted because the trigger is a CLI deploy")
        except (gateway.TargetError, metering.MeteringError):
            pass


def test_each_cli_deploy_and_manual_dispatch_is_counted():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        day = metering.budget_day(NOW)
        for n in range(3):
            out = decide(request(trigger="cli_deploy", ref="refs/heads/main"), ledger, caller=COORDINATOR,
                         now=NOW + n * 600)
            assert out["decision"] == "ALLOW" and not out.get("replayed"), out
        assert ledger.ledger_count(day, ["hosted_build"]) == 3, "three deploys of one commit are three builds"
        retried = decide(request(trigger="cli_deploy", ref="refs/heads/main", tool_use_id="toolu_1"), ledger,
                         caller=COORDINATOR, now=NOW + 1800)
        again = decide(request(trigger="cli_deploy", ref="refs/heads/main", tool_use_id="toolu_1"), ledger,
                       caller=COORDINATOR, now=NOW + 1801)
        assert again.get("replayed") is True and retried["decision"] == "ALLOW", "one invocation counts once"
        assert ledger.ledger_count(day, ["hosted_build"]) == 4


# ---- fail closed, with remedies -------------------------------------------
def test_unbounded_workflow_is_refused_with_the_exact_change():
    with env():
        fresh()
        result = decide(request(), metering.MemoryLedger(), provide=evidence(
            builds=[{"provider": "github_actions", "project": ".github/workflows/ci.yml", "would_build": True,
                     "why": "runs on pushes"}],
            workflows=[{"path": ".github/workflows/ci.yml", "would_run": True,
                        "jobs_without_timeout": ["test"], "has_concurrency": False}]))
        assert result["decision"] == "DENY" and result["reason"] == "WORKFLOW_UNBOUNDED"
        assert "timeout-minutes: 15" in result["remedy"] and "concurrency" in result["remedy"]


def test_missing_provider_evidence_refuses_the_paid_build():
    with env():
        fresh()
        for kind, reason in (("UNAVAILABLE", "PROVIDER_EVIDENCE_UNAVAILABLE"), ("DIVERGED", "PROVIDER_RESPONSE_DIVERGED")):
            result = decide(request(), metering.MemoryLedger(), provide=evidence(available=False, kind=kind))
            assert result["decision"] == "REVERIFY_REQUIRED" and result["reason"] == reason
            assert result["remedy"]
        result = gateway.authorize(request(), verifier=verifier(), now=NOW, ledger=metering.MemoryLedger())
        assert result["reason"] == "PROVIDER_EVIDENCE_UNAVAILABLE"


def test_file_backend_has_no_ledger_and_says_where_to_go():
    with env():
        fresh()
        result = decide(request(), None)
        assert result["decision"] == "REVERIFY_REQUIRED" and result["reason"] == "BUDGET_LEDGER_UNAVAILABLE"
        assert "PostgreSQL" in result["remedy"]


def test_missing_or_unsigned_budget_policy_refuses():
    with env(budget_doc=False):
        fresh()
        assert decide(request(), metering.MemoryLedger())["reason"] == "BUDGET_POLICY_UNAVAILABLE"
    unsigned = json.dumps({"budget_policy_id": "acp-budgets", "version": 1, "limits": {}})
    with env(ACP_BUDGET_POLICY=unsigned):
        fresh()
        assert gateway.budget_policy()["error"] == "ACP_BUDGET_POLICY signature does not verify"
        assert decide(request(), metering.MemoryLedger())["reason"] == "BUDGET_POLICY_UNAVAILABLE"


def test_out_of_scope_repository_is_not_waved_through():
    with env():
        fresh()
        body = request()
        body["repository_claim"] = {"owner": "Elsewhere", "name": "x", "remote_url": "https://github.com/Elsewhere/x",
                                    "head_sha": SHA}
        result = decide(body, metering.MemoryLedger())
        assert result["decision"] == "DENY" and result["reason"] == "REPOSITORY_NOT_GOVERNED"
        assert result["remedy"]
        # ordinary protected work out of scope is still ACP's to decline, unchanged
        plain = gateway.authorize({**body, "action": "git.protected_ref.update",
                                   "context": {"ref": "refs/heads/main", "old_sha": SHA, "new_sha": SHA2}},
                                  verifier=verifier(), now=NOW)
        assert plain["reason"] == "OUT_OF_POLICY_SCOPE"


def test_policy_must_opt_in_and_unknown_repo_is_refused():
    with env(policy_body=policy(protected_actions=list(gateway.DEFAULT_PROTECTED_ACTIONS))):
        fresh()
        result = decide(request(), metering.MemoryLedger())
        assert result["reason"] == "METERED_ACTION_NOT_ENABLED" and result["remedy"]
    with env():
        fresh()
        body = request()
        body["repository_claim"]["name"] = "Unregistered"
        body["repository_claim"]["remote_url"] = f"https://github.com/{OWNER}/Unregistered.git"
        assert decide(body, metering.MemoryLedger())["reason"] == "POLICY_NOT_FOUND"


def test_caller_outside_its_repositories_is_refused():
    with env():
        fresh()
        other = {"kind": "lane", "id": "lane-b", "repos": [f"{OWNER}/Other"]}
        assert decide(request(), metering.MemoryLedger(), caller=other)["reason"] == "CALLER_NOT_PERMITTED"


def test_every_refusal_reason_has_a_remedy():
    for reason in ("POLICY_NOT_FOUND", "REMOTE_MISMATCH", "STALE_REF_STATE", "ACTION_NOT_RECOGNIZED",
                   "REPOSITORY_NOT_GOVERNED", "METERED_ACTION_NOT_ENABLED", "CALLER_NOT_PERMITTED"):
        assert gateway.REMEDIES.get(reason), reason
    with env():
        fresh()
        denied = gateway.authorize({**request(), "action": "made.up"}, verifier=verifier(), now=NOW)
        assert denied["reason"] == "ACTION_NOT_RECOGNIZED" and denied["remedy"]


# ---- local metered ---------------------------------------------------------
def local(action, **context):
    ctx = {"reason": "profile the renderer under load", "tool_use_id": "toolu_1"}
    if action == "local_heavy_build":
        ctx["machine_id"] = "mac-1"
    else:
        ctx["model"] = "claude-opus-5-5"
    ctx.update(context)
    return {"agent_id": "lane-a", "session_id": "session-1", "action": action, "context": ctx}


def test_heavy_subagent_leases_up_to_six_then_points_at_light_models():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        leases = []
        for index in range(6):
            result = decide(local("heavy_subagent", tool_use_id=f"toolu_{index}"), ledger)
            assert result["decision"] == "ALLOW", result
            leases.append(result["lease_id"])
        seventh = decide(local("heavy_subagent", tool_use_id="toolu_9"), ledger)
        assert seventh["decision"] == "DENY" and seventh["reason"] == "SUBAGENT_LIMIT_REACHED"
        assert "sonnet or haiku" in seventh["remedy"]
        assert ledger.lease_release(leases[0], NOW + 60)
        assert decide(local("heavy_subagent", tool_use_id="toolu_9"), ledger, now=NOW + 61)["decision"] == "ALLOW"


def test_light_model_is_not_a_heavy_subagent():
    with env():
        fresh()
        try:
            decide(local("heavy_subagent", model="claude-sonnet-5-5"), metering.MemoryLedger())
        except gateway.TargetError as exc:
            assert "start it directly" in exc.remedy
        else:
            raise AssertionError("expected INVALID_REQUEST")


def test_local_heavy_build_is_recorded_and_never_blocked_without_a_way_forward():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(local("local_heavy_build"), ledger)["decision"] == "ALLOW"
        assert decide(local("local_heavy_build"), ledger).get("replayed") is True
        refused = decide(local("local_heavy_build", tool_use_id="toolu_2"), None)
        assert refused["decision"] == "REVERIFY_REQUIRED" and "reg build" in refused["remedy"]


# ---- build admission (the machine register asks before a build takes a slot) -------------
def admission(command="./scripts/conformance.sh", project="peel", running=(), queued=(), session="sess-a",
              interactive=False, cache="shared", ticket="t-1"):
    facts = {"contract": "reg-admission/1", "project": project, "repo": f"/r/{project}", "label": "unit",
             "command": command, "cache": cache,
             "attribution": {"session_id": session, "message_address": "uds:/tmp/cc-socks/1.sock",
                             "subagent": False, "interactive": interactive},
             "running": list(running), "queued_projects": list(queued)}
    if session is None:
        facts["attribution"].pop("session_id")
    return {"agent_id": "reg", "session_id": session, "action": "build_admission",
            "context": {"reason": f"reg build unit: {command}", "tool_use_id": ticket, "machine_id": "mac-1",
                        "admission": facts}}


def test_build_admission_decides_on_the_registers_facts():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        out = decide(admission(), ledger)
        assert out["decision"] == "ALLOW" and out["reason"] == "BUILD_ADMITTED", out
        assert out["admission_state"] == {"attributable": "SATISFIED", "not_duplicate": "SATISFIED",
                                          "within_project_share": "SATISFIED", "shared_cache": "SATISFIED"}
        running = [{"project": "peel", "command": "./scripts/conformance.sh", "receipt_id": "rcpt-1"}]
        dup = decide(admission(running=running, ticket="t-2"), ledger)
        assert dup["decision"] == "DENY" and dup["reason"] == "BUILD_DUPLICATE", dup
        assert "rcpt-1" in dup["detail"] and "sh -c" in dup["remedy"]
        share = decide(admission(command="cargo clippy", running=running, queued=["latchkey"], ticket="t-3"), ledger)
        assert share["decision"] == "REVERIFY_REQUIRED" and share["reason"] == "PROJECT_SHARE_EXCEEDED", share
        alone = decide(admission(command="cargo clippy", running=running, queued=["peel"], ticket="t-4"), ledger)
        assert alone["decision"] == "ALLOW", "a second slot is fine when no other project waits"
        nobody = decide(admission(session=None, ticket="t-5"), ledger)
        assert nobody["decision"] == "DENY" and nobody["reason"] == "BUILD_UNATTRIBUTED", nobody
        owner = decide(admission(session=None, interactive=True, ticket="t-6"), ledger)
        assert owner["decision"] == "ALLOW", "the owner at a terminal is attributed by being there"
        private = decide(admission(cache="private", ticket="t-7"), ledger)
        assert private["decision"] == "ALLOW" and private["admission_state"]["shared_cache"] == "VIOLATED"
        assert ledger.ledger_count(metering.budget_day(NOW), ["build_admission"]) == 4


def test_the_signed_budget_policy_sets_the_admission_contract():
    strict = {"version": 2, "private_cache": "refuse", "project_slots_while_others_wait": 2}
    with env(budget_doc=False, ACP_BUDGET_POLICY=json.dumps(signed(
            {"budget_policy_id": "acp-budgets", "version": 1, "limits": {}, "build_admission": strict}))):
        fresh()
        ledger = metering.MemoryLedger()
        private = decide(admission(cache="private"), ledger)
        assert private["decision"] == "DENY" and private["reason"] == "BUILD_PRIVATE_CACHE", private
        assert private["admission_contract"] == 2
        running = [{"project": "peel", "command": "a"}]
        assert decide(admission(command="b", running=running, queued=["x"], ticket="t-2"), ledger)["decision"] == "ALLOW"
    for bad in ({"duplicates": "maybe"}, {"project_slots_while_others_wait": 0}, {"extra": 1}):
        try:
            metering.validated_admission_contract(bad)
            raise AssertionError(f"accepted {bad}")
        except ValueError:
            pass


def test_build_admission_facts_are_validated():
    with env():
        fresh()
        for broken in ({"project": "p"}, {"project": "p", "command": "x", "running": "many"},
                       {"project": "p", "command": "x", "attribution": {"session_id": "s", "token": "t"}},
                       {"project": "p", "command": "x", "cache": "elsewhere"}):
            body = admission()
            body["context"]["admission"] = broken
            try:
                decide(body, metering.MemoryLedger())
                raise AssertionError(f"accepted {broken}")
            except gateway.TargetError as exc:
                assert exc.status == 400, exc


# ---- caller identity over HTTP --------------------------------------------
def callers_doc(token, kind="coordinator", repos=None):
    return json.dumps(signed({"callers_id": "acp-callers", "version": 1, "callers": [
        {"caller_id": "coord-acp", "kind": kind, "repos": repos or [f"{OWNER}/*"],
         "token_sha256": hashlib.sha256(token.encode()).hexdigest()}]}))


class Served:
    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_):
        self.server.shutdown(); self.server.server_close()

    def call(self, path, token, body=None, admin=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        headers = {"Authorization": "Bearer " + token}
        raw = None
        if body is not None:
            raw = json.dumps(body).encode()
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(raw))})
        if admin:
            headers["X-ACP-Admin-Authorization"] = "Bearer " + admin
        connection.request("POST" if body is not None else "GET", path, body=raw, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())


def test_registered_caller_token_authenticates_and_is_identified():
    coordinator_token = "coordinator-token-0123456789abcdef"
    with env(ACP_CALLERS=callers_doc(coordinator_token)):
        fresh()
        registry = gateway.callers_registry()
        assert registry["error"] is None and registry["callers"][0]["kind"] == "coordinator"
        with Served() as served:
            status, body = served.call("/internal/budget", coordinator_token)
            assert status == 200 and body["day"]
            status, _ = served.call("/internal/budget", "wrong-token-0123456789")
            assert status == 401
            status, body = served.call("/internal/posture/refresh", TOKEN, body={})
            assert status == 403 and body["error"] == "COORDINATOR_REQUIRED" and body["remedy"]


def test_tampered_callers_document_registers_nobody():
    doc = json.loads(callers_doc("coordinator-token-0123456789abcdef"))
    doc["callers"][0]["kind"] = "lane"
    with env(ACP_CALLERS=json.dumps(doc)):
        fresh()
        registry = gateway.callers_registry()
        assert registry["callers"] == [] and "signature" in registry["error"]


def test_owner_cannot_be_registered_as_a_caller():
    raw = json.loads(callers_doc("t" * 32))
    raw["callers"][0]["kind"] = "owner"
    body = {k: v for k, v in raw.items() if k != "signature"}
    with env(ACP_CALLERS=json.dumps(signed(body))):
        fresh()
        assert "owner uses the admin credential" in gateway.callers_registry()["error"]


def test_grant_route_needs_the_admin_credential():
    with env(ACP_POLICY_ADMIN_TOKEN="admin-token-0123456789abcdef"):
        fresh()
        with Served() as served:
            status, body = served.call("/internal/budget/grant", TOKEN, body={"action": "hosted_build"})
            assert status == 403 and body["error"] == "ADMIN_REQUIRED"


def _coverage_env():
    widget = policy(metered={"production_branches": ["main"],
                             "providers": {"vercel": {"project_ids": ["prj_widget", "prj_moved", "prj_gone"]}}})
    gadget = policy(policy_id="gadget", repository={"owner": OWNER, "name": "Gadget",
                                                    "canonical_remote": f"https://github.com/{OWNER}/Gadget.git"},
                    metered=None)
    gadget.pop("metered")
    return env(ACP_POLICY=json.dumps([signed(widget), signed(gadget)]), ACP_VERCEL_TEAM_ID="team_abc",
               ACP_VERCEL_TOKEN="v-token", ACP_POLICY_ADMIN_TOKEN="admin-token-0123456789abcdef")


def _team_projects(provider, url, token, body=None):
    assert "/v9/projects?" in url and "teamId=team_abc" in url
    link = lambda repo: {"type": "github", "org": repo.split("/")[0], "repo": repo.split("/")[1]}
    return {"projects": [
        {"id": "prj_widget", "name": "widget", "link": link(f"{OWNER}/{REPO}")},
        {"id": "prj_moved", "name": "moved", "link": link(f"{OWNER}/Elsewhere")},
        {"id": "prj_gadget", "name": "gadget", "link": link(f"{OWNER}/Gadget")},
        {"id": "prj_stray", "name": "stray", "link": link("Someone/Else")},
        {"id": "prj_cli", "name": "cli-only"}], "pagination": {"next": None}}


def test_coverage_flags_every_project_that_is_not_metered_where_it_builds():
    with _coverage_env():
        fresh()
        gateway.providers._CACHE.clear()
        view = gateway.coverage_view(now=NOW, fetch=_team_projects)
    status = {row["project_id"]: row["status"] for row in view["projects"]}
    assert status == {"prj_widget": "METERED", "prj_moved": "MISLINKED", "prj_gadget": "UNMETERED_GOVERNED",
                      "prj_stray": "UNGOVERNED", "prj_cli": "UNLINKED", "prj_gone": "MISSING"}, status
    rows = {row["project_id"]: row for row in view["projects"]}
    assert rows["prj_gadget"]["command"].endswith(
        f"enroll {OWNER.lower()}/gadget --vercel prj_gadget --vercel-team team_abc --apply")
    assert rows["prj_gone"]["command"].endswith(
        f"enroll {OWNER.lower()}/widget --vercel prj_moved --vercel prj_widget --vercel-team team_abc --apply"), \
        "re-enrolling drops the id that no longer exists and keeps the rest"
    assert "Elsewhere" in rows["prj_moved"]["remedy"] or "elsewhere" in rows["prj_moved"]["remedy"]
    assert view["summary"]["METERED"] == 1 and view["errors"] == []


def test_coverage_for_one_repository_and_who_may_ask():
    with _coverage_env():
        fresh()
        gateway.providers._CACHE.clear()
        one = gateway.coverage_view(OWNER, "Gadget", now=NOW, fetch=_team_projects)
        assert one["governed"] is True and [r["project_id"] for r in one["projects"]] == ["prj_gadget"]
        assert one["enroll_command"] and "--vercel prj_gadget" in one["enroll_command"]
        lane_token = "lane-token-0123456789abcdef"
        with env(ACP_CALLERS=callers_doc(lane_token, kind="lane", repos=[f"{OWNER}/{REPO}"])), Served() as served, \
                patch.object(gateway, "coverage_view", lambda owner=None, name=None: {"repository": owner}):
            status, body = served.call("/internal/coverage", lane_token)
            assert status == 403 and body["error"] == "CALLER_NOT_PERMITTED", body
            status, body = served.call(f"/internal/coverage?owner={OWNER}&name=Gadget", lane_token)
            assert status == 403, "a lane sees only its own repositories"
            status, body = served.call(f"/internal/coverage?owner={OWNER}&name={REPO}", lane_token)
            assert status == 200, body
            status, body = served.call("/internal/coverage", TOKEN, admin="admin-token-0123456789abcdef")
            assert status == 200, body


def test_posture_refresh_works_in_short_stalest_first_batches():
    policies = [policy(policy_id=f"repo{i}", repository={"owner": OWNER, "name": f"Repo{i}",
                                                          "canonical_remote": f"https://github.com/{OWNER}/Repo{i}.git"})
                for i in range(5)]
    with env(ACP_POLICY=json.dumps([signed(p) for p in policies])):
        fresh()
        gateway._POSTURE.clear()
        seen = []
        fake = lambda pol, token_for, now: (seen.append(pol["repository"]["name"]) or
                                            {"schema_version": 1, "repository": pol["repository"]["name"],
                                             "fetched_at": "x", "vercel": [], "railway": None,
                                             "github_actions": {}, "errors": []})
        with patch.object(gateway.providers, "posture_snapshot", fake), \
                patch.object(gateway, "store_ledger", lambda: None):
            first = gateway.refresh_posture(now=NOW)
            assert len(first["refreshed"]) == gateway.POSTURE_REFRESH_BATCH and len(first["remaining"]) == 2
            second = gateway.refresh_posture(now=NOW + 1)
            assert len(second["refreshed"]) == 2 and second["remaining"] == []
            third = gateway.refresh_posture(now=NOW + 2)
            assert third["refreshed"] == [] and len(third["skipped_recent"]) == 5
        assert sorted(seen) == [f"Repo{i}" for i in range(5)]


def test_limits_validation_is_exact():
    assert metering.validated_limits({})["hosted_build"]["per_day_total"] == 60
    assert metering.validated_limits({"manual_ci": {"per_day_total": None}})["manual_ci"] == {}
    for bad in ({"hosted_build": {"per_week": 3}}, {"unknown": {}}, {"manual_ci": {"per_day_total": -1}}):
        try:
            metering.validated_limits(bad)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_record_key_is_deterministic_and_field_ordered():
    a = metering.record_key("hosted_build", "vercel", "o", "n", "refs/heads/x", SHA, None, None)
    assert a == metering.record_key("hosted_build", "vercel", "o", "n", "refs/heads/x", SHA, None, None)
    assert a != metering.record_key("hosted_build", "railway", "o", "n", "refs/heads/x", SHA, None, None)


def test_policy_metered_block_is_validated():
    assert metering.validated_metered({"providers": {"vercel": {"project_ids": ["prj_a"], "team_id": "team_x1"}}},
                                      "p")["providers"]["vercel"]["team_id"] == "team_x1"
    for bad in ({"providers": {"netlify": {}}}, {"hosted_build": {"per_day": "many"}}, {"extra": 1},
                {"providers": {"vercel": {"project_ids": ["prj_a"], "team_id": "not a team"}}},
                {"providers": {"railway": {"project_id": "not-a-uuid"}}}):
        try:
            metering.validated_metered(bad, "p")
        except ValueError:
            continue
        raise AssertionError(bad)



# ---- review fixes ------------------------------------------------------------
def _grant(ledger, action="hosted_build", grant_id="g-0000000000000009", uses=1):
    ledger.grant_issue({"grant_id": grant_id, "action": action, "resource_owner": OWNER.lower(),
                        "resource_name": REPO.lower(), "uses_total": uses, "uses_left": uses, "issued_at": NOW,
                        "expires_at": NOW + 86400, "issued_by": "owner", "reason": "review fix test"})


def test_a_reused_tool_use_id_is_refused_not_replayed():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        day = metering.budget_day(NOW)
        first = decide(request(trigger="cli_deploy", ref="refs/heads/main", tool_use_id="toolu_9"), ledger,
                       caller=COORDINATOR, now=NOW)
        assert first["decision"] == "ALLOW" and not first.get("replayed"), first
        late = decide(request(trigger="cli_deploy", ref="refs/heads/main", tool_use_id="toolu_9"), ledger,
                      caller=COORDINATOR, now=NOW + metering.INVOCATION_REPLAY_SECONDS + 1)
        assert late["decision"] == "DENY" and late["reason"] == "INVOCATION_REUSED", late
        other = {"kind": "coordinator", "id": "coord-2", "repos": [f"{OWNER}/*"]}
        borrowed = decide(request(trigger="cli_deploy", ref="refs/heads/main", tool_use_id="toolu_9"), ledger,
                          caller=other, now=NOW + 5)
        assert borrowed["reason"] == "INVOCATION_REUSED", "another caller cannot ride on this record"
        assert ledger.ledger_count(day, ["hosted_build"]) == 1


def test_each_rerun_is_counted():
    with env(policy_body=policy(metered={"production_branches": ["main"], "providers": {}})):
        fresh()
        ledger = metering.MemoryLedger()
        ci = [{"provider": "github_actions", "project": ".github/workflows/ci.yml", "would_build": True, "why": "x"}]
        bounded = [{"path": ".github/workflows/ci.yml", "would_run": True, "jobs_without_timeout": [],
                    "has_concurrency": True}]
        for n in range(2):
            out = decide(request("manual_ci", ref="refs/heads/main", trigger="rerun", run_id="123",
                                 workflow=".github/workflows/ci.yml"), ledger, caller=COORDINATOR,
                         provide=evidence(builds=ci, workflows=bounded), now=NOW + n * 600)
            assert out["decision"] == "ALLOW" and not out.get("replayed"), out
        assert ledger.ledger_count(metering.budget_day(NOW), ["manual_ci"]) == 2


def test_priority_never_waives_a_service_ceiling_even_when_the_project_is_also_over():
    ask = {"blocking": "continue_work", "reason": "the lane needs this branch built to continue"}
    full = [{"provider": "vercel", "source": "live", "deployments_today": 150, "in_flight": 0, "projects_in_flight": {}}]
    with env(limits={"hosted_build": {"per_project_per_day": 1, "min_spacing_seconds": 0}}):
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40), ledger, caller=LANE, now=NOW)["decision"] == "ALLOW"
        out = decide(request(sha="2" * 40, priority=ask), ledger, caller=LANE, now=NOW + 600,
                     provide=evidence(capacity=full))
        assert out["decision"] == "AUTH_REQUIRED" and out["reason"] == "SERVICE_LIMIT_REACHED", out
        assert out["budget"]["exceeded"]["kind"] == "service"


def test_a_merge_and_the_push_of_one_commit_count_its_builds_once():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        day = metering.budget_day(NOW)
        merged = decide(request("production_merge", ref="refs/heads/main"), ledger, caller=COORDINATOR, now=NOW)
        assert merged["decision"] == "ALLOW", merged
        pushed = decide(request(ref="refs/heads/main"), ledger, caller=COORDINATOR, now=NOW + 30)
        assert pushed["decision"] == "ALLOW" and pushed.get("replayed") is True, pushed
        assert ledger.ledger_count(day, list(metering.HOSTED)) == 1


def test_a_lane_retrying_its_own_granted_production_push_is_answered_from_the_record():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        _grant(ledger)
        first = decide(request(ref="refs/heads/main"), ledger, caller=LANE, now=NOW)
        assert first["reason"] == "GRANT_APPLIED", first
        again = decide(request(ref="refs/heads/main"), ledger, caller=LANE, now=NOW + 20)
        assert again["decision"] == "ALLOW" and again.get("replayed") is True, again
        other = {"kind": "lane", "id": "lane-b", "repos": [f"{OWNER}/{REPO}"]}
        assert decide(request(ref="refs/heads/main"), ledger, caller=other, now=NOW + 40)["reason"] == "OWNER_REQUIRED"


def test_a_grant_is_not_spent_on_a_push_pacing_defers():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40, ref="refs/heads/main"), ledger, caller=COORDINATOR,
                      now=NOW)["decision"] == "ALLOW"
        _grant(ledger)
        paced = decide(request(sha="2" * 40, ref="refs/heads/main"), ledger, caller=LANE, now=NOW + 10)
        assert paced["reason"] == "BUILD_PACED", "a grant does not excuse pacing"
        assert ledger.grants["g-0000000000000009"]["uses_left"] == 1, "nothing was spent on a deferral"
        later = decide(request(sha="2" * 40, ref="refs/heads/main"), ledger, caller=LANE, now=NOW + 600)
        assert later["reason"] == "GRANT_APPLIED", later


def test_per_provider_limits_merge_over_the_defaults():
    merged = metering.validated_limits({"hosted_build": {"per_provider_per_day": {"vercel": 100}}})
    defaults = metering.DEFAULT_LIMITS["hosted_build"]["per_provider_per_day"]
    assert merged["hosted_build"]["per_provider_per_day"] == {**defaults, "vercel": 100}


def test_a_burst_retry_after_waits_for_the_window_to_drop_below_the_burst():
    with env(limits={"hosted_build": {"min_spacing_seconds": 0}}):
        fresh()
        ledger = metering.MemoryLedger()
        for n in range(7):
            ledger.ledger_insert({"record_key": f"k{n}", "request_id": f"r{n}", "action": "hosted_build",
                                  "provider": "vercel", "project": "widget", "resource_owner": OWNER.lower(),
                                  "resource_name": REPO.lower(), "ref": "refs/heads/feature", "sha": str(n) * 40,
                                  "caller_kind": "lane", "caller_id": "lane-a", "reason": "x" * 8, "counted": True,
                                  "reason_code": "WITHIN_BUDGET", "budget_day": metering.budget_day(NOW),
                                  "grant_id": None, "evidence_digest": None, "created_at": NOW + n * 60})
        burst = decide(request(sha="9" * 40), ledger, caller=LANE, now=NOW + 420)
        assert burst["reason"] == "BUILD_BURST", burst
        # Builds at +0..+360: the window holds at most 4 once the build at +120 (7th from last is +0;
        # the 5th newest is +120) leaves it, 30 minutes after +120.
        assert burst["retry_after"] == int(NOW + 120 + 1800 - (NOW + 420)) + 1, burst


def test_an_unreadable_service_is_advised_not_silently_ignored():
    down = [{"provider": "vercel", "source": "unavailable", "kind": "UNAVAILABLE", "detail": "HTTP 503"}]
    with env():
        fresh()
        out = decide(request(), metering.MemoryLedger(), caller=COORDINATOR, provide=evidence(capacity=down))
        assert out["decision"] == "ALLOW"
        assert "CAPACITY_UNREAD" in [r["code"] for r in out["advice"]["recommendations"]], out["advice"]


def test_a_reused_subagent_tool_use_id_after_release_is_refused():
    ledger = metering.MemoryLedger()
    ledger.lease_open({"lease_key": "k", "session_id": "s", "model": "opus", "reason": "x" * 8,
                       "opened_at": NOW, "expires_at": NOW + 60})
    try:
        ledger.lease_open({"lease_key": "k", "session_id": "s", "model": "opus", "reason": "x" * 8,
                           "opened_at": NOW, "expires_at": NOW + 60})
    except ValueError:
        pass
    else:
        raise AssertionError("the memory ledger must refuse a duplicate lease as the database does")


def test_a_posture_refresh_holds_no_transaction_while_it_reads_providers():
    from contextlib import contextmanager
    state = {"open": False, "opened": 0}

    @contextmanager
    def transaction():
        state["open"], state["opened"] = True, state["opened"] + 1
        try:
            yield None
        finally:
            state["open"] = False

    def snapshot(policy, token_for, now):
        assert not state["open"], "a provider read ran inside a database transaction"
        return {"schema_version": 1, "repository": "example-org/widget", "fetched_at": "x",
                "vercel": {}, "railway": {}, "github_actions": {}, "errors": []}

    ledger = type("L", (), {"snapshot_times": lambda self, p: {},
                            "snapshot_put": lambda self, *a: None})()
    with env(), patch.object(gateway.postgres_store, "enabled", return_value=True), \
            patch.object(gateway.postgres_store, "active", side_effect=lambda: state["open"]), \
            patch.object(gateway.postgres_store, "transaction", transaction), \
            patch.object(gateway, "store_ledger", return_value=ledger), \
            patch.object(gateway, "_governed_policies", return_value=[policy()]), \
            patch.object(gateway.providers, "posture_snapshot", side_effect=snapshot):
        fresh()
        out = gateway.refresh_posture(now=NOW)
    assert out["refreshed"] == ["example-org/widget"] and state["opened"] == 2, (out, state)


def test_authorization_evidence_is_read_before_the_transaction_and_reused_inside_it():
    from contextlib import contextmanager
    state = {"open": False, "network": []}

    @contextmanager
    def transaction():
        state["open"] = True
        try:
            yield None
        finally:
            state["open"] = False

    def github(claim, context, policy_body, known=None):
        assert not state["open"], "GitHub was read inside a database transaction"
        state["network"].append("github")
        return {"available": True, "installed": True,
                "repository": {"owner": OWNER, "name": REPO, "default_branch": "main"}}

    def provide(action, policy_body, claim, context):
        assert not state["open"], "a provider was read inside a database transaction"
        state["network"].append("provider")
        return evidence()(action, policy_body, claim, context)

    with env():
        fresh()
        registry = gateway.policy_registry()
        with patch.object(gateway.postgres_store, "transaction", transaction), \
                patch.object(gateway, "policy_registry", return_value=registry), \
                patch.object(gateway, "trust_state", return_value={}), \
                patch.object(gateway, "github_evidence", side_effect=github), \
                patch.object(gateway, "provider_evidence", side_effect=provide):
            memo = gateway.prefetch_authorize_evidence(json.dumps(request()).encode())
        assert state["network"] == ["github", "provider"], state
        replayed = []
        out = gateway.authorize(request(), verifier=gateway._from_memo(memo, "verify", lambda *a: replayed.append(a)),
                                now=NOW, caller=COORDINATOR, ledger=metering.MemoryLedger(),
                                provider_evidence=gateway._from_memo(memo, "provider", lambda *a: replayed.append(a)))
        assert out["decision"] == "ALLOW" and replayed == [], (out, replayed)
        assert gateway.prefetch_authorize_evidence(b"not json") == {"verify": [], "provider": []}


def test_unbounded_workflows_read_at_the_branch_advise_but_never_refuse_the_push_that_fixes_them():
    ci = [{"provider": "github_actions", "project": ".github/workflows/ci.yml", "would_build": True, "why": "x"}]
    branch_copy = [{"path": ".github/workflows/ci.yml", "would_run": True, "jobs_without_timeout": ["test"],
                    "has_concurrency": False, "read_at": "feature"}]
    with env(policy_body=policy(metered={"production_branches": ["main"], "providers": {}})):
        fresh()
        out = decide(request(), metering.MemoryLedger(), caller=COORDINATOR,
                     provide=evidence(builds=ci, workflows=branch_copy))
        assert out["decision"] == "ALLOW", out
        assert "WORKFLOW_UNBOUNDED_ON_BRANCH" in [r["code"] for r in out["advice"]["recommendations"]]
        exact = [dict(branch_copy[0], read_at=None)]
        refused = decide(request(sha=SHA2), metering.MemoryLedger(), caller=COORDINATOR,
                         provide=evidence(builds=ci, workflows=exact))
        assert refused["reason"] == "WORKFLOW_UNBOUNDED", "the commit's own workflows are still checked exactly"

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} metering tests passed")
