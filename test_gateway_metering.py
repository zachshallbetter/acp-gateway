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


def fresh():
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


def evidence(builds=None, workflows=None, available=True, kind=None):
    def provide(action, policy_body, claim, context):
        if not available:
            return {"available": False, "kind": kind or "UNAVAILABLE", "provider": "vercel", "detail": "HTTP 503"}
        rows = builds if builds is not None else [
            {"provider": "vercel", "project": "widget", "would_build": True, "why": "builds every push"}]
        return {"available": True, "builds": rows, "workflows": workflows or [], "digest": "d" * 64}
    return provide


def request(action="hosted_build", ref="refs/heads/feature", sha=SHA, **context):
    ctx = {"trigger": {"hosted_build": "push", "production_merge": "merge", "manual_ci": "workflow_dispatch"}
           .get(action), "ref": ref, "new_sha": sha, "reason": "ship the feature branch preview"}
    ctx.update(context)
    return {"agent_id": "lane-a", "actor_id": "github-user:1", "session_id": "session-1", "action": action,
            "repository_claim": {"owner": OWNER, "name": REPO, "remote_url": REMOTE, "head_sha": sha},
            "context": {k: v for k, v in ctx.items() if v is not None}}


def decide(body, ledger, caller=None, provide=None, now=NOW):
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


def test_deployment_wide_and_provider_limits_count_across_repositories():
    with env(limits={"hosted_build": {"per_provider_per_day": {"vercel": 1}}}):
        fresh()
        ledger = metering.MemoryLedger()
        assert decide(request(sha="1" * 40), ledger)["decision"] == "ALLOW"
        over = decide(request(sha="2" * 40), ledger)
        assert over["decision"] == "AUTH_REQUIRED" and over["budget"]["exceeded"]["scope"] == "vercel"


# ---- production ------------------------------------------------------------
def test_shared_or_lane_caller_cannot_merge_to_production_without_a_grant():
    with env():
        fresh()
        for caller in (None, LANE):
            result = decide(request("production_merge", ref="refs/heads/main"), metering.MemoryLedger(),
                            caller=caller)
            assert result["decision"] == "AUTH_REQUIRED" and result["reason"] == "OWNER_REQUIRED", result
            assert "coordinator" in result["remedy"] and "budget-grant" in result["remedy"]


def test_push_to_production_branch_is_production_too():
    with env():
        fresh()
        result = decide(request(ref="refs/heads/main"), metering.MemoryLedger(), caller=LANE)
        assert result["reason"] == "OWNER_REQUIRED"


def test_coordinator_merges_within_five_a_day():
    with env():
        fresh()
        ledger = metering.MemoryLedger()
        for index in range(5):
            result = decide(request("production_merge", ref="refs/heads/main", sha=str(index) * 40), ledger,
                            caller=COORDINATOR)
            assert result["decision"] == "ALLOW", result
        sixth = decide(request("production_merge", ref="refs/heads/main", sha="9" * 40), ledger, caller=COORDINATOR)
        assert sixth["decision"] == "AUTH_REQUIRED" and sixth["reason"] == "BUDGET_EXCEEDED"


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
    for bad in ({"providers": {"netlify": {}}}, {"hosted_build": {"per_day": "many"}}, {"extra": 1},
                {"providers": {"railway": {"project_id": "not-a-uuid"}}}):
        try:
            metering.validated_metered(bad, "p")
        except ValueError:
            continue
        raise AssertionError(bad)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} metering tests passed")
