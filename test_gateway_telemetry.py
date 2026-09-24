"""Tests for the telemetry layer: events, incidents, redaction, reporting, alerts.

The invariant under test is the one that makes telemetry safe to collect: it
records, correlates and reports, and it cannot turn a refusal into a permission.
The only state it may move is downward, and only for control-plane tampering on
a resource that is already contained.
"""
import hashlib, json, os, sys, tempfile
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402
from test_gateway_policy import (OWNER, REPO, REMOTE, NOTICE, SIGNING_KEY, claim, env,  # noqa: E402
                                 request, verifier, Served)
from test_gateway_lockout import ADMIN, GOOD, BAD, MAIN, contained_env, fresh, lock, quarantine, restart

PAT = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0123456789\n-----END RSA PRIVATE KEY-----"
RESOURCE = f"{OWNER}/{REPO}".lower()


def envelope(action="git.protected_ref.update", **overrides):
    """The §3 telemetry envelope, rather than the flat request shape."""
    body = {
        "principal": {"actor_id": "github-user:12345", "reported_github_login": "alice",
                      "reported_github_user_id": "12345", "agent_id": "claude",
                      "agent_session_id": "sess_456", "client_type": "interactive_agent",
                      "client_version": "1.2.3"},
        "request_provenance": {"source": "interactive_user",
                               "request_summary": "Force push main to the specified revision.",
                               "request_sha256": "sha256:" + hashlib.sha256(b"x").hexdigest(),
                               "request_id": "req_local_1"},
        "workspace": {"resource_id": RESOURCE,
                      "repository_claim": {"owner": OWNER, "name": REPO, "remote_url": REMOTE,
                                           "notice_sha256": NOTICE, "head_sha": "abc123"}},
        "git_state": {"detached_head": False, "dirty": True, "ahead": 2, "behind": 0,
                      "remotes": [{"name": "origin", "url": REMOTE}]},
        "operation": {"normalized_operation": action,
                      "command_redacted": "git push --force-with-lease origin <sha>:main",
                      "ref": MAIN, "old_sha": "abc123", "new_sha": "def456", "force": True},
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(body.get(key), dict):
            body[key].update(value)
        else:
            body[key] = value
    return body


def last(event_type=None):
    for record in reversed(gateway.AUDIT):
        if event_type is None or record.get("event") == event_type:
            return record
    return None


def types():
    return [record.get("event") for record in gateway.AUDIT]


# ---- 1-3. every decision and transition emits its event --------------------
def test_decisions_emit_their_own_events():
    fresh()
    with contained_env():
        # denied first: once ACP has verified a repository, losing sight of it is
        # REVERIFY_REQUIRED rather than a plain denial
        gateway.authorize(request("production.deploy"), verifier=None)
        assert last()["event"] == "AUTHORIZATION_DENIED" and last()["severity"] == "NOTICE"
        gateway.authorize(request("git.remote.update"), verifier=verifier())
        assert last()["event"] == "AUTHORIZATION_ALLOWED" and last()["severity"] == "INFO"
        gateway.authorize(request("git.remote.update"),
                          verifier=verifier(available=False, installed=False,
                                            reason="GITHUB_INSTALLATION_REMOVED"))
        assert last()["event"] == "REVERIFY_REQUIRED" and last()["severity"] == "WARNING"
        gateway.authorize(request("git.remote.update"), verifier=verifier(reason="GITHUB_AUTH_REQUIRED",
                                                                          available=False, installed=False))
        assert last()["event"] == "AUTH_REQUIRED"


def test_state_transitions_emit_their_own_events():
    fresh()
    with contained_env():
        quarantine()
        assert "QUARANTINE_ENTERED" in types()
        assert last("QUARANTINE_ENTERED")["severity"] == "HIGH"
        lock(now=2000.0)
        assert last("LOCKED_ENTERED")["severity"] == "CRITICAL"
        assert last("LOCKED_ENTERED")["incident_id"]


def test_provider_loss_and_recovery_are_events():
    fresh()
    with contained_env():
        gateway.authorize(request("git.remote.update"), verifier=verifier())
        gateway.authorize(request("git.remote.update"), verifier=verifier(available=False, installed=False))
        assert "PROVIDER_ACCESS_LOST" in types()
        gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert "PROVIDER_ACCESS_RESTORED" in types()


# ---- 4-9. the report endpoint ---------------------------------------------
def report(**overrides):
    body = {"event_type": "LOCAL_POLICY_MODIFIED", "event_id": "evt_client_1",
            "observed_at": "2026-09-06T12:00:00Z",
            "principal": {"actor_id": "github-user:12345", "agent_id": "claude", "session_id": "s1"},
            "resource": {"resource_id": RESOURCE, "owner": OWNER, "name": REPO},
            "evidence": {"path": ".claude/settings.local.json", "previous_sha256": "a" * 64,
                         "current_sha256": "b" * 64}}
    body.update(overrides)
    return body


def test_the_report_endpoint_is_behind_the_same_bearer():
    fresh()
    with contained_env(), Served() as served:
        status, body = served.post(report(), path="/internal/report", token=None)
        assert status == 401 and body["error"] == "UNAUTHORIZED", body
        status, body = served.post(report(), path="/internal/report")
        assert status == 200 and body["accepted"] is True, body
        assert body["authorizes"] is False and body["event_id"].startswith("evt_")


def test_malformed_and_oversized_reports_are_rejected():
    fresh()
    with contained_env(), Served() as served:
        status, body = served.post(b'{"event_type":', path="/internal/report")
        assert status == 400 and body["error"] == "INVALID_JSON", body
        status, body = served.post(report(nonsense=1), path="/internal/report")
        assert status == 400 and body["error"] == "INVALID_REQUEST", body
        status, body = served.post(b"x", length=gateway.event_body_limit() + 1, path="/internal/report")
        assert status == 413 and body["max_bytes"] == gateway.event_body_limit(), body
        # a client cannot report a decision or a state transition into existence
        for forbidden in ("AUTHORIZATION_ALLOWED", "LOCK_CLEARED", "RECOVERY_VERIFIED", "LOCKED_ENTERED"):
            status, body = served.post(report(event_type=forbidden), path="/internal/report")
            assert status == 400 and body["error"] == "INVALID_REQUEST", (forbidden, body)


def test_a_report_cannot_authorize_anything():
    fresh()
    with contained_env():
        lock()
        for event_type in sorted(gateway.REPORTABLE_EVENTS):
            gateway.report_event(report(event_type=event_type))
        out = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert out["decision"] == "LOCKED", "no volume of telemetry unlocks a resource"


def test_routine_checkpoints_are_reportable_and_stay_quiet():
    """A bound project reports at session start and before each protected effect.
    Those reports must be accepted, and must never open an incident or move state."""
    fresh()
    with contained_env(), Served() as served:
        for event_type, evidence in (
                ("SESSION_STARTED", {"checkpoint": "SESSION_START"}),
                ("SESSION_RESUMED", {"checkpoint": "SESSION_RESUME"}),
                ("PROTECTED_EFFECT_PENDING", {"checkpoint": "PRE_PUSH", "action": "git.protected_ref.update"}),
                ("REMOTE_CHANGED", {"detail": "origin moved"}),
                ("BRANCH_PROTECTION_CHANGED", {}), ("POLICY_DIGEST_CHANGED", {}),
                ("NOTICE_DIGEST_CHANGED", {}), ("CREDENTIALS_ROTATED", {})):
            status, body = served.post(report(event_type=event_type, evidence=evidence),
                                       path="/internal/report")
            assert status == 200 and body["accepted"] is True, (event_type, body)
            assert body["authorizes"] is False and body["incident_id"] is None, (event_type, body)
            assert body["severity"] in ("INFO", "NOTICE"), (event_type, body)
            assert body["kind"] == ("checkpoint" if event_type in gateway.CHECKPOINT_EVENTS
                                    else "control_plane_change"), body
            assert body["authorization_state"] == "NORMAL", body
        status, body = served.post(report(event_type="PROTECTED_EFFECT_PENDING",
                                          evidence={"action": "Push Main"}), path="/internal/report")
        assert status == 400 and body["field"] == "evidence.action", body
        status, body = served.post(report(event_type="SESSION_STARTED",
                                          evidence={"checkpoint": "WHENEVER"}), path="/internal/report")
        assert status == 400 and body["field"] == "evidence.checkpoint", body
    assert last("PROTECTED_EFFECT_PENDING")["evidence"]["action"] == "git.protected_ref.update"


def test_a_checkpoint_report_never_lifts_containment():
    fresh()
    with contained_env():
        quarantine()
        out = gateway.report_event(report(event_type="SESSION_STARTED", evidence={}))
        assert out["authorization_state"] == "QUARANTINED" and out["authorizes"] is False, out
        decided = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert decided["decision"] == "QUARANTINE", decided


def test_a_client_cannot_grade_its_own_severity():
    fresh()
    with contained_env():
        out = gateway.report_event(report(event_type="CREDENTIAL_EXTRACTION_ATTEMPT"))
    assert out["severity"] == "CRITICAL", out
    # ...and the field is not even accepted
    try:
        gateway.report_event(report(severity="INFO"))
    except gateway.TargetError as exc:
        assert exc.payload()["error"] == "INVALID_REQUEST"
        return
    raise AssertionError("severity must be server-assigned")


def test_the_request_summary_is_bounded_and_the_prompt_is_not_kept():
    fresh()
    with contained_env():
        gateway.authorize(envelope("git.remote.update"), verifier=verifier())
        record = last("AUTHORIZATION_ALLOWED")
        assert record["request_summary"].startswith("Force push main")
        assert record["request_sha256"].startswith("sha256:")
        assert "request_text" not in record, "the full prompt is not retained by default"
        try:
            gateway.authorize(envelope("git.remote.update",
                                       request_provenance={"request_summary": "x" * 3000}))
        except gateway.TargetError as exc:
            assert exc.payload()["error"] == "INVALID_REQUEST"
        else:
            raise AssertionError("an unbounded summary must be refused")
    # ...and it is kept only when the deployment explicitly asks
    fresh()
    with contained_env(ACP_STORE_FULL_REQUEST_TEXT="1"):
        gateway.authorize(envelope("git.remote.update",
                                   request_provenance={"request_text": "the whole conversation"}),
                          verifier=verifier())
    assert last("AUTHORIZATION_ALLOWED")["request_text"] == "the whole conversation"


def test_provenance_is_recorded_and_validated():
    fresh()
    with contained_env():
        gateway.authorize(envelope("git.remote.update",
                                   request_provenance={"source": "repository_instruction"}),
                          verifier=verifier())
        assert last("AUTHORIZATION_ALLOWED")["provenance_source"] == "repository_instruction"
        try:
            gateway.authorize(envelope("git.remote.update", request_provenance={"source": "made_up"}))
        except gateway.TargetError as exc:
            assert exc.payload()["error"] == "INVALID_REQUEST"
            # ...and provenance never grants anything
            out = gateway.authorize(envelope("git.remote.update",
                                             request_provenance={"source": "interactive_user"}),
                                    verifier=None)
            assert out["decision"] != "ALLOW", out
            return
    raise AssertionError("an unknown provenance must be refused")


# ---- 10-13. redaction ------------------------------------------------------
def test_command_redaction_keeps_the_shape_and_drops_the_value():
    for raw, gone, kept in (
            (f"git push https://{PAT}@github.com/o/r main", PAT, "github.com/o/r"),
            ('curl -H "Authorization: Bearer sk-secret-value" https://api', "sk-secret-value", "curl"),
            ("railway variables --set DEPLOY_SECRET=hunter2hunter2", "hunter2hunter2", "railway variables"),
            (f"echo '{PEM}' > key.pem", "MIIEpAIBAAKCAQEA0123456789", "key.pem"),
            ("gh auth login --token github_pat_11ABCDEFG0aBcDeFgHiJkLmNoP", "github_pat_11ABCDEFG", "gh auth")):
        cleaned = gateway.redact(raw)
        assert gone not in cleaned, raw
        assert kept in cleaned, (raw, cleaned)
        assert "REDACTED" in cleaned, cleaned


def test_planted_secrets_never_reach_the_audit_log():
    fresh()
    planted = {"ACP_GATEWAY_TOKEN": "test-token-long-enough-to-scrub",
               "ACP_GITHUB_PRIVATE_KEY": PEM, "ACP_POLICY_SIGNING_KEY": SIGNING_KEY,
               "ACP_POLICY_ADMIN_TOKEN": ADMIN, "ACP_GITHUB_TOKEN_ANIME_UNIVERSE": PAT}
    with contained_env(**planted):
        gateway.authorize(envelope("git.remote.update", operation={
            "command_redacted": f"git push https://{PAT}@github.com/x/y && "
                                f"curl -H 'Authorization: Bearer {ADMIN}'"}), verifier=verifier())
        gateway.report_event(report(evidence={"detail": f"found {PEM} and {SIGNING_KEY}"}))
        blob = json.dumps(gateway.AUDIT)
    for name, value in planted.items():
        assert value not in blob, name
    assert "REDACTED" in blob


def test_the_inbound_authorization_header_is_never_logged():
    fresh()
    with contained_env(), Served() as served:
        served.post(request("git.remote.update"))
        served.post(report(), path="/internal/report")
    blob = json.dumps(gateway.AUDIT)
    assert "test-token-long-enough-to-scrub" not in blob
    assert "Bearer " not in blob, blob[:400]


# ---- 14-16. identity -------------------------------------------------------
def test_reported_and_verified_identity_are_separate_fields():
    fresh()
    def with_identity(login, ident):
        def verify(claimed, context=None, policy_body=None):
            base = verifier()(claimed, context, policy_body)
            return {**base, "identity": {"login": login, "id": ident}}
        return verify
    with contained_env():
        out = gateway.authorize(envelope("git.remote.update"), verifier=with_identity("alice", 12345))
        assert out["decision"] == "ALLOW", out
        record = last("AUTHORIZATION_ALLOWED")
    assert record["reported_identity"] == {"reported_github_login": "alice",
                                           "reported_github_user_id": "12345"}
    assert record["verified_identity"] == {"github_login": "alice", "github_user_id": 12345,
                                           "verification": "VERIFIED"}


def test_an_identity_mismatch_is_an_event_and_a_refusal():
    fresh()
    def as_someone_else(claimed, context=None, policy_body=None):
        return {**verifier()(claimed, context, policy_body),
                "identity": {"login": "contractor123", "id": 99999}}
    with contained_env():
        out = gateway.authorize(envelope("git.remote.update"), verifier=as_someone_else)
        record = last("IDENTITY_MISMATCH")
    assert out["decision"] == "DENY" and out["reason"] == "IDENTITY_MISMATCH", out
    assert record["severity"] == "HIGH"
    # both identities are preserved; neither overwrites the other
    assert record["reported_identity"]["reported_github_login"] == "alice"
    assert record["verified_identity"]["github_login"] == "contractor123"


def test_a_principal_contradicting_its_own_claim_is_a_mismatch():
    fresh()
    with contained_env():
        out = gateway.authorize(envelope("git.remote.update",
                                         principal={"reported_github_user_id": "99999"}),
                                verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "IDENTITY_MISMATCH", out


def test_an_unresolvable_identity_is_unverified_not_verified():
    fresh()
    with contained_env():
        gateway.authorize(envelope("git.remote.update"), verifier=verifier())
        record = last("AUTHORIZATION_ALLOWED")
    assert record["verified_identity"]["verification"] == "UNVERIFIED", record["verified_identity"]
    assert record["verified_identity"]["github_login"] is None, "consistency is not verification"


# ---- 17-18. alternate agents -----------------------------------------------
def test_an_alternate_agent_after_a_denial_is_observed_not_punished():
    fresh()
    with contained_env():
        body = request("production.deploy")
        body["agent_id"] = "claude"
        first = gateway.authorize(body, verifier=None, now=5000.0)
        assert first["decision"] == "DENY"
        body["agent_id"] = "codex-cli"
        second = gateway.authorize(body, verifier=None, now=5060.0)
        counters = gateway.security_record(gateway.security_keys(claim(), "github-user:12345"))["counters"]
    assert "ALTERNATE_AGENT_OBSERVED" in types() and "DELEGATION_AFTER_DENIAL" in types()
    assert second["decision"] == "DENY", second
    assert second["authorization_state"] == "NORMAL", "an alternate client is not itself a lockout"
    assert counters["delegation_after_denial_count"] == 1
    assert counters["alternate_agent_count"] == 1


def test_ordinary_use_of_a_second_agent_raises_nothing():
    fresh()
    with contained_env():
        for agent in ("claude", "codex-cli"):
            body = request("repository.read")
            body["agent_id"] = agent
            assert gateway.authorize(body)["decision"] == "ALLOW"
    assert "DELEGATION_AFTER_DENIAL" not in types()
    assert "ALTERNATE_AGENT_OBSERVED" not in types()


def test_counters_are_kept_by_category():
    fresh()
    with contained_env():
        quarantine()
        gateway.authorize(request("git.remote.update"), verifier=verifier())      # attempt while A4
        gateway.report_event(report(event_type="CREDENTIAL_EXTRACTION_ATTEMPT"))
        gateway.report_event(report(event_type="IDENTITY_MISMATCH"))
        counters = gateway.security_record(gateway.security_keys(claim(), "github-user:12345"))["counters"]
    assert counters["credential_extraction_count"] == 1
    assert counters["identity_mismatch_count"] == 1
    assert counters.get("ordinary_denial_count", 0) == 0, "categories must not be pooled"


# ---- 19-24. incidents ------------------------------------------------------
def incidents():
    return gateway.list_incidents()["incidents"]


def test_incidents_persist_and_carry_the_whole_recovery():
    with tempfile.TemporaryDirectory() as directory:
        store, log = os.path.join(directory, "s.json"), os.path.join(directory, "audit.jsonl")
        fresh(store)
        with contained_env(ACP_SECURITY_STATE_FILE=store, ACP_AUDIT_LOG=log):
            lock()
            incident = incidents()[0]
            assert incident["status"] == "CONTAINED" and incident["severity"] == "CRITICAL", incident
            assert incident["resource_id"] == RESOURCE
            restart()
            del gateway.AUDIT[:]
            gateway.load_audit_tail()
            assert incidents()[0]["incident_id"] == incident["incident_id"], "A5 incident must persist"
            # the recovery attaches to the same incident, end to end
            gateway.administer({"action": "authorize_recovery", "resource": {"owner": OWNER, "name": REPO},
                                "actor_id": "github-user:12345", "ref": MAIN, "observed_sha": BAD,
                                "target_sha": GOOD, "authorized_by": "security-admin:jane"}, now=2000.0)
            assert incidents()[0]["status"] == "RECOVERY_AUTHORIZED"
            token = gateway.authorize(request(gateway.RECOVERY_OPERATION,
                                              context={"ref": MAIN, "old_sha": BAD, "new_sha": GOOD}),
                                      verifier=verifier(ref_sha=BAD), now=2100.0)["capability_token"]
            gateway.complete_recovery({"capability_token": token}, now=2200.0)
            assert incidents()[0]["status"] == "VERIFYING"
            # a failed verification returns the incident to contained
            gateway.authorize(request("git.remote.update"), verifier=verifier(ref_sha="wrong"), now=2300.0)
            assert incidents()[0]["status"] == "CONTAINED", incidents()[0]
            detail = gateway.incident_detail(incident["incident_id"])
    timeline = [entry["event"] for entry in detail["timeline"]]
    for expected in ("LOCKED_ENTERED", "RECOVERY_AUTHORIZED", "RECOVERY_EXECUTED",
                     "RECOVERY_VERIFICATION_STARTED", "RECOVERY_VERIFICATION_FAILED"):
        assert expected in timeline, (expected, timeline)


def test_a_successful_recovery_resolves_the_incident_and_it_stays_queryable():
    fresh()
    with contained_env():
        lock()
        incident_id = incidents()[0]["incident_id"]
        gateway.administer({"action": "authorize_verification", "resource": {"owner": OWNER, "name": REPO},
                            "actor_id": "github-user:12345", "ref": MAIN, "target_sha": GOOD,
                            "authorized_by": "security-admin:jane"}, now=2000.0)
        out = gateway.authorize(request("git.remote.update"), verifier=verifier(ref_sha=GOOD), now=2100.0)
        assert out["decision"] == "ALLOW", out
        resolved = gateway.get_incident(incident_id)
        detail = gateway.incident_detail(incident_id)
    assert resolved["status"] == "RESOLVED", resolved
    assert detail["incident"]["incident_id"] == incident_id, "a resolved incident is kept, not deleted"
    assert detail["timeline_count"] > 0


def test_a_report_and_a_later_escalation_share_one_incident():
    # The report arrives first and opens the incident; the escalation that
    # follows must attach to it rather than minting a second.
    fresh()
    with contained_env():
        opened = gateway.report_event(report(event_type="CREDENTIAL_EXTRACTION_ATTEMPT"))
        gateway.authorize(request("git.remote.update", context={"signals": ["acp_bypass_attempted"]}),
                          verifier=verifier())
        found = incidents()
    assert len(found) == 1, found
    assert found[0]["incident_id"] == opened["incident_id"]
    assert found[0]["status"] == "CONTAINED" and found[0]["severity"] == "CRITICAL"
    timeline = [entry["event"] for entry in
                gateway.incident_detail(opened["incident_id"])["timeline"]]
    assert "CREDENTIAL_EXTRACTION_ATTEMPT" in timeline and "QUARANTINE_ENTERED" in timeline, timeline


def test_a_lock_is_recorded_once_not_twice():
    fresh()
    with contained_env():
        lock()
        summary = gateway.security_summary("24h", now=1002.0)
    assert [record["event"] for record in gateway.AUDIT].count("LOCKED_ENTERED") == 1
    assert summary["locked"] == 1, summary


def test_an_unrelated_resource_gets_its_own_incident():
    fresh()
    with contained_env():
        lock()
        gateway.report_event(report(event_type="CREDENTIAL_EXTRACTION_ATTEMPT",
                                    resource={"resource_id": "anime-universe/other", "owner": OWNER,
                                              "name": "Other"}))
        found = incidents()
    assert len({entry["incident_id"] for entry in found}) == 2, found
    assert {entry["resource_id"] for entry in found} == {RESOURCE, "anime-universe/other"}


def test_reported_tampering_while_quarantined_escalates_but_never_grants():
    fresh()
    with contained_env():
        quarantine()
        out = gateway.report_event(report(event_type="LOCAL_POLICY_REMOVED"))
        assert out["authorization_state"] == "LOCKED", out
        assert out["authorizes"] is False
        decision = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert decision["decision"] == "LOCKED", decision


def test_deleting_the_local_file_does_not_clear_anything():
    fresh()
    with contained_env():
        quarantined = quarantine()
        assert quarantined["quarantine"]["local_configuration"]["permissions"]["deny"]
        gateway.report_event(report(event_type="LOCAL_POLICY_REMOVED"))
        still = gateway.authorize(request("repository.read"))
    assert still["decision"] == "ALLOW", "reads continue"
    assert gateway.security_record(gateway.security_keys(claim()))["authorization_state"] == "LOCKED"


# ---- 25-29. operator reporting ---------------------------------------------
def test_the_summary_counts_match_the_events_emitted():
    fresh()
    with contained_env():
        for _ in range(3):
            gateway.authorize(request("git.remote.update"), verifier=verifier(), now=10000.0)
        for _ in range(2):
            gateway.authorize(request("production.deploy"), verifier=None, now=10000.0)
        quarantine(now=10000.0)
        summary = gateway.security_summary("24h", now=10000.0)
    ring = [record.get("event") for record in gateway.AUDIT]
    assert summary["allowed"] == ring.count("AUTHORIZATION_ALLOWED") == 3, summary
    assert summary["denied"] == ring.count("AUTHORIZATION_DENIED"), summary
    assert summary["reverify_required"] == ring.count("REVERIFY_REQUIRED"), summary
    assert summary["quarantines"] == ring.count("QUARANTINE_ENTERED") == 1
    # six decisions went in; six are accounted for
    assert summary["authorization_requests"] == 6
    assert (summary["allowed"] + summary["denied"] + summary["auth_required"]
            + summary["reverify_required"]) == 6, summary
    assert summary["by_severity"]["HIGH"] >= 1
    assert summary["open_incidents"] == 1
    try:
        gateway.security_summary("all-time")
    except gateway.TargetError as exc:
        assert exc.payload()["periods"] == ["1h", "24h", "30d", "7d"]
        return
    raise AssertionError("reporting windows are bounded")


def test_event_filtering_and_bounded_pagination():
    fresh()
    with contained_env():
        for index in range(12):
            body = request("git.remote.update")
            body["agent_id"] = "codex-cli" if index % 2 else "claude"
            gateway.authorize(body, verifier=verifier(), now=20000.0)
        first = gateway.query_events({"agent": "codex-cli"}, limit=4, now=20000.0)
        assert first["count"] == 4 and first["matched"] == 6, first
        assert all(record["agent_id"] == "codex-cli" for record in first["events"])
        second = gateway.query_events({"agent": "codex-cli"}, limit=4, cursor=first["next_cursor"],
                                      now=20000.0)
        assert second["count"] == 2 and second["next_cursor"] is None
        assert gateway.query_events({"severity": "INFO"}, now=20000.0)["matched"] == 12
        assert gateway.query_events({"decision": "ALLOW"}, now=20000.0)["matched"] == 12
        assert gateway.query_events({"resource": RESOURCE}, now=20000.0)["matched"] == 12
        # the whole history is never one response
        assert gateway.query_events({}, limit=9999, now=20000.0)["limit"] == gateway.EVENT_QUERY_MAX


def test_security_status_reports_health_without_secrets():
    fresh()
    with contained_env(), Served() as served:
        lock()
        status = gateway.security_status()
        assert status["locked_resources"] == 1 and status["open_incidents"] == 1
        assert status["policy"]["valid"] is True and status["authority"]["healthy"] is True
        assert status["policy_scope"] == [OWNER.lower()], status["policy_scope"]
        _, app_status = served.get("/internal/app-status")
    assert app_status["policy_signing"] is True and app_status["admin_credential"] is True
    blob = json.dumps([status, app_status])
    for secret in (ADMIN, SIGNING_KEY, "test-token-long-enough-to-scrub"):
        assert secret not in blob, secret


def test_reporting_endpoints_need_the_admin_credential():
    fresh()
    with contained_env(), Served() as served:
        for path in ("/internal/security/status", "/internal/security/summary",
                     "/internal/security/events", "/internal/security/incidents",
                     "/internal/security/audit-chain"):
            status, body = served.get(path)
            assert status == 403 and body["error"] == "ADMIN_AUTHORIZATION_REQUIRED", (path, body)
        for path in ("/internal/security/status", "/internal/security/summary?period=1h",
                     "/internal/security/events?limit=5", "/internal/security/incidents"):
            status, body = served.get(path, admin=ADMIN)
            assert status == 200, (path, body)
        status, body = served.get("/internal/security/incidents/inc_nope", admin=ADMIN)
        assert status == 404 and body["error"] == "INCIDENT_NOT_FOUND", body


def test_telemetry_still_works_with_the_provider_gone():
    fresh()
    with contained_env():
        out = gateway.authorize(envelope("git.remote.update"), verifier=None)
        assert out["decision"] != "ALLOW"
        assert last("AUTHORIZATION_DENIED")["request_summary"], "telemetry does not need GitHub"
        accepted = gateway.report_event(report())
    assert accepted["accepted"] is True


# ---- 30-33. notifications and the audit chain ------------------------------
def test_a_notification_failure_never_changes_the_decision():
    fresh()
    with contained_env(ACP_SECURITY_WEBHOOK_URL="https://alerts.example/hook"), \
            patch("gateway.urlopen", side_effect=OSError("the webhook is down")):
        out = lock()
    assert out["decision"] == "LOCKED", out
    assert gateway.security_record(gateway.security_keys(claim()))["authorization_state"] == "LOCKED"
    failures = [record for record in gateway.AUDIT if record["event"] == "NOTIFICATION_FAILED"]
    assert failures and failures[-1]["attempts"] == 2, "bounded retries, then recorded"


def test_the_webhook_payload_carries_no_secret_and_no_prompt():
    fresh()
    sent = []
    class Fake:
        def __enter__(self): return self
        def __exit__(self, *a): return None
    def capture(request_object, timeout=None):
        sent.append(json.loads(request_object.data))
        return Fake()
    with contained_env(ACP_SECURITY_WEBHOOK_URL="https://alerts.example/hook",
                       ACP_SECURITY_WEBHOOK_TOKEN="webhook-token-long-enough",
                       ACP_STORE_FULL_REQUEST_TEXT="1"), \
            patch("gateway.urlopen", side_effect=capture):
        quarantine()
        gateway.authorize(envelope("git.remote.update",
                                   request_provenance={"request_text": "my entire private prompt"}),
                          verifier=verifier())
    assert sent, "a quarantine must alert"
    blob = json.dumps(sent)
    for absent in (ADMIN, SIGNING_KEY, "webhook-token-long-enough", "my entire private prompt",
                   "test-token-long-enough-to-scrub"):
        assert absent not in blob, absent
    assert sent[0]["event"] == "QUARANTINE_ENTERED" and sent[0]["severity"] == "HIGH"
    assert sent[0]["summary"].startswith("HIGH QUARANTINE_ENTERED")


def test_the_audit_chain_verifies_and_notices_an_edit():
    fresh()
    with contained_env(ACP_AUDIT_HASH_CHAIN="1"):
        gateway._CHAIN["head"] = None
        for _ in range(4):
            gateway.authorize(request("git.remote.update"), verifier=verifier())
        records = [dict(entry) for entry in gateway.AUDIT]
    assert gateway.verify_audit_chain(records)["valid"] is True
    tampered = [dict(entry) for entry in records]
    tampered[1]["decision"] = "DENY"
    broken = gateway.verify_audit_chain(tampered)
    assert broken["valid"] is False and broken["broken_at"] == 1, broken
    assert broken["reason"] == "EVENT_HASH_MISMATCH"
    removed = records[:1] + records[2:]
    assert gateway.verify_audit_chain(removed)["valid"] is False, "a deleted event breaks the chain"


def test_the_chain_head_survives_a_restart():
    with tempfile.TemporaryDirectory() as directory:
        store, log = os.path.join(directory, "s.json"), os.path.join(directory, "audit.jsonl")
        fresh(store)
        with contained_env(ACP_AUDIT_HASH_CHAIN="1", ACP_SECURITY_STATE_FILE=store, ACP_AUDIT_LOG=log):
            gateway._CHAIN["head"] = None
            gateway.authorize(request("git.remote.update"), verifier=verifier())
            head = gateway.AUDIT[-1]["event_hash"]
            restart()
            del gateway.AUDIT[:]
            gateway._CHAIN["head"] = None
            gateway.load_audit_tail()
            gateway.authorize(request("git.remote.update"), verifier=verifier())
            assert gateway.AUDIT[-1]["previous_hash"] == head, "the chain continues across a restart"
            assert gateway.verify_audit_chain(list(gateway.AUDIT))["valid"] is True


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} telemetry tests passed")
