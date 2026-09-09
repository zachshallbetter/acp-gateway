"""Tests for the persistent states: A4 quarantine, A5 lockout, A6 recovery, A7 verification.

The property under test throughout is that authority only ever *decreases* on
its own. Nothing an agent can do -- a new session, a different model, a fresh
clone, deleting the local quarantine file, reporting success -- moves the state
back toward normal. The only ways forward are an authenticated administrator and
evidence ACP gathered itself.
"""
import hashlib, hmac, http.client, json, os, sys, tempfile, threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402
from test_gateway_policy import (OWNER, REPO, REMOTE, NOTICE, SIGNING_KEY, claim, env,  # noqa: E402
                                 policy, request, signed, verifier, Served)

ADMIN = "admin-token-long-enough-for-tests"
GOOD, BAD = "good0002", "bad00001"
MAIN = "refs/heads/main"


def fresh(state_file=None):
    gateway._REGISTRY.update(key=None, value=None)
    gateway._TRUST_STATE.update(loaded=True, repositories={})
    gateway._SECURITY.update(loaded=not state_file, records={}, degraded=None)
    gateway._LAST_DENIAL.clear()
    gateway._PROVIDER.update(status="UNKNOWN", changed_at=None)
    del gateway.AUDIT[:]


def restart():
    """Everything in memory is gone; only the state file survives."""
    gateway._SECURITY.update(loaded=False, records={}, degraded=None)


def contained_env(**extra):
    return env(**{"ACP_POLICY_ADMIN_TOKEN": ADMIN, **extra})


def signal(name, action="git.remote.update", **overrides):
    body = request(action, context={"signals": [name]})
    body.update(overrides)
    return body


def quarantine(now=1000.0):
    """One material violation: A4."""
    return gateway.authorize(signal("policy_modification_attempted"), verifier=verifier(), now=now)


def escalate_once(now=1001.0):
    """A second material violation on an already-quarantined resource: A5."""
    return gateway.authorize(signal("acp_bypass_attempted"), verifier=verifier(), now=now)


def lock(now=1000.0):
    """Two material violations: A4 then A5."""
    quarantine(now)
    return escalate_once(now + 1)


def events(*names):
    return [entry for entry in gateway.AUDIT if entry.get("event") in names]


def state_of(owner=OWNER, name=REPO):
    return (gateway.security_record(gateway.security_keys({"owner": owner, "name": name})) or {})


# ---- 1-2. escalation, and what must not escalate ---------------------------
def test_repeated_circumvention_escalates_quarantine_to_locked():
    fresh()
    with contained_env():
        first = quarantine()
        assert first["decision"] == "QUARANTINE" and first["code"] == "A4", first
        assert first["authorization_state"] == "QUARANTINED"
        assert first["quarantine"]["local_configuration_path"] == ".claude/settings.local.json"
        second = escalate_once()
    assert second["decision"] == "LOCKED" and second["code"] == "A5", second
    assert second["authorization_state"] == "LOCKED"
    assert second["incident_id"] == first["incident_id"], "one incident, not two"
    assert second["recovery"] == {"required": True, "class": "SECURITY_ADMIN"}
    assert events("QUARANTINE_ENTERED") and events("LOCKED_ENTERED")


def test_provider_disappearance_alone_never_locks():
    fresh()
    with contained_env():
        gateway.authorize(request("git.remote.update"), verifier=verifier())      # verified once
        for _ in range(6):
            out = gateway.authorize(request("git.remote.update"),
                                    verifier=verifier(available=False, installed=False,
                                                      reason="GITHUB_INSTALLATION_REMOVED"))
            assert out["decision"] == "REVERIFY_REQUIRED" and out["code"] == "A3", out
    assert state_of().get("authorization_state", "NORMAL") == "NORMAL"


def test_local_policy_deletion_is_a_material_signal_not_an_escape():
    fresh()
    with contained_env():
        first = gateway.authorize(signal("quarantine_policy_removed"), verifier=verifier())
        assert first["reason"] == "CONTROL_PLANE_INTEGRITY_EVENT", first
        second = gateway.authorize(signal("managed_policy_absent"), verifier=verifier())
    assert second["decision"] == "LOCKED", second


# ---- 3-7. what LOCKED survives ---------------------------------------------
def test_locked_survives_a_restart():
    with tempfile.TemporaryDirectory() as directory:
        store = os.path.join(directory, "security.json")
        fresh(store)
        with contained_env(ACP_SECURITY_STATE_FILE=store):
            lock()
            assert json.load(open(store)), "the state must be on disk, not only in memory"
            restart()
            out = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert out["decision"] == "LOCKED" and out["code"] == "A5", out


def test_authentication_alone_cannot_clear_locked():
    fresh()
    with contained_env():
        lock()
        # a fully successful provider verification is not a way out
        out = gateway.authorize(request("git.remote.update"), verifier=verifier())
        assert out["decision"] == "LOCKED", out
        # nor is the AUTH_REQUIRED flow completing
        out = gateway.authorize(request("git.remote.update"),
                                verifier=verifier(reason="GITHUB_AUTH_REQUIRED"))
    assert out["decision"] == "LOCKED", out


def test_a_different_agent_or_session_or_clone_cannot_clear_locked():
    fresh()
    with contained_env():
        lock()
        results = []
        for agent, session in (("claude-session-abc", "s1"), ("codex-cli", "s2"), ("copilot", "s3"),
                               ("curl/8.4.0", None), (None, "brand-new-session")):
            body = request("git.remote.update")
            body["agent_id"], body["session_id"] = agent, session
            out = gateway.authorize(body, verifier=verifier())
            results.append((out["decision"], out["code"], out["incident_id"]))
        # a fresh clone reports pristine state; it is still the same resource
        pristine = gateway.authorize(request("git.remote.update",
                                             repository_claim=claim(head_sha="fresh999")),
                                     verifier=verifier())
    assert len(set(results)) == 1 and results[0][0] == "LOCKED", results
    assert pristine["decision"] == "LOCKED", pristine


def test_locked_denies_ordinary_protected_work_but_not_reads():
    fresh()
    with contained_env():
        lock()
        for action in ("git.remote.update", "production.deploy", "git.protected_ref.update",
                       "repository.transfer", "git.something.unknown"):
            out = gateway.authorize(request(action, context={"ref": MAIN, "old_sha": "a", "new_sha": "b"}),
                                    verifier=verifier())
            assert out["decision"] == "LOCKED", (action, out)
        read = gateway.authorize(request("repository.read"), verifier=verifier())
    assert read["decision"] == "ALLOW", "read-only inspection must survive containment"


def test_locked_does_not_authorize_recovery_by_itself():
    fresh()
    static = json.dumps([{"recovery_id": "rec-static", "repository": {"owner": OWNER, "name": REPO},
                          "ref": MAIN, "observed_sha": BAD, "target_sha": GOOD,
                          "principal": "github-user:12345", "expires_at": 4102444800}])
    with contained_env(ACP_RECOVERY_AUTHORIZATIONS=static):
        lock()
        # a statically configured grant is not a back door around a lock
        out = gateway.authorize(request("git.history.rewrite",
                                        context={"ref": MAIN, "old_sha": BAD, "new_sha": GOOD,
                                                 "recovery_authorization_id": "rec-static"}),
                                verifier=verifier())
        assert out["decision"] == "LOCKED", out
        # nor is asking for the recovery operation directly
        direct = gateway.authorize(request(gateway.RECOVERY_OPERATION,
                                           context={"ref": MAIN, "old_sha": BAD, "new_sha": GOOD}),
                                   verifier=verifier())
    assert direct["decision"] == "LOCKED", direct


def test_repeated_locked_requests_only_accumulate_audit():
    fresh()
    with contained_env():
        locked = lock()
        version, incident = locked["security_version"], locked["incident_id"]
        for _ in range(6):
            out = gateway.authorize(request("git.remote.update"), verifier=verifier())
            assert out["decision"] == "LOCKED"
            assert out["security_version"] == version, "denial must not escalate the response"
            assert out["incident_id"] == incident
        assert len(events("LOCKED_REQUEST_DENIED")) == 6
        assert state_of()["attempts"] == 6
        # nothing destructive was even offered
        assert "capability_token" not in out and "authorized_action" not in out


# ---- 9-13. A6 is admin-issued and exactly bound ----------------------------
def grant(now=2000.0, ref=MAIN, observed=BAD, target=GOOD, expires_in=900, owner=OWNER, name=REPO):
    return gateway.administer({"action": "authorize_recovery",
                               "resource": {"owner": owner, "name": name},
                               "actor_id": "github-user:12345", "operation": gateway.RECOVERY_OPERATION,
                               "ref": ref, "observed_sha": observed, "target_sha": target,
                               "authorized_by": "security-admin:jane", "expires_in": expires_in}, now=now)


def recover(now=2100.0, ref=MAIN, old=BAD, new=GOOD, ref_sha=None, **overrides):
    body = request(gateway.RECOVERY_OPERATION, context={"ref": ref, "old_sha": old, "new_sha": new})
    body.update(overrides)
    return gateway.authorize(body, verifier=verifier(ref_sha=ref_sha or old), now=now)


def test_recovery_authorization_needs_the_administrative_credential():
    fresh()
    with contained_env(), Served() as served:
        lock()
        payload = {"action": "authorize_recovery", "resource": {"owner": OWNER, "name": REPO},
                   "ref": MAIN, "observed_sha": BAD, "target_sha": GOOD,
                   "authorized_by": "security-admin:jane"}
        status, body = served.post(payload, path="/internal/recover")
        assert status == 403 and body["error"] == "ADMIN_AUTHORIZATION_REQUIRED", body
        status, body = served.post(payload, path="/internal/recover",
                                   admin="test-token-long-enough-to-scrub")
        assert status == 403, "the gateway bearer is not the administrative credential"
        status, body = served.post(payload, path="/internal/recover", admin=ADMIN)
        assert status == 200 and body["authorization_state"] == "RECOVERY_AUTHORIZED", body
        assert body["code"] == "A6" and body["recovery"]["single_use"] is True


def test_a_recovery_grant_is_refused_for_a_resource_that_is_not_contained():
    fresh()
    with contained_env():
        try:
            grant()
        except gateway.TargetError as exc:
            assert exc.payload()["error"] == "NOT_CONTAINED", exc.payload()
            return
    raise AssertionError("recovery grants exist to leave containment, not to pre-authorize a force-push")


def test_a6_binds_the_exact_resource_ref_and_both_shas():
    fresh()
    with contained_env():
        lock()
        grant()
        # ...another repository, reached through the same locked actor
        wrong_repo = gateway.authorize(
            request(gateway.RECOVERY_OPERATION, repository_claim=claim(name="Other-Repo"),
                    context={"ref": MAIN, "old_sha": BAD, "new_sha": GOOD}),
            verifier=verifier(ref_sha=BAD), now=2100.0)
        assert wrong_repo["reason"] == "RECOVERY_PRECONDITION_FAILED", wrong_repo
        assert "different repository" in wrong_repo["detail"]
        for label, kwargs, needle in (("ref", {"ref": "refs/heads/release"}, "different ref"),
                                      ("observed", {"old": "moved111"}, "observed SHA"),
                                      ("target", {"new": "other222"}, "target SHA")):
            out = recover(**kwargs)
            assert out["decision"] == "DENY", (label, out)
            assert out["reason"] == "RECOVERY_PRECONDITION_FAILED", (label, out)
            assert needle in out["detail"], (label, out["detail"])


def test_a6_will_not_retarget_when_the_remote_has_moved():
    fresh()
    with contained_env():
        lock()
        grant()
        # ACP looks for itself: the ref is no longer at the observed revision
        out = recover(ref_sha="somethingelse")
    assert out["decision"] == "DENY" and out["reason"] == "RECOVERY_PRECONDITION_FAILED", out
    assert "expected revision" in out["detail"], out


def test_an_expired_a6_grant_is_rejected():
    fresh()
    with contained_env():
        lock()
        grant(expires_in=60)
        out = recover(now=2000.0 + 5000)
    assert out["decision"] == "DENY" and out["reason"] == "RECOVERY_PRECONDITION_FAILED", out
    assert "expired" in out["detail"], out


def test_ordinary_protected_work_is_refused_while_a6_is_open():
    fresh()
    with contained_env():
        lock()
        grant()
        out = gateway.authorize(request("git.remote.update"), verifier=verifier(), now=2100.0)
    assert out["decision"] == "DENY" and out["reason"] == "RECOVERY_IN_PROGRESS", out
    assert out["authorization_state"] == "RECOVERY_AUTHORIZED"


# ---- 18-19. the authorized transition, and where it leads ------------------
def test_a_valid_a6_permits_exactly_the_authorized_transition():
    fresh()
    with contained_env():
        lock()
        grant()
        out = recover()
    assert out["decision"] == "RECOVERY_AUTHORIZED" and out["code"] == "A6", out
    assert out["policy_effect"] == "SINGLE_RECOVERY_OPERATION_AUTHORIZED"
    assert out["authorized_action"] == {"action": gateway.RECOVERY_OPERATION, "ref": MAIN,
                                        "old_sha": BAD, "new_sha": GOOD}
    assert out["capability"]["single_use"] is True
    assert out["capability"]["scope"] == {"ref": MAIN, "old_sha": BAD, "new_sha": GOOD}
    assert out["authorized_by"] == "security-admin:jane"
    assert out["capability_token"]


def test_executing_the_recovery_moves_to_a7_not_to_normal():
    fresh()
    with contained_env():
        lock()
        grant()
        token = recover()["capability_token"]
        done = gateway.complete_recovery({"capability_token": token, "result": "succeeded"}, now=2200.0)
    assert done["decision"] == "VERIFY_RECOVERY" and done["code"] == "A7", done
    assert done["authorization_state"] == "VERIFY_RECOVERY"
    assert done["expected_target"] == {"ref": MAIN, "sha": GOOD, "authorization_id": None} or \
        done["expected_target"]["sha"] == GOOD, done
    assert events("RECOVERY_EXECUTED") and events("RECOVERY_VERIFICATION_STARTED")


def test_a_consumed_recovery_capability_cannot_be_replayed():
    fresh()
    with contained_env():
        lock()
        grant()
        token = recover()["capability_token"]
        gateway.complete_recovery({"capability_token": token}, now=2200.0)
        replay = gateway.complete_recovery({"capability_token": token}, now=2300.0)
    assert replay["decision"] == "LOCKED" and replay["reason"] == "AUTHORIZATION_REPLAYED", replay
    assert events("RECOVERY_REJECTED")


def test_a_failed_recovery_consumes_the_grant_and_stays_locked():
    fresh()
    with contained_env():
        lock()
        grant()
        token = recover()["capability_token"]
        out = gateway.complete_recovery({"capability_token": token, "result": "failed"}, now=2200.0)
    assert out["decision"] == "LOCKED" and out["reason"] == "RECOVERY_EXECUTION_FAILED", out


# ---- 20-23. A7 is decided by ACP, never by the caller ----------------------
def reach_a7():
    lock()
    grant()
    gateway.complete_recovery({"capability_token": recover()["capability_token"]}, now=2200.0)


def test_a7_denies_ordinary_protected_work():
    fresh()
    with contained_env():
        reach_a7()
        out = gateway.authorize(request("git.remote.update"), verifier=None, now=2300.0)
    assert out["decision"] == "VERIFY_RECOVERY" and out["code"] == "A7", out


def test_a7_cannot_be_completed_by_self_report():
    fresh()
    with contained_env():
        reach_a7()
        # the caller insists the repository is fine; ACP has no evidence of its own
        out = gateway.authorize(request("git.remote.update", repository_claim=claim(head_sha=GOOD)),
                                verifier=verifier(available=False, installed=False), now=2300.0)
    assert out["decision"] == "VERIFY_RECOVERY", out
    assert out["reason"] == "RECOVERY_VERIFICATION_UNAVAILABLE"
    assert state_of()["authorization_state"] == "VERIFY_RECOVERY", "still awaiting real evidence"


def test_failed_a7_verification_returns_to_locked():
    fresh()
    with contained_env():
        reach_a7()
        # the ref is not where the authorized recovery said it would be
        out = gateway.authorize(request("git.remote.update"),
                                verifier=verifier(ref_sha="unexpected99"), now=2300.0)
    assert out["decision"] == "LOCKED" and out["reason"] == "RECOVERY_VERIFICATION_FAILED", out
    assert state_of()["authorization_state"] == "LOCKED"
    assert events("RECOVERY_VERIFICATION_FAILED")


def test_successful_a7_verification_restores_normal_authorization():
    fresh()
    with contained_env():
        reach_a7()
        before = state_of()["security_version"]
        out = gateway.authorize(request("git.remote.update"), verifier=verifier(ref_sha=GOOD), now=2300.0)
        after = state_of()
    assert out["decision"] == "ALLOW" and out["code"] == "A0", out
    assert out["authorization_state"] == "NORMAL" and out["incident_id"] is None
    assert after["authorization_state"] == "NORMAL"
    assert after["security_version"] > before, "recovery must open a fresh security context"
    assert events("RECOVERY_VERIFIED") and events("LOCK_CLEARED")


# ---- 24-25. capabilities are the enforcement boundary ----------------------
def test_capabilities_issued_before_containment_never_come_back():
    fresh()
    with contained_env():
        allowed = gateway.authorize(request("git.remote.update"), verifier=verifier(), now=900.0)
        token = allowed["capability_token"]
        assert gateway.verify_capability(token, now=901.0)["valid"] is True
        lock(now=905.0)
        # still inside its own lifetime, and already dead: the security version moved
        assert gateway.verify_capability(token, now=930.0) == \
            {"valid": False, "reason": "REVOKED", "capability": allowed["capability"]}
        reach_a7()
        fresh_out = gateway.authorize(request("git.remote.update"), verifier=verifier(ref_sha=GOOD), now=2300.0)
        # ...and it stays dead after a fully successful recovery
        assert gateway.verify_capability(token, now=2400.0)["valid"] is False
    assert fresh_out["capability"]["security_version"] > allowed["capability"]["security_version"]


def test_a_capability_is_narrow_and_short_lived():
    fresh()
    with contained_env():
        out = gateway.authorize(request("git.protected_ref.update",
                                        context={"ref": MAIN, "old_sha": "abc123", "new_sha": "def456"}),
                                verifier=verifier(ref_sha="abc123", fast_forward=True), now=900.0)
        capability = out["capability"]
        assert capability["operation"] == "git.protected_ref.update"
        assert capability["scope"] == {"ref": MAIN, "old_sha": "abc123", "new_sha": "def456"}
        assert capability["expires_at_epoch"] - 900 <= 60, "a capability is not a standing permission"
        assert gateway.verify_capability(out["capability_token"], now=901.0)["valid"] is True
        assert gateway.verify_capability(out["capability_token"], now=2000.0)["reason"] == "EXPIRED"
        tampered = out["capability_token"][:-1] + ("0" if out["capability_token"][-1] != "0" else "1")
        assert gateway.verify_capability(tampered, now=901.0)["reason"] == "SIGNATURE_INVALID"


def test_the_capability_boundary_is_reachable_over_http():
    fresh()
    with contained_env(), Served() as served:
        status, out = served.post(request("git.remote.update"), path="/internal/authorize")
        assert status == 200 and out["decision"] in ("DENY", "REVERIFY_REQUIRED"), out
        status, checked = served.post({"capability_token": "nonsense"}, path="/internal/verify-capability")
        assert status == 200 and checked["valid"] is False, checked
        status, body = served.post({"capability_token": "x", "extra": 1}, path="/internal/verify-capability")
        assert status == 400, body


# ---- containment state, and the store itself -------------------------------
def test_administrative_status_and_the_state_endpoint_need_the_admin_credential():
    fresh()
    with contained_env(), Served() as served:
        lock()
        status, body = served.get(f"/internal/security-state?owner={OWNER}&name={REPO}")
        assert status == 403 and body["error"] == "ADMIN_AUTHORIZATION_REQUIRED", body
        connection = http.client.HTTPConnection(*served.server.server_address, timeout=10)
        connection.request("GET", f"/internal/security-state?owner={OWNER}&name={REPO}",
                           headers={"Authorization": "Bearer test-token-long-enough-to-scrub",
                                    "X-ACP-Admin-Authorization": "Bearer " + ADMIN})
        response = connection.getresponse()
        body = json.loads(response.read())
        connection.close()
    assert response.status == 200 and body["authorization_state"] == "LOCKED", body
    assert body["code"] == "A5" and body["incident_id"]
    assert ADMIN not in json.dumps(body) and SIGNING_KEY not in json.dumps(body)


def test_an_unreadable_state_store_fails_closed():
    with tempfile.TemporaryDirectory() as directory:
        store = os.path.join(directory, "security.json")
        open(store, "w").write("{ this is not json")
        gateway._SECURITY.update(loaded=False, records={}, degraded=None)
        gateway._REGISTRY.update(key=None, value=None)
        with contained_env(ACP_SECURITY_STATE_FILE=store):
            assert gateway.security_degraded()
            out = gateway.authorize(request("git.remote.update"), verifier=verifier())
            assert out["decision"] == "DENY" and out["reason"] == "SECURITY_STATE_UNAVAILABLE", out
            # reads still work; only controlled operations stop
            assert gateway.authorize(request("repository.read"))["decision"] == "ALLOW"
    gateway._SECURITY.update(loaded=True, records={}, degraded=None)


def test_an_admin_can_require_verification_without_authorizing_any_repair():
    fresh()
    with contained_env():
        lock()
        out = gateway.administer({"action": "authorize_verification",
                                  "resource": {"owner": OWNER, "name": REPO},
                                  "ref": MAIN, "target_sha": GOOD,
                                  "authorized_by": "security-admin:jane"}, now=2000.0)
        assert out["authorization_state"] == "VERIFY_RECOVERY" and out["code"] == "A7", out
        assert state_of().get("recovery") is None, "no repair was authorized"
        restored = gateway.authorize(request("git.remote.update"),
                                     verifier=verifier(ref_sha=GOOD), now=2100.0)
    assert restored["decision"] == "ALLOW", restored


def test_no_secret_reaches_a_containment_response():
    fresh()
    with contained_env():
        blob = json.dumps([lock(), grant(), recover(),
                           gateway.administer({"action": "status",
                                               "resource": {"owner": OWNER, "name": REPO}})])
    for secret in (ADMIN, SIGNING_KEY, "test-token-long-enough-to-scrub"):
        assert secret not in blob, secret


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} lockout tests passed")
