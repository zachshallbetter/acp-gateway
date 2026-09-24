"""Tests for the policy channel: ACP decides, and keeps deciding without GitHub.

Every test that needs provider evidence injects a fake verifier. Nothing here
touches the network, GitHub, or a real credential -- which is itself part of the
point: the policy must be evaluable when GitHub is not there at all.
"""
import hashlib, hmac, http.client, json, os, sys, threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402

OWNER, REPO = "Example-Org", "Infinite-Verse"
REMOTE = f"https://github.com/{OWNER}/{REPO}.git"
NOTICE = hashlib.sha256(b"NOTICE\n").hexdigest()
SIGNING_KEY = "policy-signing-key-that-is-long-enough"


def policy(**overrides):
    body = {"policy_id": "notice-enforcer", "version": 1, "status": "active",
            "repository": {"owner": OWNER, "name": REPO, "canonical_remote": REMOTE},
            "notice": {"sha256": NOTICE},
            "protected_actions": list(gateway.DEFAULT_PROTECTED_ACTIONS)}
    body.update(overrides)
    return body


def signed(body, key=SIGNING_KEY):
    digest = gateway.policy_digest(body)
    return {**body, "signature": hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest()}


def env(**extra):
    """A deployment holding one signed policy, and nothing else."""
    base = {"ACP_GATEWAY_TOKEN": "test-token-long-enough-to-scrub",
            "ACP_POLICY": json.dumps(signed(policy())),
            "ACP_POLICY_SIGNING_KEY": SIGNING_KEY,
            "ACP_POLICY_SCOPE": OWNER}
    base.update(extra)
    return patch.dict(os.environ, base, clear=False)


def fresh():
    gateway._REGISTRY.update(key=None, value=None)
    gateway._TRUST_STATE.update(loaded=True, repositories={})
    gateway._SECURITY.update(loaded=True, records={}, degraded=None)
    gateway._LAST_DENIAL.clear()
    gateway._PROVIDER.update(status="UNKNOWN", changed_at=None)
    del gateway.AUDIT[:]


def claim(**overrides):
    body = {"owner": OWNER, "name": REPO, "remote_url": REMOTE, "notice_sha256": NOTICE, "head_sha": "abc123"}
    body.update(overrides)
    return body


def request(action, **overrides):
    body = {"agent_id": "claude-session-abc", "actor_id": "github-user:12345",
            "repository_claim": claim(), "action": action, "context": {}}
    body.update(overrides)
    return body


def verifier(available=True, installed=True, notice=NOTICE, ref_sha=None, fast_forward=None, reason=None, **extra):
    """A stand-in for GitHub. Absent one, ACP has no independent evidence."""
    def verify(claimed, context=None, policy_body=None):
        return {"available": available, "installed": installed,
                "repository": {"owner": OWNER, "name": REPO, "default_branch": "main"} if available else None,
                "notice_sha256": notice, "reason": reason,
                "ref": {"name": (context or {}).get("ref"), "sha": ref_sha} if ref_sha else None,
                "fast_forward": fast_forward, **extra}
    return verify


# ---- 1. the existing read side is untouched -------------------------------
def test_existing_get_endpoints_are_unchanged():
    for route in ("GET /health", "GET /internal/app-status", "GET /internal/app-probe?owner=",
                  "GET /internal/installations", "GET /internal/projects?owner=",
                  "GET /internal/project-context?owner=&project="):
        assert route in gateway.ENDPOINTS, route
    assert "POST /internal/authorize" in gateway.ENDPOINTS
    # and the read-side entry points still exist with their old signatures
    assert gateway.project_context.__code__.co_varnames[:2] == ("owner", "project")
    assert gateway.project_list.__code__.co_argcount == 1


# ---- 2-4. the POST boundary ------------------------------------------------
class Served:
    """The real handler on a loopback port -- the only way to test the HTTP
    contract (auth, media type, Content-Length bounds) rather than the engine."""

    def __enter__(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *_):
        self.server.shutdown(); self.server.server_close()

    def post(self, body, token="test-token-long-enough-to-scrub", media="application/json",
             length=None, path="/internal/authorize", admin=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        headers = {"Content-Length": str(length if length is not None else len(raw))}
        if media:
            headers["Content-Type"] = media
        if token:
            headers["Authorization"] = "Bearer " + token
        if admin:
            headers["X-ACP-Admin-Authorization"] = "Bearer " + admin
        connection.request("POST", path, body=raw, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload

    def get(self, path, token="test-token-long-enough-to-scrub", admin=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=10)
        headers = {"Authorization": "Bearer " + token} if token else {}
        if admin:
            headers["X-ACP-Admin-Authorization"] = "Bearer " + admin
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        return response.status, payload


def test_authorize_requires_the_acp_bearer_token():
    fresh()
    with env(), Served() as served:
        status, body = served.post(request("repository.read"), token=None)
        assert status == 401 and body["error"] == "UNAUTHORIZED", body
        status, body = served.post(request("repository.read"), token="wrong-token-entirely")
        assert status == 401, body
        status, body = served.post(request("repository.read"))
        assert status == 200 and body["decision"] == "ALLOW", body


def test_malformed_json_is_rejected_without_echoing_it():
    fresh()
    with env(), Served() as served:
        status, body = served.post(b'{"action": "repository.read"')
        assert status == 400 and body["error"] == "INVALID_JSON", body
        assert "repository.read" not in json.dumps(body), "a rejected body must not come back"
        status, body = served.post(request("repository.read"), media="text/plain")
        assert status == 415 and body["error"] == "UNSUPPORTED_MEDIA_TYPE", body
        status, body = served.post({"action": "repository.read", "wat": 1})
        assert status == 400 and body["error"] == "INVALID_REQUEST", body


def test_oversized_and_unmeasured_requests_are_rejected():
    fresh()
    with env(), Served() as served:
        status, body = served.post(b"x" * 16, length=gateway.MAX_BODY_BYTES + 1)
        assert status == 413 and body["error"] == "REQUEST_TOO_LARGE", body
        assert body["max_bytes"] == gateway.MAX_BODY_BYTES
        for bad in ({"owner": ["Example-Org"]}, {"owner": True}, {"name": 7}):
            status, body = served.post(request("repository.read", repository_claim=bad))
            assert status == 400 and body["error"] == "INVALID_REQUEST", (bad, body)
        status, body = served.post(request("repository.read", context={"force": "yes"}))
        assert status == 400 and body["field"] == "context.force", body
        status, body = served.post(request("repository.read", context={"signals": "all of them"}))
        assert status == 400 and body["field"] == "context.signals", body
        oversized = request("repository.read")
        oversized["agent_id"] = "a" * (gateway.MAX_FIELD_CHARS + 1)
        status, body = served.post(oversized)
        assert status == 400 and body["error"] == "INVALID_REQUEST", body


def test_get_and_post_share_one_error_contract():
    fresh()
    with env(), Served() as served:
        status, body = served.get("/internal/authorize")
        assert status == 405 and body["error"] == "METHOD_NOT_ALLOWED", body
        status, body = served.post(request("repository.read"), path="/internal/nope")
        assert status == 404 and body["error"] == "NOT_FOUND", body
        status, body = served.get("/health", token=None)
        assert status == 200 and body["status"] == "ok", body


# ---- 5-7. verification is what protected actions turn on -------------------
def test_local_work_needs_no_github_verification():
    fresh()
    with env():
        for action in sorted(gateway.LOCAL_ACTIONS):
            out = gateway.authorize(request(action), verifier=None)
            assert out["decision"] == "ALLOW" and out["reason"] == "NOT_PROTECTED_ACTION", out
            assert out["action_class"] == "local"
            assert out["repository_trust"] == "SELF_REPORTED", out


def test_self_reported_cannot_authorize_a_protected_ref_update():
    fresh()
    with env():
        out = gateway.authorize(request("git.protected_ref.update",
                                        context={"ref": "refs/heads/main", "old_sha": "abc123",
                                                 "new_sha": "def456"}), verifier=None)
    assert out["decision"] == "DENY", out
    assert out["reason"] == "PROTECTED_ACTION_REQUIRES_VERIFICATION"
    assert out["repository_trust"] == "SELF_REPORTED"
    assert out["policy_effect"] == "FAIL_CLOSED_FOR_PROTECTED_ACTIONS"


def test_verified_may_authorize_a_permitted_protected_action():
    fresh()
    with env():
        out = gateway.authorize(request("git.protected_ref.update",
                                        context={"ref": "refs/heads/main", "old_sha": "abc123",
                                                 "new_sha": "def456"}),
                                verifier=verifier(ref_sha="abc123", fast_forward=True))
    assert out["decision"] == "ALLOW" and out["reason"] == "VERIFIED_AND_PERMITTED", out
    assert out["repository_trust"] == "VERIFIED"
    # an ALLOW authorizes exactly one thing
    assert out["authorized_action"] == {"action": "git.protected_ref.update", "ref": "refs/heads/main",
                                        "old_sha": "abc123", "new_sha": "def456"}


def test_a_moved_ref_is_reverified_not_allowed():
    fresh()
    with env():
        out = gateway.authorize(request("git.protected_ref.update",
                                        context={"ref": "refs/heads/main", "old_sha": "abc123",
                                                 "new_sha": "def456"}),
                                verifier=verifier(ref_sha="999999", fast_forward=True))
    assert out["decision"] == "REVERIFY_REQUIRED" and out["reason"] == "STALE_REF_STATE", out


# ---- 8-9. losing GitHub downgrades trust; it does not remove policy --------
def test_losing_the_installation_asks_for_reverification():
    fresh()
    with env():
        # first ACP verifies -- that is what makes the later loss a state change
        ok = gateway.authorize(request("git.remote.update"), verifier=verifier())
        assert ok["decision"] == "ALLOW", ok
        out = gateway.authorize(request("git.remote.update"),
                                verifier=verifier(available=False, installed=False,
                                                  reason="GITHUB_INSTALLATION_REMOVED"))
    assert out["decision"] == "REVERIFY_REQUIRED", out
    assert out["reason"] == "GITHUB_INSTALLATION_REMOVED"
    # and the actor is not accused of anything
    assert out["decision"] != "QUARANTINE"


def test_an_owner_never_verified_is_denied_not_reverified():
    fresh()
    with env():
        out = gateway.authorize(request("git.remote.update"),
                                verifier=verifier(available=False, installed=False))
    assert out["decision"] == "DENY", out
    assert out["reason"] == "PROTECTED_ACTION_REQUIRES_VERIFICATION"


def test_provider_loss_does_not_remove_the_policy():
    fresh()
    with env():
        out = gateway.authorize(request("production.deploy"), verifier=None)
    assert out["policy_id"] == "notice-enforcer" and out["policy_version"] == 1, out
    assert out["decision"] in ("DENY", "REVERIFY_REQUIRED")
    assert out["policy_effect"] == "FAIL_CLOSED_FOR_PROTECTED_ACTIONS"
    # ...and the local half of the same repository still works
    assert gateway.authorize(request("repository.read"), verifier=None)["decision"] == "ALLOW"


def test_github_auth_requirement_is_returned_structurally():
    fresh()
    with env():
        out = gateway.authorize(request("git.remote.update"),
                                verifier=verifier(available=False, installed=False,
                                                  reason="GITHUB_AUTH_REQUIRED",
                                                  auth={"provider": "github", "method": "device_or_oauth",
                                                        "verification_uri": "https://github.com/login/device",
                                                        "user_code": "ABCD-1234", "expires_in": 900}))
    assert out["decision"] == "AUTH_REQUIRED" and out["auth"]["provider"] == "github", out
    assert out["policy_effect"] == "AUTHENTICATION_REQUIRED_BEFORE_RETRY"


# ---- 10-11. the claim is evidence, and it has to line up -------------------
def test_a_notice_mismatch_denies_a_protected_action():
    fresh()
    with env():
        out = gateway.authorize(request("git.remote.update", repository_claim=claim(notice_sha256="0" * 64)),
                                verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "NOTICE_MISMATCH", out


def test_a_notice_mismatch_observed_by_acp_quarantines():
    fresh()
    with env():
        out = gateway.authorize(request("git.remote.update"), verifier=verifier(notice="1" * 64))
    assert out["decision"] == "QUARANTINE" and out["reason"] == "NOTICE_MISMATCH", out
    assert out["repository_trust"] == "QUARANTINED"


def test_a_remote_mismatch_denies():
    fresh()
    with env():
        out = gateway.authorize(
            request("git.protected_ref.update",
                    repository_claim=claim(remote_url="https://github.com/someone-else/Infinite-Verse.git",
                                           notice_sha256=None),
                    context={"ref": "refs/heads/main", "old_sha": "a", "new_sha": "b"}),
            verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "REMOTE_MISMATCH", out


def test_a_fork_of_the_governed_repository_is_not_the_governed_repository():
    fresh()
    with env():
        # matched by canonical remote, but the caller is standing somewhere else
        out = gateway.authorize(request("git.remote.update",
                                        repository_claim=claim(owner=OWNER, name="Infinite-Verse-fork",
                                                               notice_sha256=None)),
                                verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "REPOSITORY_MISMATCH", out


def test_a_repository_acp_cannot_recognise_is_denied():
    fresh()
    def elsewhere(claimed, context=None, policy_body=None):
        return {"available": True, "installed": True, "notice_sha256": NOTICE,
                "repository": {"owner": OWNER, "name": "Something-Else"}}
    with env():
        out = gateway.authorize(request("git.remote.update"), verifier=elsewhere)
    assert out["decision"] == "DENY" and out["reason"] == "REPOSITORY_MISMATCH", out


def test_an_unrelated_repository_is_not_governed_here():
    fresh()
    with env():
        out = gateway.authorize(request("git.protected_ref.update",
                                        repository_claim={"owner": "some-other-org", "name": "thing"},
                                        context={"ref": "refs/heads/main", "old_sha": "a", "new_sha": "b"}))
    assert out["decision"] == "ALLOW" and out["reason"] == "OUT_OF_POLICY_SCOPE", out
    assert out["policy_effect"] == "NOT_GOVERNED"


def test_an_in_scope_repository_with_no_policy_fails_closed():
    fresh()
    with env():
        out = gateway.authorize(request("production.deploy",
                                        repository_claim={"owner": OWNER, "name": "Unregistered"}),
                                verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "POLICY_NOT_FOUND", out


def test_an_unknown_action_fails_closed():
    fresh()
    with env():
        out = gateway.authorize(request("git.something.new"), verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "ACTION_NOT_RECOGNIZED", out


# ---- 12-14. recovery is separate from containment --------------------------
RECOVERY = [{"recovery_id": "rec-001", "policy_id": "notice-enforcer",
             "repository": {"owner": OWNER, "name": REPO}, "ref": "refs/heads/main",
             "observed_sha": "bad0001", "target_sha": "good002",
             "principal": "github-user:12345", "expires_at": 4102444800,
             "actions": ["git.history.rewrite"]}]


def rewrite(**context):
    body = {"ref": "refs/heads/main", "old_sha": "bad0001", "new_sha": "good002"}
    body.update(context)
    return request("git.history.rewrite", context=body)


def test_history_rewrite_requires_a_recovery_authorization():
    fresh()
    with env():
        out = gateway.authorize(rewrite(), verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "RECOVERY_AUTHORIZATION_REQUIRED", out
    assert out["repository_trust"] == "VERIFIED", "verification alone must not authorize a rewrite"


def test_an_exact_recovery_authorization_is_honoured():
    fresh()
    with env(ACP_RECOVERY_AUTHORIZATIONS=json.dumps(RECOVERY)):
        out = gateway.authorize(rewrite(recovery_authorization_id="rec-001"), verifier=verifier())
    assert out["decision"] == "ALLOW" and out["reason"] == "RECOVERY_AUTHORIZED", out
    assert out["authorizing_principal"] == "github-user:12345"
    assert out["authorized_action"]["ref"] == "refs/heads/main"


def test_a_recovery_authorization_cannot_reach_another_ref_or_sha():
    fresh()
    with env(ACP_RECOVERY_AUTHORIZATIONS=json.dumps(RECOVERY)):
        for context in ({"ref": "refs/heads/release"}, {"new_sha": "other99"}, {"old_sha": "moved55"}):
            out = gateway.authorize(rewrite(recovery_authorization_id="rec-001", **context),
                                    verifier=verifier())
            assert out["decision"] == "DENY", (context, out)
            assert out["reason"] == "RECOVERY_AUTHORIZATION_REQUIRED", (context, out)
        expired = [{**RECOVERY[0], "expires_at": 1000}]
    with env(ACP_RECOVERY_AUTHORIZATIONS=json.dumps(expired)):
        out = gateway.authorize(rewrite(recovery_authorization_id="rec-001"), verifier=verifier())
    assert out["decision"] == "DENY" and "expired" in out["detail"], out


def test_an_agent_cannot_supply_its_own_authorization():
    fresh()
    with env():
        # the grant is server-side; presenting an id that is not registered fails
        out = gateway.authorize(rewrite(recovery_authorization_id="rec-forged"), verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "RECOVERY_AUTHORIZATION_REQUIRED", out
    # and there is no request field through which a grant could be sent at all
    assert "recovery_authorization" not in gateway.CONTEXT_FIELDS
    assert gateway.CONTEXT_FIELDS & {"recovery_authorization_id"}


def test_a_force_push_is_elevated_even_when_verified():
    fresh()
    with env():
        out = gateway.authorize(request("git.protected_ref.update",
                                        context={"ref": "refs/heads/main", "old_sha": "abc123",
                                                 "new_sha": "def456", "force": True}),
                                verifier=verifier(ref_sha="abc123", fast_forward=True))
    assert out["decision"] == "DENY" and out["reason"] == "RECOVERY_AUTHORIZATION_REQUIRED", out


def test_a_trust_failure_does_not_authorize_repair():
    fresh()
    with env(ACP_RECOVERY_AUTHORIZATIONS=json.dumps(RECOVERY)):
        out = gateway.authorize(rewrite(recovery_authorization_id="rec-001"),
                                verifier=verifier(available=False, installed=False))
    assert out["decision"] != "ALLOW", out
    assert out["decision"] == "DENY" and out["reason"] == "PROTECTED_ACTION_REQUIRES_VERIFICATION"


# ---- 15-17. ACP itself, and every agent, are treated the same --------------
def test_policy_modification_requires_administrative_authorization():
    fresh()
    with env():
        out = gateway.authorize(request("policy.modify"), verifier=verifier())
        assert out["decision"] == "DENY" and out["reason"] == "POLICY_MODIFICATION_FORBIDDEN", out
        assert out["action_class"] == "administrative"
        credential = gateway.authorize(request("credential.modify"), verifier=verifier())
        assert credential["reason"] == "CREDENTIAL_MODIFICATION_FORBIDDEN", credential
        allowed = gateway.authorize(request("policy.modify"), verifier=verifier(), admin=True)
        assert allowed["decision"] == "ALLOW" and allowed["reason"] == "ADMINISTRATIVELY_AUTHORIZED", allowed


def test_the_admin_credential_is_not_the_gateway_bearer():
    fresh()
    with env(ACP_POLICY_ADMIN_TOKEN="admin-token-long-enough"), Served() as served:
        status, body = served.post(request("policy.modify"))
        assert status == 200 and body["decision"] == "DENY", body
        status, body = served.post(request("policy.modify"), admin="test-token-long-enough-to-scrub")
        assert body["decision"] == "DENY", "the gateway bearer must not double as the admin credential"
        status, body = served.post(request("policy.modify"), admin="admin-token-long-enough")
        assert body["decision"] == "ALLOW", body


def test_a_policy_modification_attempt_is_a_circumvention_signal():
    fresh()
    with env():
        out = gateway.authorize(request("git.remote.update",
                                        context={"signals": ["policy_modification_attempted"]}),
                                verifier=verifier())
    assert out["decision"] == "QUARANTINE" and out["reason"] == "CIRCUMVENTION_SUSPECTED", out
    assert out["policy_effect"] == "CONTAINMENT_NO_AUTOMATIC_REPAIR"


def test_a_mirror_used_for_a_protected_action_quarantines():
    fresh()
    with env():
        out = gateway.authorize(
            request("git.remote.update",
                    repository_claim=claim(remote_url="https://github.com/attacker/Infinite-Verse.git")),
            verifier=verifier())
    assert out["decision"] == "QUARANTINE" and out["reason"] == "CIRCUMVENTION_SUSPECTED", out


def test_the_agent_identity_does_not_change_the_result():
    fresh()
    results = []
    with env():
        for agent in ("claude-session-abc", "codex-cli", "copilot", "some-local-model", "curl/8.4.0", None):
            body = request("git.protected_ref.update",
                           context={"ref": "refs/heads/main", "old_sha": "abc123", "new_sha": "def456"})
            body["agent_id"] = agent
            out = gateway.authorize(body, verifier=None)
            results.append((out["decision"], out["reason"], out["repository_trust"]))
    assert len(set(results)) == 1, results
    assert results[0][0] == "DENY"


# ---- 18-20. integrity, and what never leaves the process -------------------
def test_no_secret_ever_appears_in_a_response():
    fresh()
    secrets = {"ACP_GATEWAY_TOKEN": "test-token-long-enough-to-scrub",
               "ACP_GITHUB_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----abcdefghijklmnop",
               "ACP_POLICY_SIGNING_KEY": SIGNING_KEY,
               "ACP_POLICY_ADMIN_TOKEN": "admin-token-long-enough",
               "ACP_GITHUB_TOKEN_EXAMPLE_ORG": "ghp_averyrealisticlookingtoken"}
    # nothing in this suite may reach the network; the provider is simply absent
    with env(**secrets), patch("gateway.repo_api", side_effect=OSError("offline")), Served() as served:
        seen = []
        for action in ("repository.read", "git.remote.update", "policy.modify"):
            seen.append(json.dumps(served.post(request(action))[1]))
        seen.append(json.dumps(served.get("/internal/policy")[1]))
        seen.append(json.dumps(served.get("/internal/policies/notice-enforcer")[1]))
        seen.append(json.dumps(served.get("/internal/app-status")[1]))
        seen.append(json.dumps(served.post(b"{", token=None)[1]))
    blob = "\n".join(seen)
    for name, value in secrets.items():
        assert value not in blob, name
    # the signature and key id are public; the key that made them is not
    assert "notice-enforcer" in blob and "acp-policy-hmac-sha256" in blob


def test_the_digest_changes_when_the_policy_bytes_change():
    first = gateway.policy_digest(policy())
    assert gateway.policy_digest(policy()) == first, "the digest must be stable"
    assert gateway.policy_digest(policy(version=2)) != first
    assert gateway.policy_digest(policy(protected_actions=["git.remote.update"])) != first
    assert gateway.policy_digest(policy(notice={"sha256": "0" * 64})) != first
    # the signature travels with the body, not inside the digest
    assert gateway.policy_digest({**policy(), "signature": "x" * 64}) == first


def test_an_invalid_signature_fails_closed():
    fresh()
    tampered = {**signed(policy()), "repository": {"owner": OWNER, "name": REPO,
                                                   "canonical_remote": "https://github.com/attacker/x.git"}}
    with env(ACP_POLICY=json.dumps(tampered)):
        registry = gateway.policy_registry()
        record = registry["policies"]["notice-enforcer"]
        assert record["state"] == "INVALID", record
        out = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert out["decision"] == "DENY" and out["reason"] == "POLICY_INVALID", out
    # ...and the same configuration refuses to start at all
    try:
        with env(ACP_POLICY=json.dumps(tampered)):
            gateway.policy_registry(strict=True)
    except ValueError:
        pass
    else:
        raise AssertionError("a policy that does not verify must fail startup")


def test_an_unparseable_policy_fails_closed_and_fails_startup():
    fresh()
    with env(ACP_POLICY="{not json"):
        out = gateway.authorize(request("git.remote.update"), verifier=verifier())
        assert out["decision"] == "DENY" and out["reason"] == "POLICY_INVALID", out
        assert gateway.authorize(request("repository.read"))["decision"] == "ALLOW", "reads may continue"
        try:
            gateway.policy_registry(strict=True)
        except ValueError:
            return
    raise AssertionError("malformed policy configuration must fail startup")


def test_an_unsigned_policy_is_refused_where_signing_is_configured():
    fresh()
    with env(ACP_POLICY=json.dumps(policy())):
        record = gateway.policy_registry()["policies"]["notice-enforcer"]
        assert record["state"] == "INVALID" and "unsigned" in record["error"], record


def test_the_policy_endpoint_publishes_integrity_not_rules():
    fresh()
    with env(), Served() as served:
        status, body = served.get("/internal/policy")
        assert status == 200, body
        entry = body["policies"][0]
        assert entry["sha256"] == gateway.policy_digest(policy())
        assert entry["signature"] and entry["signing_key_id"] == "acp-policy-hmac-sha256"
        assert body["decisions"] == list(gateway.DECISIONS)
        # the hidden half of the policy stays hidden by default
        one = served.get("/internal/policies/notice-enforcer")[1]
        assert "policy" not in one, "the policy body is not published unless asked for"
        assert "notice" not in entry and "notice" not in one, one
        status, body = served.get("/internal/policies/nope")
        assert status == 404 and body["error"] == "POLICY_NOT_FOUND", body


# ---- audit -----------------------------------------------------------------
def test_every_decision_is_audited_without_credentials():
    fresh()
    with env(ACP_GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----abcdefghijklmnop"):
        gateway.authorize(request("git.protected_ref.update",
                                  context={"ref": "refs/heads/main", "old_sha": "a", "new_sha": "b"}),
                          verifier=verifier(ref_sha="a", fast_forward=True))
    entry = gateway.AUDIT[-1]
    for field in ("timestamp", "request_id", "actor_id", "agent_id", "policy_id", "policy_version",
                  "repository_claim", "action", "ref", "old_sha", "new_sha", "verification_state",
                  "decision", "reason"):
        assert field in entry, field
    assert entry["decision"] == "ALLOW" and entry["actor_id"] == "github-user:12345"
    assert "PRIVATE KEY" not in gateway.scrub(json.dumps(entry))


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} policy tests passed")
