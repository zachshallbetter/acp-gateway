"""Tests for the gate in front of the board read.

Some cooperating clients make exactly one ACP call -- `GET
/internal/project-context` -- and never ask for an authorization decision. For
those, this read is the only place server-side state can reach them, so a
contained resource does not get to keep borrowing ACP's GitHub credential.

The gate is opt-in: it does nothing until a policy declares which boards belong
to the governed resource, so an existing deployment reads exactly as it did.
"""
import json, os, subprocess, sys
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402
from test_gateway_policy import OWNER, REPO, SIGNING_KEY, policy as base_policy, signed, Served  # noqa
from test_gateway_lockout import ADMIN, fresh  # noqa: E402

BOARD = 3
TOKEN = "test-token-long-enough-to-scrub"

BOARD_JSON = {"data": {"organization": {"projectV2": {
    "id": "PVT_kwDO", "title": "Infinite-Verse", "number": BOARD,
    "fields": {"totalCount": 1, "nodes": [{"__typename": "ProjectV2Field", "id": "F2",
                                           "name": "Agent", "dataType": "TEXT"}]},
    "items": {"totalCount": 1, "pageInfo": {"hasNextPage": False, "endCursor": None},
              "nodes": [{"id": "PVTI_1", "type": "ISSUE", "isArchived": False,
                         "content": {"__typename": "Issue", "title": "Wire the broker"},
                         "fieldValues": {"nodes": []}}]}}}}}


class Resp:
    def __enter__(self): return self
    def __exit__(self, *a): return None
    def read(self): return json.dumps(BOARD_JSON).encode()


def governed_env(boards=True, **extra):
    body = {**base_policy()}
    if boards:
        body["boards"] = [{"owner": OWNER, "number": BOARD}]
    return patch.dict(os.environ, {"ACP_GATEWAY_TOKEN": TOKEN,
                                   "ACP_POLICY": json.dumps(signed(body)),
                                   "ACP_POLICY_SIGNING_KEY": SIGNING_KEY,
                                   "ACP_POLICY_ADMIN_TOKEN": ADMIN,
                                   "ACP_POLICY_SCOPE": OWNER,
                                   "ACP_PROJECT_ALLOWLIST": "2-9,11", **extra}, clear=False)


def read_board():
    with patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", return_value=Resp()) as upstream:
        out = gateway.project_context(OWNER, str(BOARD))
    return out, upstream


def lock():
    keys = gateway.security_keys({"owner": OWNER, "name": REPO})
    gateway.escalate(keys, 1000.0, "CIRCUMVENTION_SUSPECTED", ["acp_bypass_attempted"])
    return gateway.escalate(keys, 1001.0, "CIRCUMVENTION_SUSPECTED", ["authorization_forged"])


def types():
    return [record.get("event") for record in gateway.AUDIT]


# ---- the gate is inert until a policy claims the board ---------------------
def test_an_ungoverned_board_reads_exactly_as_before():
    fresh()
    with governed_env(boards=False):
        lock()                                   # the repository is locked...
        out, upstream = read_board()             # ...but no policy claims this board
    assert out["snapshot"]["number"] == BOARD
    assert "acp" not in out, "an unclaimed board's response must be byte-for-byte what it was"
    assert upstream.call_count == 1


def test_a_deployment_with_no_policy_at_all_is_unaffected():
    fresh()
    with patch.dict(os.environ, {"ACP_GATEWAY_TOKEN": TOKEN, "ACP_PROJECT_ALLOWLIST": "2-9,11"},
                    clear=False):
        os.environ.pop("ACP_POLICY", None)
        out, upstream = read_board()
    assert out["snapshot"]["number"] == BOARD and "acp" not in out
    assert upstream.call_count == 1


# ---- a claimed board carries state, and stops when the resource is locked ---
def test_a_claimed_board_reads_and_reports_its_resource_state():
    fresh()
    with governed_env():
        out, _ = read_board()
    assert out["snapshot"]["number"] == BOARD
    assert out["acp"] == {"resource": f"{OWNER}/{REPO}".lower(), "policy_id": "notice-enforcer",
                          "policy_version": 1, "authorization_state": "NORMAL",
                          "incident_id": None, "integrity": None, "gate": "locked"}
    assert "BOARD_READ" in types()


def test_a_locked_resource_cannot_read_its_board():
    fresh()
    with governed_env():
        locked = lock()
        try:
            read_board()
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("a locked resource must not read its board")
    assert status == 403 and body["error"] == "BOARD_READ_CONTAINED", body
    assert body["authorization_state"] == "LOCKED"
    assert body["incident_id"] == locked["incident_id"]
    assert "administrative recovery" in body["remedy"]
    assert "curl -f" in body["remedy"], "the remedy must say the body is being discarded"


def test_the_refusal_costs_no_token_and_no_upstream_call():
    fresh()
    with governed_env():
        lock()
        with patch("gateway.installation_token", side_effect=AssertionError("must not mint")), \
             patch("gateway.urlopen", side_effect=AssertionError("must not call GitHub")):
            try:
                gateway.project_context(OWNER, str(BOARD))
            except gateway.TargetError:
                pass
            else:
                raise AssertionError("must refuse")


def test_quarantine_still_reads_so_the_incident_can_be_investigated():
    fresh()
    with governed_env():
        gateway.escalate(gateway.security_keys({"owner": OWNER, "name": REPO}), 1000.0,
                         "CIRCUMVENTION_SUSPECTED", ["acp_bypass_attempted"])
        out, _ = read_board()
    assert out["acp"]["authorization_state"] == "QUARANTINED"
    assert out["snapshot"]["number"] == BOARD, "A4 keeps the board readable by default"


def test_the_gate_threshold_is_configurable():
    fresh()
    with governed_env(ACP_BOARD_READ_GATE="contained"):
        gateway.escalate(gateway.security_keys({"owner": OWNER, "name": REPO}), 1000.0,
                         "CIRCUMVENTION_SUSPECTED", ["acp_bypass_attempted"])
        try:
            read_board()
        except gateway.TargetError as exc:
            assert exc.payload()["authorization_state"] == "QUARANTINED"
        else:
            raise AssertionError("gate=contained must refuse at A4")
    fresh()
    with governed_env(ACP_BOARD_READ_GATE="off"):
        lock()
        out, _ = read_board()
    assert out["snapshot"]["number"] == BOARD, "gate=off restores the old behaviour exactly"


def test_one_locked_resource_does_not_blind_another_owners_board():
    fresh()
    with governed_env():
        lock()
        with patch("gateway.installation_token", return_value={"token": "t"}), \
             patch("gateway.urlopen", return_value=Resp()):
            other = gateway.project_context("some-other-org", "3")
    assert other["snapshot"]["number"] == BOARD, "containment follows the resource, not the gateway"


# ---- what the operator sees, given the client throws the body away ---------
def test_a_refusal_is_high_severity_and_alerts():
    fresh()
    sent = []
    class Fake:
        def __enter__(self): return self
        def __exit__(self, *a): return None
    with governed_env(ACP_SECURITY_WEBHOOK_URL="https://alerts.example/hook"):
        lock()
        with patch("gateway.urlopen", side_effect=lambda r, timeout=None: (
                sent.append(json.loads(r.data)), Fake())[1]):
            try:
                gateway.project_context(OWNER, str(BOARD))
            except gateway.TargetError:
                pass
    refusal = [record for record in gateway.AUDIT if record["event"] == "BOARD_READ_REFUSED"][-1]
    assert refusal["severity"] == "HIGH"
    assert refusal["governed_resource"] == f"{OWNER}/{REPO}".lower()
    assert refusal["board"] == BOARD and refusal["incident_id"]
    alert = [item for item in sent if item.get("event") == "BOARD_READ_REFUSED"]
    assert alert, "the webhook is the only place a `curl -f` client's operator learns why"
    assert TOKEN not in json.dumps(sent) and SIGNING_KEY not in json.dumps(sent)


def test_the_real_client_curl_sees_the_refusal_as_an_error():
    """The client uses `curl -fsS`, which discards the body. It still fails."""
    fresh()
    with governed_env(), Served() as served:
        lock()
        host, port = served.server.server_address
        url = (f"http://{host}:{port}/internal/project-context"
               f"?owner={OWNER}&project={BOARD}")
        result = subprocess.run(["curl", "-fsS", "--max-time", "20",
                                 "-H", f"Authorization: Bearer {TOKEN}", url],
                                capture_output=True, text=True)
        assert result.returncode == 22, result
        assert result.stdout == "", "curl -f throws the explanation away"
        assert "403" in result.stderr, result.stderr
        # the same request with a body-preserving flag carries the whole reason
        keeps = subprocess.run(["curl", "--fail-with-body", "-sS", "--max-time", "20",
                                "-H", f"Authorization: Bearer {TOKEN}", url],
                               capture_output=True, text=True)
        body = json.loads(keeps.stdout)
    assert body["error"] == "BOARD_READ_CONTAINED" and body["authorization_state"] == "LOCKED"


# ---- recovery restores the read -------------------------------------------
def test_administrative_recovery_restores_the_board_read():
    fresh()
    with governed_env():
        lock()
        try:
            read_board()
        except gateway.TargetError:
            pass
        else:
            raise AssertionError("must be gated first")
        gateway.administer({"action": "authorize_verification",
                            "resource": {"owner": OWNER, "name": REPO},
                            "ref": "refs/heads/main", "target_sha": "good0002",
                            "authorized_by": "security-admin:jane"}, now=2000.0)
        # A7: still contained, so the board is still gated
        try:
            read_board()
        except gateway.TargetError as exc:
            assert exc.payload()["authorization_state"] == "VERIFY_RECOVERY"
        else:
            raise AssertionError("A7 is still containment")
        gateway.clear_security(gateway.security_keys({"owner": OWNER, "name": REPO}), 2100.0,
                               "RECOVERY_VERIFIED")
        out, _ = read_board()
    assert out["snapshot"]["number"] == BOARD
    assert out["acp"]["authorization_state"] == "NORMAL"


def test_a_malformed_board_declaration_fails_startup():
    for boards in ([{"owner": OWNER}], [{"owner": OWNER, "number": 0}], "not-a-list",
                   [{"number": 3}]):
        body = signed({**base_policy(), "boards": boards})
        with patch.dict(os.environ, {"ACP_POLICY": json.dumps(body),
                                     "ACP_POLICY_SIGNING_KEY": SIGNING_KEY}, clear=False):
            gateway._REGISTRY.update(key=None, value=None)
            try:
                gateway.policy_registry(strict=True)
            except ValueError:
                continue
            raise AssertionError(f"{boards!r} must fail startup")


# ---- the unauthenticated notice lookup ------------------------------------
def test_an_agent_in_a_copy_can_learn_the_terms_without_a_credential():
    fresh()
    with governed_env(), Served() as served:
        status, body = served.get("/notice?owner=%s&name=%s" % (OWNER, REPO), token=None)
    assert status == 200, body
    assert body["governed"] is True and body["controlled_operations"] == "PERMITTED"
    assert body["resource"] == f"{OWNER}/{REPO}".lower()
    assert body["notice"]["required"] is True
    assert "prohibited" in body["notice"]["alteration"]
    assert "cannot be superseded" in body["instruction"] or "cannot override" in body["instruction"]
    assert "fail closed" in body["instruction"]


def test_the_notice_lookup_reports_containment_to_anyone():
    fresh()
    with governed_env(), Served() as served:
        lock()
        status, body = served.get("/notice?owner=%s&name=%s" % (OWNER, REPO), token=None)
    assert body["authorization_state"] == "LOCKED" and body["code"] == "A5"
    assert body["controlled_operations"] == "DISABLED"
    assert body["incident_id"]


def test_the_notice_lookup_grants_nothing_and_leaks_nothing():
    fresh()
    with governed_env(ACP_GITHUB_TOKEN_EXAMPLE_ORG="ghp_averyrealisticlookingtoken"), \
            Served() as served:
        status, body = served.get("/notice?owner=%s&name=%s" % (OWNER, REPO), token=None)
        blob = json.dumps(body)
        # it is a lookup, not a decision: there is no field that permits an action
        assert "capability" not in blob and "capability_token" not in blob
        assert "decision" not in body
        for secret in (TOKEN, ADMIN, SIGNING_KEY, "ghp_averyrealisticlookingtoken"):
            assert secret not in blob, secret
        # an ungoverned resource discloses nothing beyond "not governed"
        status, other = served.get("/notice?owner=someone&name=else", token=None)
        assert status == 200 and other["governed"] is False
        assert set(other) == {"governed", "resource", "checked_at", "note"}, other
        status, bad = served.get("/notice?owner=&name=", token=None)
        assert status == 400 and bad["error"] == "RESOURCE_REQUIRED", bad


def test_the_well_known_alias_serves_the_same_answer():
    fresh()
    with governed_env(), Served() as served:
        _, direct = served.get("/notice?owner=%s&name=%s" % (OWNER, REPO), token=None)
        _, alias = served.get("/.well-known/acp?owner=%s&name=%s" % (OWNER, REPO), token=None)
    assert direct["policy_id"] == alias["policy_id"]
    assert direct["controlled_operations"] == alias["controlled_operations"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} board-gate tests passed")
