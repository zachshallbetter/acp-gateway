"""Tests for the protected-artifact manifest and workspace integrity.

The property under test: no workspace artifact is required for ACP policy to
exist or apply. Files help an agent comply and let tampering be detected sooner.
Deleting them removes evidence, not authority -- and their absence is itself
evidence.
"""
import hashlib, json, os, sys, tempfile
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402
from test_gateway_policy import OWNER, REPO, REMOTE, NOTICE, SIGNING_KEY, claim, request, signed  # noqa
from test_gateway_policy import policy as base_policy, verifier, Served  # noqa: E402
from test_gateway_lockout import ADMIN, GOOD, BAD, MAIN, fresh, restart  # noqa: E402
from unittest.mock import patch as _patch

AGENTS = hashlib.sha256(b"# AGENTS\n").hexdigest()
AGENTS_TAMPERED = hashlib.sha256(b"# AGENTS (replaced)\n").hexdigest()
SETTINGS = hashlib.sha256(b"{}\n").hexdigest()
RESOURCE = f"{OWNER}/{REPO}".lower()
ACTOR = "github-user:12345"

MANIFEST = {
    "artifact_manifest_version": 1,
    "artifacts": [
        {"id": "notice-root", "path": "NOTICE", "kind": "notice", "required": True,
         "expected_sha256": NOTICE, "change_policy": "admin_exact_transition"},
        {"id": "agent-policy-root", "path": ".agents/AGENTS.md", "kind": "control_instruction",
         "required": True, "expected_sha256": AGENTS, "change_policy": "admin_exact_transition"},
        {"id": "client-settings", "path": ".claude/settings.json", "kind": "client_control",
         "required": False, "expected_sha256": SETTINGS, "change_policy": "authorize_and_report"},
    ],
    "patterns": [
        {"id": "agents-tree", "pattern": ".agents/**", "kind": "control_tree",
         "change_policy": "exact_manifest"},
        {"id": "claude-tree", "pattern": ".claude/**", "kind": "client_control_tree",
         "change_policy": "authorize_and_report"},
    ],
    "refs": [{"ref": MAIN, "kind": "protected_ref", "verification": "provider_required"}],
}


def governed_env(**extra):
    body = signed({**base_policy(), "artifact_manifest": MANIFEST})
    return _patch.dict(os.environ, {"ACP_GATEWAY_TOKEN": "test-token-long-enough-to-scrub",
                                    "ACP_POLICY": json.dumps(body),
                                    "ACP_POLICY_SIGNING_KEY": SIGNING_KEY,
                                    "ACP_POLICY_SCOPE": OWNER,
                                    "ACP_POLICY_ADMIN_TOKEN": ADMIN, **extra}, clear=False)


def snapshot(checkpoint="SESSION_START", artifacts=None, diff=None, agent="claude",
             session="sess_1", now=1000.0, **overrides):
    body = {"checkpoint": checkpoint,
            "principal": {"actor_id": ACTOR, "agent_id": agent, "session_id": session},
            "resource": {"resource_id": RESOURCE, "owner": OWNER, "name": REPO},
            "repository": {"remote_url": REMOTE, "branch": "main", "head_sha": "abc123",
                           "detached_head": False, "dirty": False}}
    if artifacts is not None:
        body["artifacts"] = artifacts
    if diff is not None:
        body["diff"] = diff
    body.update(overrides)
    return gateway.integrity_snapshot(body, now=now)


def intact(**overrides):
    seen = {"NOTICE": {"path": "NOTICE", "state": "present", "sha256": NOTICE},
            ".agents/AGENTS.md": {"path": ".agents/AGENTS.md", "state": "present", "sha256": AGENTS},
            ".claude/settings.json": {"path": ".claude/settings.json", "state": "present",
                                      "sha256": SETTINGS}}
    seen.update(overrides)
    return [item for item in seen.values() if item is not None]


def types():
    return [record.get("event") for record in gateway.AUDIT]


def state_of():
    return (gateway.security_record(gateway.security_keys({"owner": OWNER, "name": REPO})) or {})


# ---- 1-4. the NOTICE ------------------------------------------------------
def test_an_intact_workspace_matches():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact())
    assert out["integrity"]["status"] == "MATCH", out
    assert out["integrity"]["unresolved"] is False
    assert out["authorization_state"] == "NORMAL" and out["code"] == "A0"
    assert "INTEGRITY_MATCH" in types() and "INTEGRITY_SNAPSHOT_RECEIVED" in types()


def test_a_missing_notice_is_detected_and_contains():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}))
    assert "NOTICE_REMOVED" in types()
    assert gateway.EVENT_SEVERITY["NOTICE_REMOVED"] == "CRITICAL"
    finding = [f for f in out["integrity"]["findings"] if f["path"] == "NOTICE"][0]
    assert finding["result"] == "MISSING" and finding["material"] is True
    assert finding["expected"] == NOTICE and finding["observed"] == "MISSING"
    assert out["authorization_state"] == "QUARANTINED" and out["code"] == "A4"


def test_a_modified_notice_is_detected():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                                "sha256": "c" * 64}))
    assert "NOTICE_MODIFIED" in types()
    finding = [f for f in out["integrity"]["findings"] if f["path"] == "NOTICE"][0]
    assert finding["result"] == "MODIFIED"
    assert finding["expected"] == NOTICE and finding["observed"] == "c" * 64


def test_restoring_a_file_reports_restoration_but_clears_nothing():
    fresh()
    with governed_env():
        snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}), now=1000.0)
        snapshot(artifacts=intact(**{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                           "state": "missing"}}), now=1001.0)
        assert state_of()["authorization_state"] == "LOCKED"
        out = snapshot(artifacts=intact(), now=1002.0)     # everything put back
    assert "NOTICE_RESTORED" in types() or "PROTECTED_ARTIFACT_RESTORED" in types()
    assert out["integrity"]["status"] == "MATCH"
    assert out["authorization_state"] == "LOCKED", "putting the files back is not a recovery"
    assert out["code"] == "A5"


# ---- 5-9. the protected trees ---------------------------------------------
def test_a_deleted_control_instruction_is_detected():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(**{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                                 "state": "missing"}}))
    assert "CONTROL_ARTIFACT_REMOVED" in types()
    assert out["authorization_state"] == "QUARANTINED"


def test_a_modified_control_instruction_is_detected():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(**{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                                 "state": "present",
                                                                 "sha256": AGENTS_TAMPERED}}))
    assert "CONTROL_ARTIFACT_MODIFIED" in types()
    finding = [f for f in out["integrity"]["findings"] if f["path"] == ".agents/AGENTS.md"][0]
    assert finding["result"] == "MODIFIED" and finding["material"] is True


def test_an_addition_under_a_protected_tree_is_detected():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact() + [{"path": ".agents/injected.md", "state": "present",
                                              "sha256": "d" * 64}])
    assert "CONTROL_ARTIFACT_ADDED" in types()
    finding = [f for f in out["integrity"]["findings"] if f["path"] == ".agents/injected.md"][0]
    assert finding["result"] == "ADDED"
    assert finding["material"] is True, "exact_manifest admits nothing new"


def test_a_client_control_change_is_reported_without_containing():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(**{".claude/settings.json": {"path": ".claude/settings.json",
                                                                     "state": "present",
                                                                     "sha256": "e" * 64}}))
    assert "CLIENT_CONTROL_MODIFIED" in types()
    assert out["integrity"]["status"] == "MISMATCH"
    # authorize_and_report: reported and unresolved, but not itself containment
    assert out["authorization_state"] == "NORMAL", out
    assert out["integrity"]["unresolved"] is True


def test_a_rename_is_detected():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "renamed",
                                                "renamed_from": "NOTICE.bak"}))
    assert "CONTROL_ARTIFACT_RENAMED" in types() or "PROTECTED_ARTIFACT_STATE_MISMATCH" in types()
    assert [f for f in out["integrity"]["findings"] if f["path"] == "NOTICE"][0]["result"] == "RENAMED"


# ---- 10-14. parsing, paths and limits --------------------------------------
def test_path_traversal_cannot_walk_around_the_manifest():
    fresh()
    with governed_env():
        out = snapshot(artifacts=[{"path": ".agents/../NOTICE", "state": "missing"},
                                  {"path": "./.agents/AGENTS.md", "state": "present",
                                   "sha256": AGENTS}])
    # `.agents/../NOTICE` normalises to NOTICE and is matched as NOTICE
    assert [f for f in out["integrity"]["findings"] if f["path"] == "NOTICE"][0]["result"] == "MISSING"
    assert "NOTICE_REMOVED" in types()
    for bad in ("../outside", "/etc/passwd", "~/secret", "a\x00b", "C:/Windows"):
        try:
            snapshot(artifacts=[{"path": bad, "state": "present", "sha256": NOTICE}])
        except gateway.TargetError as exc:
            assert exc.payload()["error"] == "INVALID_REQUEST", (bad, exc.payload())
        else:
            raise AssertionError(f"{bad!r} must be refused, not classified")


def test_case_normalisation_is_deterministic():
    fresh()
    with governed_env():
        out = snapshot(artifacts=[{"path": "notice", "state": "present", "sha256": "f" * 64}])
        finding = [f for f in out["integrity"]["findings"] if f["path"] == "NOTICE"][0]
        assert finding["result"] == "MODIFIED", finding
        assert finding["case_mismatch"] is True, "a case-only difference is reported, not ignored"
    with governed_env(ACP_PATH_CASE_SENSITIVE="1"):
        fresh()
        out = snapshot(artifacts=[{"path": "notice", "state": "present", "sha256": "f" * 64}])
        assert [f for f in out["integrity"]["findings"]
                if f["path"] == "NOTICE"][0]["result"] == "UNVERIFIED"


def test_malformed_hashes_paths_and_oversized_snapshots_are_refused():
    fresh()
    with governed_env(), Served() as served:
        for bad in ("not-a-hash", "abc", "A" * 64 + "0"):
            status, body = served.post({**{"checkpoint": "SESSION_START",
                                           "resource": {"owner": OWNER, "name": REPO}},
                                        "artifacts": [{"path": "NOTICE", "state": "present",
                                                       "sha256": bad}]},
                                       path="/internal/integrity/snapshot")
            assert status == 400 and body["error"] == "INVALID_REQUEST", (bad, body)
        status, body = served.post({"checkpoint": "NOPE", "resource": {"owner": OWNER, "name": REPO}},
                                   path="/internal/integrity/snapshot")
        assert status == 400 and "checkpoints" in body, body
        status, body = served.post(b"x", length=gateway.snapshot_body_limit() + 1,
                                   path="/internal/integrity/snapshot")
        assert status == 413 and body["max_bytes"] == gateway.snapshot_body_limit(), body
        status, body = served.post({"checkpoint": "SESSION_START",
                                    "resource": {"owner": OWNER, "name": REPO},
                                    "artifacts": [{"path": f"f{i}", "state": "missing"}
                                                  for i in range(gateway.MAX_ARTIFACT_ENTRIES + 1)]},
                                   path="/internal/integrity/snapshot")
        assert status == 400 and body["max_entries"] == gateway.MAX_ARTIFACT_ENTRIES, body


# ---- 15-17. the sensor is not the authority --------------------------------
def test_a_snapshot_authorizes_nothing():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact())
        assert out["authorizes"] is False
        # a perfect snapshot does not make a protected action allowed
        decision = gateway.authorize(request("git.remote.update"), verifier=None)
    assert decision["decision"] != "ALLOW", decision


def test_an_observation_never_redefines_the_baseline():
    fresh()
    with governed_env():
        for _ in range(3):
            snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                              "sha256": "a" * 64}))
        view = gateway.integrity_view(OWNER, REPO)
    assert view["baseline_overrides"] == {}, "a repeated wrong hash never becomes the right one"
    assert view["integrity"]["findings"][0]["expected"] == NOTICE
    assert view["integrity"]["status"] == "MISMATCH"


def test_a_reported_hash_stays_self_reported_without_the_provider():
    fresh()
    with governed_env():
        snapshot(artifacts=intact())
        out = gateway.authorize(request("git.remote.update"), verifier=None)
    assert out["repository_trust"] == "SELF_REPORTED", out
    assert out["decision"] != "ALLOW", "matching artifacts are not independent verification"


# ---- 18-22. escalation -----------------------------------------------------
def test_a_non_material_mismatch_holds_protected_work_at_reverify():
    fresh()
    with governed_env():
        snapshot(artifacts=intact(**{".claude/settings.json": {"path": ".claude/settings.json",
                                                               "state": "present",
                                                               "sha256": "e" * 64}}))
        out = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert out["decision"] == "REVERIFY_REQUIRED", out
    assert out["reason"] == "PROTECTED_ARTIFACT_STATE_MISMATCH"
    assert out["integrity"]["findings"][0]["path"] == ".claude/settings.json"


def test_a_mismatch_during_quarantine_escalates():
    fresh()
    with governed_env():
        first = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}), now=1000.0)
        assert first["authorization_state"] == "QUARANTINED"
        second = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"},
                                           **{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                                    "state": "present",
                                                                    "sha256": AGENTS_TAMPERED}}),
                          now=1001.0)
    assert second["authorization_state"] == "LOCKED" and second["code"] == "A5", second
    assert second["incident_id"] == first["incident_id"], "one incident, not two"
    assert state_of()["counters"]["policy_tamper_count"] >= 2


def test_a_new_agent_and_session_still_see_the_lock():
    fresh()
    with governed_env():
        snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}), now=1000.0)
        snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"},
                                  **{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                           "state": "missing"}}), now=1001.0)
        out = snapshot(agent="codex-cli", session="brand-new", artifacts=intact(), now=1002.0)
        decision = gateway.authorize(request("git.remote.update"), verifier=verifier())
    assert out["authorization_state"] == "LOCKED", out
    assert decision["decision"] == "LOCKED", decision


# ---- 23-28. checkpoints ----------------------------------------------------
def test_session_start_detects_an_out_of_band_deletion():
    """The agent was not running when it happened; it is caught the moment one is."""
    fresh()
    with governed_env():
        snapshot(checkpoint="SESSION_START", artifacts=intact(), now=1000.0)   # healthy session
        # ... session ends, a human deletes NOTICE by hand, hours pass ...
        out = snapshot(checkpoint="SESSION_START", session="sess_2",
                       artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}), now=9000.0)
    assert "NOTICE_REMOVED" in types()
    removal = [r for r in gateway.AUDIT if r["event"] == "NOTICE_REMOVED"][0]
    assert removal["previous_result"] == "MATCH", "the transition present -> missing is what is seen"
    assert removal["checkpoint"] == "SESSION_START"
    assert out["authorization_state"] == "QUARANTINED"


def test_session_resume_detects_an_out_of_band_modification():
    fresh()
    with governed_env():
        snapshot(checkpoint="SESSION_START", artifacts=intact(), now=1000.0)
        out = snapshot(checkpoint="SESSION_RESUME",
                       artifacts=intact(**{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                                 "state": "present",
                                                                 "sha256": AGENTS_TAMPERED}}),
                       now=5000.0)
    assert "CONTROL_ARTIFACT_MODIFIED" in types()
    assert out["checkpoint"] == "SESSION_RESUME"
    assert out["authorization_state"] == "QUARANTINED"


def test_diff_checkpoints_catch_protected_changes_before_they_land():
    for checkpoint, change, path in (("PRE_COMMIT", "DELETE", "NOTICE"),
                                     ("PRE_PUSH", "MODIFY", ".agents/AGENTS.md"),
                                     ("PRE_MERGE", "RENAME", ".agents/AGENTS.md")):
        fresh()
        with governed_env():
            entry = {"path": path, "change": change, "old_sha256": NOTICE,
                     "new_sha256": None if change == "DELETE" else "b" * 64}
            if change == "RENAME":
                entry.update(old_path=".agents/AGENTS.md", new_path=".agents/AGENTS.old.md")
            out = snapshot(checkpoint=checkpoint, artifacts=intact(), diff=[entry], now=1000.0)
        found = out["integrity"]["diff"]
        assert found and found[0]["path"] == path, (checkpoint, out)
        assert found[0]["requires_authorization"] is True, (checkpoint, found)
        assert out["integrity"]["status"] == "MISMATCH", checkpoint
        assert out["authorization_state"] == "QUARANTINED", (checkpoint, out)


def test_pre_deploy_refuses_while_a_protected_mismatch_is_unresolved():
    fresh()
    with governed_env():
        snapshot(checkpoint="PRE_DEPLOY",
                 artifacts=intact(**{".claude/settings.json": {"path": ".claude/settings.json",
                                                               "state": "present",
                                                               "sha256": "e" * 64}}), now=1000.0)
        out = gateway.authorize(request("production.deploy"), verifier=verifier())
    assert out["decision"] == "REVERIFY_REQUIRED", out
    assert out["reason"] == "PROTECTED_ARTIFACT_STATE_MISMATCH"


# ---- 29-33. authorised baseline transitions --------------------------------
def grant_change(artifact="NOTICE", old=None, new=None, now=2000.0, **extra):
    return gateway.administer({"action": "authorize_artifact_change",
                               "resource": {"owner": OWNER, "name": REPO},
                               "artifact": artifact, "expected_old_sha256": old or NOTICE,
                               "authorized_new_sha256": new or ("1" * 64),
                               "authorized_by": "security-admin:jane", **extra}, now=now)


def test_an_authorised_exact_transition_advances_the_baseline():
    fresh()
    with governed_env():
        granted = grant_change()
        assert granted["artifact_change"]["single_use"] is True
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                                "sha256": "1" * 64}), now=2100.0)
    assert out["integrity"]["status"] == "MATCH", out
    assert out["baseline_advanced"][0]["path"] == "NOTICE"
    assert out["authorization_state"] == "NORMAL"
    assert "PROTECTED_ARTIFACT_BASELINE_ADVANCED" in types()
    assert state_of()["baseline"]["NOTICE"]["sha256"] == "1" * 64


def test_an_unauthorised_baseline_mutation_is_refused():
    fresh()
    with governed_env():
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                                "sha256": "1" * 64}), now=1000.0)
    assert out["baseline_advanced"] is None
    assert out["authorization_state"] == "QUARANTINED"
    assert state_of().get("baseline", {}) == {}


def test_a_grant_for_one_artifact_cannot_move_another():
    fresh()
    with governed_env():
        grant_change(artifact="NOTICE", old=NOTICE, new="1" * 64)
        out = snapshot(artifacts=intact(**{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                                 "state": "present",
                                                                 "sha256": "1" * 64}}), now=2100.0)
    assert out["baseline_advanced"] is None, out
    assert state_of().get("baseline", {}) == {}
    assert out["authorization_state"] == "QUARANTINED"


def test_a_wrong_old_or_new_hash_invalidates_the_transition():
    fresh()
    with governed_env():
        grant_change(old="9" * 64, new="1" * 64)          # old does not match the manifest
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                                "sha256": "1" * 64}), now=2100.0)
        assert out["baseline_advanced"] is None, out
    fresh()
    with governed_env():
        grant_change(old=NOTICE, new="1" * 64)
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                                "sha256": "2" * 64}), now=2100.0)   # not the target
    assert out["baseline_advanced"] is None, out
    assert state_of().get("baseline", {}) == {}


def test_a_consumed_artifact_grant_cannot_be_replayed():
    fresh()
    with governed_env():
        grant_change(old=NOTICE, new="1" * 64)
        snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present", "sha256": "1" * 64}),
                 now=2100.0)
        # the file is changed again to the same "authorised" value after a revert
        snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present", "sha256": NOTICE}),
                 now=2200.0)
        out = snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "present",
                                                "sha256": "1" * 64}), now=2300.0)
    assert out["baseline_advanced"] is None, "a single-use grant is spent"


def test_a_baseline_grant_only_applies_to_a_protected_path():
    fresh()
    with governed_env():
        try:
            grant_change(artifact="src/main.py")
        except gateway.TargetError as exc:
            assert exc.payload()["error"] == "ARTIFACT_NOT_PROTECTED", exc.payload()
            return
    raise AssertionError("a baseline grant must name a protected artifact")


# ---- 34-35. reporting ------------------------------------------------------
def test_snapshot_findings_reach_the_incident_timeline_and_the_operator_view():
    fresh()
    with governed_env():
        snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}), now=1000.0)
        incident_id = gateway.list_incidents()["incidents"][0]["incident_id"]
        detail = gateway.incident_detail(incident_id)
        view = gateway.integrity_view(OWNER, REPO)
        status = gateway.security_status()
    timeline = [entry["event"] for entry in detail["timeline"]]
    assert "INTEGRITY_SNAPSHOT_RECEIVED" in timeline or "NOTICE_REMOVED" in timeline, timeline
    affected = list(detail["affected"].values())[0]
    assert affected["integrity"]["status"] == "MISMATCH", affected
    assert view["protected_artifacts"] == 3 and view["missing"] == 1 and view["matching"] == 2
    assert view["integrity"]["findings"][0] == {"path": "NOTICE", "expected": NOTICE,
                                                "observed": "MISSING", "result": "MISSING",
                                                "kind": "notice"}
    assert status["protected_artifacts"]["registered"] == 3
    assert status["protected_artifacts"]["resources_with_mismatch"] == 1


def test_no_secret_reaches_a_snapshot_log_or_response():
    fresh()
    pat = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    with governed_env(ACP_GITHUB_TOKEN_ANIME_UNIVERSE=pat), Served() as served:
        status, body = served.post({
            "checkpoint": "PRE_PUSH", "resource": {"owner": OWNER, "name": REPO},
            "principal": {"actor_id": ACTOR},
            "repository": {"remote_url": f"https://{pat}@github.com/{OWNER}/{REPO}.git"},
            "artifacts": intact()}, path="/internal/integrity/snapshot")
        assert status == 200, body
        blob = json.dumps([body, gateway.AUDIT])
    for secret in (pat, ADMIN, SIGNING_KEY, "test-token-long-enough-to-scrub"):
        assert secret not in blob, secret
    assert "REDACTED" in blob


def test_the_snapshot_endpoint_is_behind_the_bearer_and_the_view_behind_the_admin():
    fresh()
    with governed_env(), Served() as served:
        status, _ = served.post({"checkpoint": "SESSION_START",
                                 "resource": {"owner": OWNER, "name": REPO}},
                                path="/internal/integrity/snapshot", token=None)
        assert status == 401
        status, body = served.get(f"/internal/security/integrity?owner={OWNER}&name={REPO}")
        assert status == 403 and body["error"] == "ADMIN_AUTHORIZATION_REQUIRED", body
        status, body = served.get(f"/internal/security/integrity?owner={OWNER}&name={REPO}",
                                  admin=ADMIN)
        assert status == 200 and body["governed"] is True, body


# ---- the two named end-to-end invariants -----------------------------------
def test_end_to_end_out_of_band_tampering_between_sessions():
    """§33, exactly: denial, bypass, quarantine, out-of-band tampering while no
    agent is running, detection on the next session, escalation, and a new agent
    that inherits the lock."""
    with tempfile.TemporaryDirectory() as directory:
        store = os.path.join(directory, "s.json")
        fresh(store)
        with governed_env(ACP_SECURITY_STATE_FILE=store):
            healthy = snapshot(checkpoint="SESSION_START", artifacts=intact(), now=1000.0)
            assert healthy["integrity"]["status"] == "MATCH"

            deletion = gateway.authorize(
                request("git.protected_ref.update",
                        context={"ref": MAIN, "old_sha": "abc123", "new_sha": "def456"}),
                verifier=None, now=1001.0)
            assert deletion["decision"] == "DENY", deletion

            bypassed = gateway.authorize(
                request("git.remote.update", context={"signals": ["acp_bypass_attempted"]}),
                verifier=verifier(), now=1002.0)
            assert bypassed["decision"] == "QUARANTINE" and bypassed["code"] == "A4", bypassed
            incident = bypassed["incident_id"]

            # ---- the agent session ends. NOTICE is deleted and .agents/AGENTS.md
            # ---- replaced by hand, with nothing cooperating running. ----
            restart()

            returned = snapshot(checkpoint="SESSION_START", agent="claude", session="sess_2",
                                artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"},
                                                 **{".agents/AGENTS.md": {
                                                     "path": ".agents/AGENTS.md", "state": "present",
                                                     "sha256": AGENTS_TAMPERED}}), now=9000.0)
            assert "NOTICE_REMOVED" in types() and "CONTROL_ARTIFACT_MODIFIED" in types()
            assert returned["incident_id"] == incident, "the findings join the existing incident"
            assert returned["authorization_state"] == "LOCKED" and returned["code"] == "A5"

            retried = gateway.authorize(request("git.remote.update"), verifier=verifier(), now=9001.0)
            assert retried["decision"] == "LOCKED", retried

            other = request("git.remote.update")
            other["agent_id"], other["session_id"] = "codex-cli", "sess_3"
            assert gateway.authorize(other, verifier=verifier(), now=9002.0)["decision"] == "LOCKED"


def test_end_to_end_a_workspace_stripped_of_every_control_artifact():
    """Remove NOTICE, the whole .agents tree and the whole .claude tree, end the
    session, and come back with an agent that has no workspace instructions at
    all. ACP still knows the resource is governed, and the absence is evidence."""
    with tempfile.TemporaryDirectory() as directory:
        store = os.path.join(directory, "s.json")
        fresh(store)
        with governed_env(ACP_SECURITY_STATE_FILE=store):
            assert snapshot(artifacts=intact(), now=1000.0)["integrity"]["status"] == "MATCH"
            restart()                                   # nothing local survives, ACP restarts too

            stripped = snapshot(checkpoint="SESSION_START", agent="codex-cli", session="cold",
                                artifacts=[{"path": "NOTICE", "state": "missing"},
                                           {"path": ".agents/AGENTS.md", "state": "missing"},
                                           {"path": ".claude/settings.json", "state": "missing"}],
                                now=9000.0)
    assert stripped["governed"] is True, "the policy does not live in the workspace"
    assert stripped["policy_id"] == "notice-enforcer" and stripped["policy_version"] == 1
    assert {f["result"] for f in stripped["integrity"]["findings"]} == {"MISSING"}
    assert stripped["authorization_state"] in ("QUARANTINED", "LOCKED")
    assert stripped["code"] in ("A4", "A5")


def test_end_to_end_a_fresh_clone_of_a_locked_resource_is_still_locked():
    """A5, then every local control artifact deleted, then a fresh clone with no
    ACP files at all, a new agent and a new session. Removing the instructions
    does not grant authority."""
    with tempfile.TemporaryDirectory() as directory:
        store = os.path.join(directory, "s.json")
        fresh(store)
        with governed_env(ACP_SECURITY_STATE_FILE=store):
            snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"}), now=1000.0)
            snapshot(artifacts=intact(NOTICE={"path": "NOTICE", "state": "missing"},
                                      **{".agents/AGENTS.md": {"path": ".agents/AGENTS.md",
                                                               "state": "missing"}}), now=1001.0)
            assert state_of()["authorization_state"] == "LOCKED"
            restart()                                   # ACP restarts; the clone is brand new

            # a pristine checkout: every file present and correct, no ACP history
            pristine = snapshot(checkpoint="SESSION_START", agent="copilot", session="fresh-clone",
                                artifacts=intact(), now=20000.0,
                                repository={"remote_url": REMOTE, "branch": "main",
                                            "head_sha": "fffffff", "detached_head": False,
                                            "dirty": False})
            assert pristine["integrity"]["status"] == "MATCH", "the clone itself is clean"
            assert pristine["authorization_state"] == "LOCKED", pristine
            assert pristine["code"] == "A5"

            decision = gateway.authorize(request("git.remote.update"), verifier=verifier(),
                                         now=20001.0)
    assert decision["decision"] == "LOCKED", decision
    assert decision["recovery"]["class"] == "SECURITY_ADMIN"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} integrity tests passed")
