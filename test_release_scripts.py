"""scripts/ff-merge.py and scripts/release.py against local git repositories and fakes for ACP, the
owner's harness, Vercel and Railway. No network, Keychain or real CLI is reached."""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "scripts"))
import acp_ops
from acp_ops import Stop


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ff = load("ff_merge_under_test", "ff-merge.py")
release = load("release_under_test", "release.py")
release.sleep = lambda seconds: None


def sh(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class Repos:
    """A bare 'GitHub' remote and a clone with main at one commit."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.remote, self.clone = base / "remote.git", base / "clone"
        sh(base, "git", "init", "-q", "--bare", "-b", "main", str(self.remote))
        sh(base, "git", "init", "-q", "-b", "main", str(self.clone))
        for key, value in (("user.name", "t"), ("user.email", "t@example.invalid"), ("commit.gpgsign", "false")):
            sh(self.clone, "git", "config", key, value)
        sh(self.clone, "git", "remote", "add", "origin", str(self.remote))
        self.main = self.commit("base")
        sh(self.clone, "git", "push", "-q", "origin", "main")

    def commit(self, message):
        sh(self.clone, "git", "commit", "-q", "--allow-empty", "-m", message)
        return sh(self.clone, "git", "rev-parse", "HEAD")

    def remote_main(self):
        return sh(self.remote, "git", "rev-parse", "refs/heads/main")

    def close(self):
        self.tmp.cleanup()


def allow(action, **scope):
    return {"decision": "ALLOW", "reason": "VERIFIED_AND_PERMITTED", "request_id": "r1",
            "authorized_action": {"action": action, **scope}}


class FFMergeTests(unittest.TestCase):
    def setUp(self):
        self.repos = Repos()
        patcher = patch.object(acp_ops, "github_repository", lambda checkout, remote: ("owner", "repo"))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.repos.close)

    def published_feature(self):
        sh(self.repos.clone, "git", "checkout", "-q", "-b", "feature")
        new = self.repos.commit("change")
        sh(self.repos.clone, "git", "push", "-q", "origin", "feature")
        return new

    def test_plan_names_the_exact_update(self):
        new = self.published_feature()
        update = ff.plan(self.repos.clone, "origin", "refs/heads/main", "HEAD")
        self.assertEqual(update, {"owner": "owner", "name": "repo", "remote": "origin", "ref": "refs/heads/main",
                                  "old_sha": self.repos.main, "new_sha": new})

    def test_plan_refuses_an_unpublished_revision(self):
        sh(self.repos.clone, "git", "checkout", "-q", "-b", "feature")
        self.repos.commit("local only")
        with self.assertRaisesRegex(Stop, "Push the branch"):
            ff.plan(self.repos.clone, "origin", "refs/heads/main", "HEAD")

    def test_plan_refuses_a_revision_that_is_not_a_fast_forward(self):
        new = self.published_feature()
        sh(self.repos.clone, "git", "checkout", "-q", "main")
        self.repos.commit("main moved")
        sh(self.repos.clone, "git", "push", "-q", "origin", "main")
        with self.assertRaisesRegex(Stop, "Rebase onto origin/main"):
            ff.plan(self.repos.clone, "origin", "refs/heads/main", new)

    def test_plan_refuses_a_short_ref_and_a_no_op(self):
        with self.assertRaisesRegex(Stop, "full branch ref"):
            ff.plan(self.repos.clone, "origin", "main", "HEAD")
        with self.assertRaisesRegex(Stop, "nothing to fast-forward"):
            ff.plan(self.repos.clone, "origin", "refs/heads/main", "HEAD")

    def update(self):
        self.published_feature()
        return ff.plan(self.repos.clone, "origin", "refs/heads/main", "HEAD")

    def test_an_exact_allow_pushes_the_reviewed_revision(self):
        update = self.update()
        scope = {k: update[k] for k in ("ref", "old_sha", "new_sha")}
        with patch.object(acp_ops, "authorize", return_value=allow("git.protected_ref.update", **scope)) as asked, \
                patch("sys.stdout", io.StringIO()):
            ff.merge(self.repos.clone, update, "token", "owner/repo#1")
        self.assertEqual(self.repos.remote_main(), update["new_sha"])
        context = asked.call_args.args[5]
        self.assertEqual(context, {**scope, "work_item": "owner/repo#1"})

    def test_a_refusal_or_a_different_scope_leaves_the_ref_alone(self):
        update = self.update()
        refused = {"decision": "AUTH_REQUIRED", "reason": "OWNER_REQUIRED", "remedy": "ask the owner"}
        other = allow("git.protected_ref.update", ref=update["ref"], old_sha=update["old_sha"], new_sha="0" * 40)
        for decision, message in ((refused, "OWNER_REQUIRED. ask the owner"), (other, "did not authorize")):
            with self.subTest(decision=decision["decision"]), \
                    patch.object(acp_ops, "authorize", return_value=decision), patch("sys.stdout", io.StringIO()):
                with self.assertRaisesRegex(Stop, message):
                    ff.merge(self.repos.clone, update, "token", "owner/repo#1")
            self.assertEqual(self.repos.remote_main(), self.repos.main)

    def test_dry_run_asks_nobody(self):
        self.published_feature()
        with patch.object(acp_ops, "authorize") as asked, patch.object(acp_ops, "harness_gate") as gate, \
                patch("os.getcwd", return_value=str(self.repos.clone)), patch("sys.stdout", io.StringIO()):
            code = ff.main(["--work-item", "owner/repo#1", "--dry-run"])
        self.assertEqual(code, 0)
        asked.assert_not_called()
        gate.assert_not_called()


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.env = patch.dict(os.environ, {"HARNESS_HOME": self.home.name})
        self.env.start()
        self.addCleanup(self.env.stop)

    def write_guard(self, held=None, approved=False):
        Path(self.home.name, "guard_common.py").write_text(
            f"def held():\n    return {held!r}\n\ndef approved(scope, repo):\n    return {approved!r}\n")

    def test_without_the_harness_acp_is_the_only_gate(self):
        self.assertIn("ACP is the only gate", acp_ops.harness_gate("repo"))

    def test_hold_and_a_missing_approval_refuse_with_the_fix(self):
        self.write_guard(held="incident")
        with self.assertRaisesRegex(Stop, "on hold \\(incident\\)"):
            acp_ops.harness_gate("repo")
        self.write_guard(approved=False)
        with self.assertRaisesRegex(Stop, "approve.py hosted repo 30"):
            acp_ops.harness_gate("repo")

    def test_an_open_window_lets_it_through(self):
        self.write_guard(approved=True)
        self.assertEqual(acp_ops.harness_gate("repo"), "owner approval for hosted repo")


class BearerTests(unittest.TestCase):
    def test_the_environment_comes_before_the_keychain(self):
        with patch.dict(os.environ, {"ACP_GATEWAY_TOKEN": "from-env"}), patch.object(acp_ops, "run") as ran:
            self.assertEqual(acp_ops.bearer("ACP_GATEWAY_TOKEN"), "from-env")
        ran.assert_not_called()

    def test_an_unresolved_reference_names_the_fix(self):
        with patch.dict(os.environ, {"ACP_GATEWAY_TOKEN": "latchkey://acp-gateway/production/ACP_GATEWAY_TOKEN"}):
            with self.assertRaisesRegex(Stop, "latchkey run --env-file"):
                acp_ops.bearer("ACP_GATEWAY_TOKEN")

    def test_neither_source_names_the_fix(self):
        with patch.dict(os.environ, {"ACP_GATEWAY_TOKEN": ""}), \
                patch.object(acp_ops, "run", return_value=completed("", 44)):
            with self.assertRaisesRegex(Stop, "neither in the environment nor in the Keychain"):
                acp_ops.bearer("ACP_GATEWAY_TOKEN")


class AuthorizeTests(unittest.TestCase):
    def test_returns_decision_fields_only(self):
        body = {"decision": "ALLOW", "reason": "VERIFIED_AND_PERMITTED", "capability_token": "secret",
                "authorized_action": {"action": "a"}}

        class Response(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with patch.object(acp_ops, "urlopen", return_value=Response(json.dumps(body).encode())):
            decision = acp_ops.authorize("t", "o", "n", "a", "1" * 40, {}, "s", "agent")
        self.assertNotIn("capability_token", decision)
        self.assertEqual(decision["decision"], "ALLOW")

    def test_an_http_refusal_carries_its_remedy(self):
        error = urllib.error.HTTPError("u", 400, "bad", {}, io.BytesIO(json.dumps(
            {"error": "INVALID_REQUEST", "detail": "bad ref", "remedy": "use a full ref"}).encode()))
        with patch.object(acp_ops, "urlopen", side_effect=error):
            with self.assertRaisesRegex(Stop, "400 INVALID_REQUEST: bad ref use a full ref"):
                acp_ops.authorize("t", "o", "n", "a", "1" * 40, {}, "s", "agent")


def completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class MigrationTests(unittest.TestCase):
    def test_current_database_needs_no_step(self):
        self.assertIsNone(release.pending_plan({"status": "current", "pending_versions": []}))

    def test_additive_pending_migrations_are_planned(self):
        step = release.pending_plan({"applied_versions": ["0001", "0002", "0003"], "pending_versions": ["0004"]})
        self.assertEqual(step, {"from": "0003", "to": "0004", "versions": ["0004"]})

    def test_a_non_additive_pending_migration_stops_the_release(self):
        with self.assertRaisesRegex(Stop, "0003 are not marked additive"):
            release.pending_plan({"applied_versions": ["0001", "0002"], "pending_versions": ["0003", "0004"]})

    def test_the_check_needs_the_migration_url(self):
        with patch.dict(os.environ, {"ACP_DATABASE_MIGRATION_URL": ""}):
            with self.assertRaisesRegex(Stop, "ACP_DATABASE_MIGRATION_URL is not set"):
                release.migration_state()
        reference = "latchkey://acp-gateway/production/ACP_DATABASE_MIGRATION_URL"
        with patch.dict(os.environ, {"ACP_DATABASE_MIGRATION_URL": reference}), \
                patch.object(acp_ops, "run") as ran:
            with self.assertRaisesRegex(Stop, "Latchkey reference.*latchkey run --env-file"):
                release.migration_state()
        ran.assert_not_called()

    def test_a_conflicting_history_stops_before_anything_changes(self):
        with patch.dict(os.environ, {"ACP_DATABASE_MIGRATION_URL": "set"}), \
                patch.object(acp_ops, "run", return_value=completed('{"status": "conflict"}', 1)):
            with self.assertRaisesRegex(Stop, "migration check failed"):
                release.migration_state()

    def test_migrate_binds_the_exact_scope(self):
        update = {"owner": "o", "name": "n", "new_sha": "a" * 40}
        step = {"from": "0003", "to": "0004", "versions": ["0004"]}
        expected = {"source_database": f"{release.DATABASE_ID}-at-0003",
                    "target_database": f"{release.DATABASE_ID}-at-0004", "work_item": "o/n#1",
                    "environment": "production", "ref": "refs/heads/feature", "new_sha": "a" * 40}
        with patch.object(acp_ops, "authorize", return_value=allow("database.migrate", **expected)) as asked, \
                patch.object(acp_ops, "run", return_value=completed('{"status": "ok"}')) as ran, \
                patch.object(release, "migration_state", return_value=(0, {"status": "current"})), \
                patch("sys.stdout", io.StringIO()):
            release.migrate(update, "feature", "t", "o/n#1", step)
        self.assertEqual(asked.call_args.args[5], expected)
        self.assertTrue(ran.call_args.args[1].endswith("scripts/migrate-db.py"))

    def test_migrate_does_not_run_without_an_exact_allow(self):
        update = {"owner": "o", "name": "n", "new_sha": "a" * 40}
        step = {"from": "0003", "to": "0004", "versions": ["0004"]}
        with patch.object(acp_ops, "authorize", return_value={"decision": "DENY", "reason": "X"}), \
                patch.object(acp_ops, "run") as ran, patch("sys.stdout", io.StringIO()):
            with self.assertRaisesRegex(Stop, "did not authorize database.migrate"):
                release.migrate(update, "feature", "t", "o/n#1", step)
        ran.assert_not_called()


SHA = "c" * 40


def vercel_listing(*states):
    return [completed(json.dumps({"deployments": [] if state is None else [
        {"url": "dpl-new.vercel.app", "state": state, "meta": {"githubCommitSha": SHA}},
        {"url": "dpl-old.vercel.app", "state": "READY", "meta": {"githubCommitSha": "d" * 40}}]}))
        for state in states]


class VercelTests(unittest.TestCase):
    def test_waits_for_the_build_of_this_revision(self):
        with patch.object(acp_ops, "run", side_effect=vercel_listing(None, "BUILDING", "READY")):
            build = release.vercel_build(SHA, 60)
        self.assertEqual(build["url"], "dpl-new.vercel.app")

    def test_a_failed_build_stops_before_railway(self):
        with patch.object(acp_ops, "run", side_effect=vercel_listing("ERROR")):
            with self.assertRaisesRegex(Stop, "alias stays on the previous deployment"):
                release.vercel_build(SHA, 60)

    def test_the_alias_must_point_at_the_new_build(self):
        with patch.object(acp_ops, "run", return_value=completed(json.dumps({"url": "dpl-old.vercel.app"}))):
            with self.assertRaisesRegex(Stop, "points at dpl-old"):
                release.vercel_alias({"url": "dpl-new.vercel.app"})


class RailwayTests(unittest.TestCase):
    def setUp(self):
        self.repos = Repos()
        self.addCleanup(self.repos.close)
        self.uploaded = []

    def fake_run(self, listings):
        def run(*args, cwd=None, input=None):
            if args[:3] == ("railway", "deployment", "list"):
                return completed(json.dumps(listings.pop(0)))
            if args[:2] == ("railway", "up"):
                self.uploaded.append(sorted(p.name for p in Path(args[2]).iterdir()))
                return completed()
            raise AssertionError(args)
        return run

    def test_deploys_the_archived_revision_and_waits_for_success(self):
        Path(self.repos.clone, "tracked.txt").write_text("x")
        sh(self.repos.clone, "git", "add", "tracked.txt")
        sha = self.repos.commit("tracked")
        Path(self.repos.clone, "local-only.json").write_text("{}")
        listings = [[{"id": "old", "status": "SUCCESS"}], [{"id": "old", "status": "SUCCESS"}],
                    [{"id": "new", "status": "BUILDING"}], [{"id": "new", "status": "SUCCESS"}]]
        with patch.object(acp_ops, "run", side_effect=self.fake_run(listings)):
            deployment = release.railway_deploy(self.repos.clone, sha, 60)
        self.assertEqual(deployment["id"], "new")
        self.assertEqual(self.uploaded, [["tracked.txt"]])

    def test_a_failed_deployment_is_reported(self):
        listings = [[{"id": "old", "status": "SUCCESS"}], [{"id": "new", "status": "FAILED"}]]
        with patch.object(acp_ops, "run", side_effect=self.fake_run(listings)):
            with self.assertRaisesRegex(Stop, "ended FAILED"):
                release.railway_deploy(self.repos.clone, self.repos.main, 60)


class ReleaseOrderTests(unittest.TestCase):
    def run_release(self, dry_run=False, step=None, skip_railway=False):
        calls = []
        update = {"owner": "zachshallbetter", "name": "acp-gateway", "remote": "origin", "ref": "refs/heads/main",
                  "old_sha": "b" * 40, "new_sha": SHA}

        def git(checkout, *args):
            if args[0] == "status":
                return ""
            if args[0] == "ls-remote":
                return f"{SHA}\trefs/heads/feature"
            raise AssertionError(args)

        def note(name, value=None):
            def record(*args, **kwargs):
                calls.append(name)
                return value
            return record

        args = argparse.Namespace(work_item="zachshallbetter/acp-gateway#1", branch="feature", dry_run=dry_run,
                                  token_account="ACP_GATEWAY_TOKEN", timeout=60, skip_railway=skip_railway)
        state = {"status": "pending" if step else "current", "pending_versions": step["versions"] if step else []}
        with patch.object(release, "git", git), \
                patch.object(release.ff_merge, "plan", note("plan", update)), \
                patch.object(release, "migration_state", note("check", (3 if step else 0, state))), \
                patch.object(release, "pending_plan", lambda s: step), \
                patch.object(acp_ops, "harness_gate", note("harness", "approved")), \
                patch.object(acp_ops, "bearer", note("bearer", "t")), \
                patch.object(release, "migrate", note("migrate")), \
                patch.object(release.ff_merge, "merge", note("merge")), \
                patch.object(release, "vercel_build", note("vercel", {"url": "dpl-new.vercel.app"})), \
                patch.object(release, "vercel_alias", note("alias")), \
                patch.object(release, "railway_deploy", note("railway", {"id": "new"})), \
                patch.object(release, "verify", note("verify")), patch("sys.stdout", io.StringIO()):
            release.release(args, ROOT)
        return calls

    def test_migrates_before_merging_and_deploys_railway_after_vercel(self):
        step = {"from": "0003", "to": "0004", "versions": ["0004"]}
        self.assertEqual(self.run_release(step=step),
                         ["plan", "check", "harness", "bearer", "migrate", "merge", "vercel", "alias", "railway",
                          "verify"])

    def test_a_current_database_skips_the_migration(self):
        self.assertNotIn("migrate", self.run_release())

    def test_skip_railway_releases_to_vercel_only(self):
        self.assertNotIn("railway", self.run_release(skip_railway=True))

    def test_dry_run_changes_nothing(self):
        step = {"from": "0003", "to": "0004", "versions": ["0004"]}
        self.assertEqual(self.run_release(dry_run=True, step=step), ["plan", "check"])


class VerifyTests(unittest.TestCase):
    def test_reports_every_unhealthy_route(self):
        answers = {"https://a/health": (200, {"status": "ok"}), "https://a/ready": (503, {"status": "not_ready"})}
        with patch.object(acp_ops, "get_json", side_effect=lambda url: answers[url]):
            with self.assertRaisesRegex(Stop, "https://a/ready answered 503 not_ready"):
                release.verify(["https://a"])


if __name__ == "__main__":
    unittest.main()
