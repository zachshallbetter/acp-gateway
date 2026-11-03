"""scripts/policy-admin.py with the Keychain, Vercel and the gateway replaced by fakes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
os.environ.setdefault("ACP_GATEWAY_TOKEN", "policy-admin-test")
spec = importlib.util.spec_from_file_location("policy_admin", ROOT / "scripts/policy-admin.py")
admin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admin)
rp = admin.load_register_policy()

KEY = "test-signing-key"


def signed(policy):
    return rp.sign(policy, KEY, admin.KEY_ID)


class FakeVercel:
    def __init__(self, document):
        self.document, self.patched = document, None

    def __call__(self, path, method="GET", body=None):
        if path.endswith("/env") and method == "GET":
            return {"envs": [{"key": "ACP_POLICY", "id": "env1", "target": ["production"]}]}
        if path.endswith("/env/env1") and method == "GET":
            return {"value": json.dumps(self.document)}
        if path.endswith("/env/env1") and method == "PATCH":
            self.patched = json.loads(body["value"])
            return {}
        raise AssertionError(f"unexpected Vercel call {method} {path}")


def existing():
    return [signed({"policy_id": "o-a", "version": 1, "status": "active",
                    "repository": {"owner": "o", "name": "a", "canonical_remote": "https://github.com/o/a.git"},
                    "protected_actions": ["git.remote.update"]})]


class RegisterTests(unittest.TestCase):
    def run_register(self, document, *repositories, apply=False, key=KEY):
        fake = FakeVercel(document)
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(admin, "keychain", return_value=key), \
                patch.object(admin, "vercel_api", fake), \
                patch.object(admin, "POLICY_FILE", Path(tmp) / "production.json"), redirect_stdout(out):
            args = argparse.Namespace(repositories=list(repositories), board=[], apply=apply)
            try:
                code = admin.cmd_register(args)
            except SystemExit as exc:
                return str(exc), fake, None
            target = Path(tmp) / "production.json"
            written = target.read_text() if target.exists() else None
        return code, fake, written, out.getvalue()

    def test_dry_run_signs_and_validates_without_writing(self):
        code, fake, written, out = self.run_register(existing(), "SnackStudio/erosion-lab")
        self.assertEqual(code, 0)
        self.assertIsNone(fake.patched)
        self.assertIn("add snackstudio-erosion-lab v1", out)
        self.assertIn("accepts all 2 policies", out)

    def test_apply_writes_vercel_and_the_repository_copy_identically(self):
        code, fake, written, _ = self.run_register(existing(), "SnackStudio/erosion-lab", "o/b", apply=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(written), fake.patched)
        self.assertEqual(written, json.dumps(fake.patched, separators=(",", ":"), sort_keys=True) + "\n")
        states = rp.validate(fake.patched, KEY, admin.KEY_ID)
        self.assertEqual({r["state"] for r in states.values()}, {"ACTIVE"})
        self.assertEqual(sorted(states), ["o-a", "o-b", "snackstudio-erosion-lab"])
        self.assertNotIn("artifact_manifest", fake.patched[-1])

    def test_registering_an_unchanged_repository_again_changes_nothing(self):
        code, fake, written, _ = self.run_register(existing(), "o/b", apply=True)
        again, fake2, _, out = self.run_register(fake.patched, "o/b", apply=True)
        self.assertEqual(again, 0)
        self.assertIsNone(fake2.patched)
        self.assertIn("unchanged o-b v1", out)
        self.assertIn("nothing to change", out)

    def test_a_signing_key_that_does_not_verify_production_changes_nothing(self):
        message, fake, _ = self.run_register(existing(), "o/b", apply=True, key="some-other-key")
        self.assertIn("does not verify production's policies", message)
        self.assertNotIn("some-other-key", message)
        self.assertIsNone(fake.patched)


class GrantTests(unittest.TestCase):
    def test_grants_only_pinned_paths_that_change_from_what_acp_expects(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "AGENTS.md").write_text("same\n")
            (repo / "scripts").mkdir()
            (repo / "scripts/acp.py").write_text("new client\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "-c", "commit.gpgSign=false", "commit", "-q", "-m", "x"], check=True)
            digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
            policy = signed({"policy_id": "o-a", "version": 1, "status": "active",
                             "repository": {"owner": "o", "name": "a"},
                             "artifact_manifest": {"artifact_manifest_version": 1, "artifacts": [
                                 {"id": "agents.md", "path": "AGENTS.md", "kind": "control_instruction",
                                  "change_policy": "authorize_and_report", "required": True,
                                  "expected_sha256": digest("same\n")},
                                 {"id": "scripts-acp.py", "path": "scripts/acp.py", "kind": "client_control",
                                  "change_policy": "authorize_and_report", "required": True,
                                  "expected_sha256": digest("pinned client\n")}]}})
            calls = []

            def gateway(path, bearer, admin_token=None, body=None):
                calls.append((path, body))
                if path.startswith("/internal/security/integrity"):
                    return {"baseline_overrides": {"scripts/acp.py": {"sha256": digest("advanced client\n")}}}
                return {"artifact_change": {"authorization_id": "artifact_1"}}

            releases = Path(tmp) / "releases.json"
            releases.write_text(json.dumps({"releases": {"9.9.9": {"AGENTS.md": digest("same\n")}}}))
            out = io.StringIO()
            with patch.dict(os.environ, {"ACP_CLIENT_RELEASES_FILE": str(releases)}), \
                    patch.object(admin, "keychain", return_value="secret"), \
                    patch.object(admin, "vercel_api", FakeVercel([policy])), \
                    patch.object(admin, "gateway_call", gateway), redirect_stdout(out):
                args = argparse.Namespace(repository="o/a", checkout=str(repo), ref="HEAD", authorized_by="owner",
                                          reason="upgrade", apply=True)
                self.assertEqual(admin.cmd_grant(args), 0)
            grants = [body for path, body in calls if path == "/internal/recover"]
            self.assertEqual(len(grants), 1)
            self.assertEqual(grants[0]["artifact"], "scripts/acp.py")
            self.assertEqual(grants[0]["expected_old_sha256"], digest("advanced client\n"))
            self.assertEqual(grants[0]["authorized_new_sha256"], digest("new client\n"))
            self.assertNotIn("secret", out.getvalue())


class GrantReleaseTests(unittest.TestCase):
    def test_a_released_client_file_needs_no_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "scripts").mkdir()
            (repo / "scripts/acp.py").write_text("released client\n")
            (repo / "PROJECT_PROFILE.json").write_text("{}\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "-c", "commit.gpgSign=false", "commit", "-q", "-m", "x"], check=True)
            digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
            releases = Path(tmp) / "releases.json"
            releases.write_text(json.dumps({"releases": {"0.6.3": {"scripts/acp.py": digest("released client\n")}}}))
            pin = lambda path, text, kind: {"id": path, "path": path, "kind": kind, "required": True,
                                            "change_policy": "authorize_and_report", "expected_sha256": digest(text)}
            policy = signed({"policy_id": "o-a", "version": 1, "status": "active",
                             "repository": {"owner": "o", "name": "a"},
                             "artifact_manifest": {"artifact_manifest_version": 1, "artifacts": [
                                 pin("scripts/acp.py", "old client\n", "client_control"),
                                 pin("PROJECT_PROFILE.json", "old profile\n", "bootstrap")]}})
            calls = []

            def gateway(path, bearer, admin_token=None, body=None):
                calls.append((path, body))
                return {"baseline_overrides": {}} if body is None else {"artifact_change": {"authorization_id": "a1"}}

            out = io.StringIO()
            with patch.dict(os.environ, {"ACP_CLIENT_RELEASES_FILE": str(releases)}), \
                    patch.object(admin, "keychain", return_value="secret"), \
                    patch.object(admin, "vercel_api", FakeVercel([policy])), \
                    patch.object(admin, "gateway_call", gateway), redirect_stdout(out):
                args = argparse.Namespace(repository="o/a", checkout=str(repo), ref="HEAD", authorized_by="owner",
                                          reason="upgrade", apply=True)
                self.assertEqual(admin.cmd_grant(args), 0)
            grants = [body["artifact"] for path, body in calls if path == "/internal/recover"]
            self.assertEqual(grants, ["PROJECT_PROFILE.json"])
            self.assertIn("scripts/acp.py: bootstrap 0.6.3 client file, accepted without a grant", out.getvalue())


class RepinUnregisterTests(unittest.TestCase):
    def pinned(self):
        digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
        return signed({"policy_id": "o-a", "version": 3, "status": "active", "repository": {"owner": "o", "name": "a"},
                       "artifact_manifest": {"artifact_manifest_version": 1, "artifacts": [
                           {"id": "scripts-acp.py", "path": "scripts/acp.py", "kind": "client_control",
                            "required": True, "change_policy": "authorize_and_report",
                            "expected_sha256": digest("old client\n")},
                           {"id": "agents.md", "path": "AGENTS.md", "kind": "control_instruction",
                            "required": True, "change_policy": "authorize_and_report",
                            "expected_sha256": digest("rules\n")}],
                           "patterns": [{"id": "deviations", "pattern": "records/deviations.jsonl",
                                         "kind": "control_tree", "change_policy": "report_only"}]}})

    def test_repin_moves_pinned_paths_to_the_contained_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            (repo / ".agents/acp/lib").mkdir(parents=True)
            (repo / ".agents/acp/lib/acp.py").write_text("new client\n")
            (repo / "AGENTS.md").write_text("rules\n")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            # -f: a global excludesFile commonly ignores .agents/
            subprocess.run(["git", "-C", str(repo), "add", "-f", "-A", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "-c", "commit.gpgSign=false", "commit", "-q", "-m", "x"], check=True)
            fake = FakeVercel([self.pinned()])
            out = io.StringIO()
            with patch.object(admin, "keychain", return_value=KEY), patch.object(admin, "vercel_api", fake), \
                    patch.object(admin, "POLICY_FILE", Path(tmp) / "production.json"), redirect_stdout(out):
                code = admin.cmd_repin(argparse.Namespace(repository="o/a", checkout=str(repo), ref="HEAD", apply=True))
            self.assertEqual(code, 0, out.getvalue())
            policy = fake.patched[0]
            self.assertEqual(policy["version"], 4)
            paths = {item["path"]: item["expected_sha256"] for item in policy["artifact_manifest"]["artifacts"]}
            self.assertEqual(paths[".agents/acp/lib/acp.py"], hashlib.sha256(b"new client\n").hexdigest())
            self.assertIn("AGENTS.md", paths)
            self.assertEqual(policy["artifact_manifest"]["patterns"][0]["pattern"], ".agents/records/deviations.jsonl")
            states = rp.validate(fake.patched, KEY, admin.KEY_ID)
            self.assertEqual({r["state"] for r in states.values()}, {"ACTIVE"})

    def test_unregister_removes_only_that_policy(self):
        fake = FakeVercel([self.pinned(), *existing()[:0], signed({"policy_id": "o-b", "version": 1, "status": "active",
                                                                    "repository": {"owner": "o", "name": "b"}})])
        with tempfile.TemporaryDirectory() as tmp, patch.object(admin, "keychain", return_value=KEY), \
                patch.object(admin, "vercel_api", fake), patch.object(admin, "POLICY_FILE", Path(tmp) / "p.json"), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(admin.cmd_unregister(argparse.Namespace(repository="o/a", apply=True)), 0)
        self.assertEqual([p["policy_id"] for p in fake.patched], ["o-b"])


if __name__ == "__main__":
    unittest.main()
