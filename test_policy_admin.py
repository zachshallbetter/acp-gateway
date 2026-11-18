"""scripts/policy-admin.py with the Keychain, ACP's document store and the gateway replaced by fakes."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
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


class FakeStore:
    """ACP's signed-document store: one document per name at a stored version."""

    def __init__(self, document, version=7, name="policy"):
        self.documents = {name: (version, document)}
        self.patched, self.writes = None, []

    def read(self, name):
        return self.documents.get(name, (0, None))

    def write(self, name, version, document):
        current = self.documents.get(name, (0, None))[0]
        assert version == current, f"signed on v{version}, store holds v{current}"
        self.documents[name] = (version + 1, document)
        self.patched = document
        self.writes.append((name, version))
        return {"name": name, "version": version + 1}

    def patches(self):
        return {"read_document": self.read, "write_signed": self.write}


def existing():
    return [signed({"policy_id": "o-a", "version": 1, "status": "active",
                    "repository": {"owner": "o", "name": "a", "canonical_remote": "https://github.com/o/a.git"},
                    "protected_actions": ["git.remote.update"]})]


class RegisterTests(unittest.TestCase):
    def run_register(self, document, *repositories, apply=False, key=KEY):
        fake = FakeStore(document)
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(admin, "keychain", return_value=key), \
                patch.multiple(admin, **fake.patches()), \
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

    def test_apply_stores_the_document_and_the_repository_copy_identically(self):
        code, fake, written, _ = self.run_register(existing(), "SnackStudio/erosion-lab", "o/b", apply=True)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(written), fake.patched)
        self.assertEqual(written, json.dumps(fake.patched, separators=(",", ":"), sort_keys=True) + "\n")
        states = rp.validate(fake.patched, KEY, admin.KEY_ID)
        self.assertEqual({r["state"] for r in states.values()}, {"ACTIVE"})
        self.assertEqual(sorted(states), ["o-a", "o-b", "snackstudio-erosion-lab"])
        self.assertNotIn("artifact_manifest", fake.patched[-1])

    def test_apply_is_one_store_write_signed_on_the_version_read(self):
        code, fake, written, _ = self.run_register(existing(), "o/b", apply=True)
        self.assertEqual(code, 0)
        self.assertEqual(fake.writes, [("policy", 7)])

    def test_dry_run_stores_nothing(self):
        code, fake, written, _ = self.run_register(existing(), "o/b")
        self.assertEqual((fake.writes, written), ([], None))

    def test_the_document_goes_to_the_gateway_route_with_both_credentials(self):
        calls = []

        def gateway(path, bearer, admin_token=None, body=None):
            calls.append((path, bearer, admin_token, body))
            return {"name": "policy", "version": 4}

        with patch.object(admin, "keychain", side_effect=lambda account: f"<{account}>"), \
                patch.object(admin, "gateway_call", gateway), redirect_stdout(io.StringIO()):
            admin.write_signed("policy", 3, ["doc"])
        self.assertEqual(calls, [("/internal/documents", "<ACP_GATEWAY_TOKEN>", "<ACP_POLICY_ADMIN_TOKEN>",
                                  {"name": "policy", "expected_version": 3, "document": ["doc"]})])

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
                    patch.multiple(admin, **FakeStore([policy]).patches()), \
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
                    patch.multiple(admin, **FakeStore([policy]).patches()), \
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
            fake = FakeStore([self.pinned()])
            out = io.StringIO()
            with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
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
        fake = FakeStore([self.pinned(), signed({"policy_id": "o-b", "version": 1, "status": "active",
                                                 "repository": {"owner": "o", "name": "b"}})])
        with tempfile.TemporaryDirectory() as tmp, patch.object(admin, "keychain", return_value=KEY), \
                patch.multiple(admin, **fake.patches()), patch.object(admin, "POLICY_FILE", Path(tmp) / "p.json"), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(admin.cmd_unregister(argparse.Namespace(repository="o/a", apply=True)), 0)
        self.assertEqual([p["policy_id"] for p in fake.patched], ["o-b"])


class DeploymentDocumentTests(unittest.TestCase):
    def test_budget_policy_is_signed_verified_and_stored_on_the_version_read(self):
        fake = FakeStore(None, version=0, name="budget")
        with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(admin.cmd_budget_policy(argparse.Namespace(limits=None, apply=True)), 0)
        self.assertEqual(fake.writes, [("budget", 0)])
        with patch.dict(os.environ, {"ACP_POLICY_SIGNING_KEY": KEY}):
            text = json.dumps(fake.patched, separators=(",", ":"), sort_keys=True)
            self.assertIsNone(rp.gateway.document_errors("budget", text))

    def test_a_document_that_does_not_verify_is_never_sent(self):
        fake = FakeStore(None, version=0, name="callers")
        with patch.object(rp.gateway, "document_errors", return_value="signature does not verify"), \
                self.assertRaisesRegex(SystemExit, "does not verify"):
            admin.signed_document({"callers_id": "acp-callers", "version": 1, "callers": []}, KEY, "callers", rp)
        self.assertEqual(fake.writes, [])


class EnrollTests(unittest.TestCase):
    def test_enroll_registers_and_meters_with_discovered_vercel_projects_in_one_write(self):
        fake = FakeStore(existing())
        linked = {"o/b": [("team_Two", "prj_b1"), ("team_Two", "prj_b2")]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(admin, "keychain", return_value=KEY), \
                patch.multiple(admin, **fake.patches()), patch.object(admin, "vercel_projects_by_repo", return_value=linked), \
                patch.object(admin, "POLICY_FILE", Path(tmp) / "p.json"), redirect_stdout(io.StringIO()):
            args = argparse.Namespace(repositories=["o/a", "o/b"], vercel=[], vercel_team=None, railway_project=None,
                                      railway_service=[], railway_map=None, production_branch=[], apply=True)
            self.assertEqual(admin.cmd_enroll(args), 0)
        self.assertEqual(fake.writes, [("policy", 7)])
        by_id = {p["policy_id"]: p for p in fake.patched}
        self.assertEqual(by_id["o-a"]["metered"]["providers"], {})
        self.assertEqual(by_id["o-b"]["metered"]["providers"],
                         {"vercel": {"project_ids": ["prj_b1", "prj_b2"], "team_id": "team_Two"}})
        self.assertIn("hosted_build", by_id["o-b"]["protected_actions"])
        states = rp.validate(fake.patched, KEY, admin.KEY_ID)
        self.assertEqual({r["state"] for r in states.values()}, {"ACTIVE"})

    def test_a_railway_map_adds_services_and_keeps_the_vercel_projects_metered(self):
        metered = signed({"policy_id": "o-site", "version": 2, "status": "active",
                          "repository": {"owner": "o", "name": "site"},
                          "protected_actions": ["hosted_build", "manual_ci", "production_merge"],
                          "metered": {"production_branches": ["main"], "providers": {
                              "vercel": {"project_ids": ["prj_cli"], "team_id": "team_One"}}}})
        fake = FakeStore([metered, *existing()])
        with tempfile.TemporaryDirectory() as tmp:
            mapping = Path(tmp) / "railway.json"
            mapping.write_text(json.dumps({"o/site": {"project_id": "11111111-1111-4111-8111-111111111111", "service_ids": ["33333333-3333-4333-8333-333333333333", "22222222-2222-4222-8222-222222222222"]}}))
            with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                    patch.object(admin, "vercel_projects_by_repo", return_value={}), \
                    patch.object(admin, "POLICY_FILE", Path(tmp) / "p.json"), redirect_stdout(io.StringIO()) as out:
                args = argparse.Namespace(repositories=["o/site", "o/a"], vercel=[], vercel_team=None,
                                          railway_project=None, railway_service=[], railway_map=str(mapping),
                                          production_branch=[], apply=True)
                self.assertEqual(admin.cmd_enroll(args), 0)
        site = next(p for p in fake.patched if p["policy_id"] == "o-site")
        self.assertEqual(site["version"], 3)
        self.assertEqual(site["metered"]["providers"], {
            "vercel": {"project_ids": ["prj_cli"], "team_id": "team_One"},
            "railway": {"project_id": "11111111-1111-4111-8111-111111111111", "service_ids": ["22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"]}})

    def test_an_unchanged_repository_is_left_at_its_version(self):
        metered = signed({"policy_id": "o-a", "version": 4, "status": "active", "repository": {"owner": "o", "name": "a"},
                          "protected_actions": ["hosted_build", "manual_ci", "production_merge"],
                          "metered": {"production_branches": ["main"], "providers": {}}})
        fake = FakeStore([metered])
        with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                patch.object(admin, "vercel_projects_by_repo", return_value={}), redirect_stdout(io.StringIO()) as out:
            args = argparse.Namespace(repositories=["o/a"], vercel=[], vercel_team=None, railway_project=None,
                                      railway_service=[], railway_map=None, production_branch=[], apply=False)
            self.assertEqual(admin.cmd_enroll(args), 0)
        self.assertIn("unchanged o-a v4", out.getvalue())

    def test_vercel_output_after_a_hint_line_still_parses(self):
        printed = subprocess.CompletedProcess([], 0, '<claude-code-hint v="1" />\n{"teams": [{"id": "team_A"}]}\n', "")
        with patch.object(admin.subprocess, "run", return_value=printed):
            self.assertEqual(admin.vercel_json("teams", "ls", "--format", "json"), {"teams": [{"id": "team_A"}]})

    def test_explicit_projects_name_one_repository(self):
        args = argparse.Namespace(repositories=["o/a", "o/b"], vercel=["prj_x"], vercel_team=None,
                                  railway_project=None, railway_service=[], railway_map=None, production_branch=[],
                                  apply=False)
        with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **FakeStore(existing()).patches()), \
                redirect_stdout(io.StringIO()), self.assertRaisesRegex(SystemExit, "enroll it on its own"):
            admin.cmd_enroll(args)


class CredentialTests(unittest.TestCase):
    def test_the_environment_comes_before_the_keychain(self):
        with patch.dict(os.environ, {"ACP_POLICY_SIGNING_KEY": "from-env"}), patch.object(subprocess, "run") as ran:
            self.assertEqual(admin.keychain("ACP_POLICY_SIGNING_KEY"), "from-env")
        ran.assert_not_called()

    def test_an_unresolved_latchkey_reference_names_the_fix(self):
        reference = "latchkey://ACP_POLICY_SIGNING_KEY"
        with patch.dict(os.environ, {"ACP_POLICY_SIGNING_KEY": reference}):
            with self.assertRaisesRegex(SystemExit, "latchkey run --env-file"):
                admin.keychain("ACP_POLICY_SIGNING_KEY")


class GatewayHostTests(unittest.TestCase):
    def test_a_self_hosted_deployment_names_its_own_hosts(self):
        env = {**os.environ, "ACP_GATEWAY_HOSTS": "acp.example.com", "ACP_GATEWAY_URL": "https://acp.example.com"}
        env.pop("ACP_RAILWAY_URL", None)
        code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('a',sys.argv[1]);"
                "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);print(m.GATEWAY, m.RAILWAY_URL);"
                "m.checked_gateway('https://acp-gateway.vercel.app')")
        out = subprocess.run([sys.executable, "-c", code, str(ROOT / "scripts/policy-admin.py")], env=env,
                             capture_output=True, text=True)
        self.assertIn("https://acp.example.com None", out.stdout)
        self.assertIn("refusing to send a token", out.stderr, "a host outside ACP_GATEWAY_HOSTS is refused")


class CallerTokenTests(unittest.TestCase):
    def test_the_token_reaches_the_keychain_on_stdin_never_on_argv(self):
        fake = FakeStore(None, version=0, name="callers")
        keychain = {}

        def security(argv, **kwargs):
            if argv == ["security", "-i"]:
                keychain["token"] = kwargs["input"].rsplit("-w ", 1)[1].strip().strip('"')
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0, keychain.get("token", "") + "\n", "")
        args = argparse.Namespace(caller_id="lane-1", kind="lane", repo=["o/a"], apply=True)
        with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                patch.object(subprocess, "run", side_effect=security) as ran, redirect_stdout(io.StringIO()):
            self.assertEqual(admin.cmd_caller(args), 0)
        argv = ran.call_args_list[0].args[0]
        self.assertEqual(argv, ["security", "-i"])
        for call in ran.call_args_list:
            self.assertNotIn(keychain["token"], " ".join(call.args[0]))
        sent = ran.call_args_list[0].kwargs["input"]
        self.assertTrue(sent.startswith("add-generic-password -U -s "))
        token = sent.rsplit("-w ", 1)[1].strip().strip('"')
        self.assertGreaterEqual(len(token), 32)
        self.assertNotIn(token, " ".join(argv))
        self.assertEqual(len(fake.writes), 1)

    def test_a_token_file_replaces_the_keychain_and_is_owner_only(self):
        fake = FakeStore(None, version=0, name="callers")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "lane-1.token")
            args = argparse.Namespace(caller_id="lane-1", kind="lane", repo=["o/a"], apply=True, token_file=path)
            with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                    patch.object(subprocess, "run") as ran, redirect_stdout(io.StringIO()):
                self.assertEqual(admin.cmd_caller(args), 0)
            ran.assert_not_called()                                    # no macOS Keychain involved
            token = open(path).read().strip()
            self.assertGreaterEqual(len(token), 32)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            stored = fake.documents["callers"][1]["callers"][0]
            self.assertEqual(stored["token_sha256"], hashlib.sha256(token.encode()).hexdigest())

    def test_a_token_file_never_overwrites_an_existing_file(self):
        fake = FakeStore(None, version=0, name="callers")
        with tempfile.NamedTemporaryFile() as existing_file:
            args = argparse.Namespace(caller_id="lane-1", kind="lane", repo=["o/a"], apply=True,
                                      token_file=existing_file.name)
            with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                    redirect_stdout(io.StringIO()), self.assertRaisesRegex(SystemExit, "already exists"):
                admin.cmd_caller(args)
        self.assertEqual(fake.writes, [])

    def test_a_keychain_failure_stores_nothing_in_acp(self):
        fake = FakeStore(None, version=0, name="callers")
        failed = subprocess.CompletedProcess([], 1, "", "boom")
        args = argparse.Namespace(caller_id="lane-1", kind="lane", repo=["o/a"], apply=True)
        with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                patch.object(subprocess, "run", return_value=failed), redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(SystemExit, "Keychain"):
            admin.cmd_caller(args)
        self.assertEqual(fake.writes, [])

    def test_a_silent_keychain_failure_is_caught_by_reading_the_item_back(self):
        fake = FakeStore(None, version=0, name="callers")
        silent = subprocess.CompletedProcess([], 0, "", "")             # exit 0, nothing stored
        args = argparse.Namespace(caller_id="lane-1", kind="lane", repo=["o/a"], apply=True)
        with patch.object(admin, "keychain", return_value=KEY), patch.multiple(admin, **fake.patches()), \
                patch.object(subprocess, "run", return_value=silent), redirect_stdout(io.StringIO()), \
                self.assertRaisesRegex(SystemExit, "Keychain"):
            admin.cmd_caller(args)
        self.assertEqual(fake.writes, [])


if __name__ == "__main__":
    unittest.main()
