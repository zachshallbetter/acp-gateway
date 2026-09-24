"""Tests for scripts/register-policy.py: what it writes is what the gateway loads.

Runs against --local files only. Nothing here touches Railway or the network.
"""
import json, os, subprocess, sys, tempfile
from pathlib import Path

root = Path(__file__).parent
SCRIPT = root / "scripts" / "register-policy.py"
KEY = "policy-signing-key-that-is-long-enough"


def run(path, *args, key=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ACP_")}
    if key:
        env["ACP_POLICY_SIGNING_KEY"] = key
    return subprocess.run([sys.executable, str(SCRIPT), "--local", str(path), *args],
                          capture_output=True, text=True, env=env)


def written(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_nothing_is_written_without_apply():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "policy.json"
        out = run(path, "--owner", "acme", "--name", "widget")
        assert out.returncode == 0, out.stderr
        assert not path.exists()
        assert json.loads(out.stdout)["policy_id"] == "acme-widget"


def test_a_repository_is_replaced_at_the_next_version_and_keeps_its_board():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "policy.json"
        assert run(path, "--owner", "acme", "--name", "widget", "--board", "acme:4", "--apply").returncode == 0
        assert run(path, "--owner", "acme", "--name", "other", "--apply").returncode == 0
        assert run(path, "--owner", "Acme", "--name", "Widget", "--apply").returncode == 0
        policies = {p["policy_id"]: p for p in written(path)}
        assert sorted(policies) == ["acme-other", "acme-widget"], policies
        assert policies["acme-widget"]["version"] == 2
        assert policies["acme-widget"]["boards"] == [{"owner": "acme", "number": 4}], \
            "a re-registration that does not restate the board must not drop it"


def test_with_a_signing_key_the_policy_is_signed_and_loads():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "policy.json"
        out = run(path, "--owner", "acme", "--name", "widget", "--apply", key=KEY)
        assert out.returncode == 0, out.stderr
        assert json.loads(out.stdout)["signed"] is True
        assert KEY not in out.stdout + out.stderr, "the key is never printed"
        sys.path.insert(0, str(root))
        os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
        import gateway
        from unittest.mock import patch
        with patch.dict(os.environ, {"ACP_POLICY": path.read_text(), "ACP_POLICY_SIGNING_KEY": KEY}):
            gateway._REGISTRY.update(key=None, value=None)
            registry = gateway.policy_registry(strict=True)
        assert registry["policies"]["acme-widget"]["state"] == "ACTIVE"


def test_introducing_a_key_needs_every_policy_resigned():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "policy.json"
        assert run(path, "--owner", "acme", "--name", "other", "--apply").returncode == 0
        before = path.read_text()
        refused = run(path, "--owner", "acme", "--name", "widget", "--apply", key=KEY)
        assert refused.returncode != 0 and "unsigned" in refused.stderr, refused.stderr
        assert path.read_text() == before, "a refused run writes nothing"
        assert run(path, "--owner", "acme", "--name", "widget", "--sign-all", "--apply", key=KEY).returncode == 0
        assert all("signature" in p for p in written(path))


def test_a_corrupt_registry_is_never_merged_into():
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "policy.json"
        path.write_text("{not json")
        out = run(path, "--owner", "acme", "--name", "widget", "--apply")
        assert out.returncode != 0 and "refusing" in out.stderr, out.stderr
        assert path.read_text() == "{not json"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} register-policy tests passed")
