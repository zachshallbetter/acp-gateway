"""The GitHub App definition: manifest, gateway and icon agree, and stay read-only.

github-app/manifest.json is what the App should be; gateway.APP_PERMISSIONS is what
the gateway checks each installation against. If they drift apart, the drift report
on /internal/installations stops meaning anything -- so they are held equal here.
"""
import json, os, struct, sys
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402

APP = root / "github-app"
MANIFEST = json.loads((APP / "manifest.json").read_text(encoding="utf-8"))


def test_the_manifest_and_the_gateway_define_the_same_permissions():
    assert MANIFEST["default_permissions"] == gateway.APP_PERMISSIONS, (
        "github-app/manifest.json and gateway.APP_PERMISSIONS must list the same grant")


def test_the_app_is_read_only_and_listens_to_nothing():
    assert set(MANIFEST["default_permissions"].values()) == {"read"}, "the gateway never writes to GitHub"
    assert MANIFEST["default_events"] == [], "the gateway has no webhook endpoint"
    assert MANIFEST["hook_attributes"]["active"] is False
    assert MANIFEST["public"] is False, "only its owner installs it"


def test_the_manifest_names_the_app_and_says_what_it_does():
    assert MANIFEST["name"] == "ACP Agent Control Plane"
    assert len(MANIFEST["name"]) <= 34, "GitHub App names are limited to 34 characters"
    assert "read" in MANIFEST["description"].lower() and len(MANIFEST["description"]) < 1000


def test_every_permission_is_documented_with_its_reason():
    doc = (root / "docs/GITHUB_APP.md").read_text(encoding="utf-8")
    for name in gateway.APP_PERMISSIONS:
        assert f"`{name}`" in doc, f"docs/GITHUB_APP.md does not explain {name}"


def test_the_icon_meets_githubs_logo_rules():
    png = (APP / "logo.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", png[16:24])
    assert width == height and width >= 200, (width, height)
    assert len(png) < 1_000_000, "GitHub rejects logos over 1 MB"
    svg = ET.parse(APP / "logo.svg").getroot()
    assert svg.find("{http://www.w3.org/2000/svg}title").text == MANIFEST["name"]


def test_drift_names_what_is_missing_and_what_is_excess():
    live = {"issues": "read", "metadata": "read", "organization_projects": "read",
            "repository_hooks": "read", "repository_projects": "write"}
    drift = gateway.permission_drift(live, "Organization")
    assert drift == {"permissions_missing": ["contents", "pull_requests"],
                     "permissions_excess": ["repository_hooks", "repository_projects"]}, drift
    assert gateway.permission_drift(dict(gateway.APP_PERMISSIONS), "Organization") == \
        {"permissions_missing": [], "permissions_excess": []}


def test_a_user_installation_is_not_missing_organization_permissions():
    grant = {k: v for k, v in gateway.APP_PERMISSIONS.items() if not k.startswith("organization_")}
    assert gateway.permission_drift(grant, "User") == {"permissions_missing": [], "permissions_excess": []}


def test_a_broader_grant_than_read_is_excess_even_when_read_is_needed():
    grant = dict(gateway.APP_PERMISSIONS, contents="write")
    drift = gateway.permission_drift(grant, "Organization")
    assert drift["permissions_missing"] == [] and drift["permissions_excess"] == ["contents"], drift


def test_each_installation_reports_its_drift():
    entry = gateway.installation_entry({"id": 1, "account": {"login": "acme", "type": "Organization"},
                                        "permissions": {"metadata": "read"}})
    assert entry["permissions_missing"] == ["contents", "issues", "organization_projects", "pull_requests"]
    assert entry["permissions_excess"] == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} github-app tests passed")
