"""Tests for owner-agnostic reads and for errors a caller can act on.

The gateway used to be pinned to one installation, so a board owned by any
other account -- notably a personal user account -- was a 502 with no way to
tell why. These cover the two halves of the fix: installations are discovered
per owner, and every refusal names what the caller must supply or change.
"""
import json, os, sys
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402


def resp(body):
    r = type("R", (), {"__enter__": lambda self: self, "__exit__": lambda *a: None})()
    r.__dict__["read"] = lambda: json.dumps(body).encode()
    return r


def install(login, ident, account_type="Organization", projects="read"):
    return {"id": ident, "account": {"login": login, "type": account_type},
            "permissions": ({"organization_projects": projects} if projects else {})}


def test_repository_projects_does_not_count_as_projectsv2_access():
    # The real user installation held issues/metadata/repository_hooks and
    # repository_projects:write, and could still see zero ProjectsV2 boards.
    # Counting Projects (classic) as access reported it as capable.
    entry = gateway.installation_entry(
        {"id": 152843663, "account": {"login": "zachshallbetter", "type": "User"},
         "permissions": {"issues": "read", "metadata": "read", "repository_hooks": "read",
                         "repository_projects": "write"}})
    assert entry["projects_read"] is False, entry["permissions"]
    assert gateway.installation_entry(
        {"id": 1, "account": {"login": "o", "type": "Organization"},
         "permissions": {"organization_projects": "read"}})["projects_read"] is True


def test_a_user_installation_is_told_the_permission_does_not_exist():
    fresh()
    miss = {"data": {"organization": None, "user": None}}
    with patch.dict(os.environ, {**APP_ENV, "ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(miss), resp(miss), resp([
             {"id": 5, "account": {"login": "zachshallbetter", "type": "User"},
              "permissions": {"repository_projects": "write"}}])]):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        try:
            gateway.project_context("zachshallbetter", "38")
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("must raise")
    assert body["error"] == "PROJECTS_PERMISSION_MISSING" and body["account_type"] == "User"
    # Checked against GitHub's own App and PAT settings pages: Projects exists as
    # an App permission only at repository (classic) and organization level, and
    # a fine-grained PAT has no Projects permission at all. Pointing an operator
    # at an account-level App permission sends them looking for a row that is
    # not there -- name the credential that does work instead.
    assert "No GitHub App can read a user's ProjectsV2 boards" in body["remedy"], body["remedy"]
    assert "ACP_GITHUB_TOKEN_ZACHSHALLBETTER" in body["remedy"]
    assert "read:project" in body["remedy"]


def fresh():
    """Discovery is cached process-wide; each test starts from cold."""
    gateway._INSTALLATIONS.update(value=None, fetched_at=0.0)
    gateway._APP["value"] = None


APP_ENV = {"ACP_GITHUB_APP_ID": "4555426", "ACP_GITHUB_PRIVATE_KEY": "test-key"}


# ---- 1. any account the App is installed on, discovered not deployed -------
def test_owner_resolves_to_its_own_installation():
    fresh()
    listing = [install("Example-Org", 900001), install("zachshallbetter", 999001, "User")]
    with patch.dict(os.environ, APP_ENV, clear=False), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.urlopen", side_effect=[resp(listing)]):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        assert gateway.installation_for("zachshallbetter") == "999001"
        # cached: the org lookup costs no second call
        assert gateway.installation_for("Example-Org") == "900001"


def test_owner_match_is_case_insensitive():
    fresh()
    with patch.dict(os.environ, APP_ENV, clear=False), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.urlopen", side_effect=[resp([install("ZachShallbetter", 999001, "User")])]):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        assert gateway.installation_for("zachshallbetter") == "999001"


def test_pinned_installation_skips_discovery_entirely():
    fresh()
    with patch.dict(os.environ, {**APP_ENV, "ACP_GITHUB_INSTALLATIONS": "zachshallbetter:42,Example-Org:7"}), \
         patch("gateway.urlopen", side_effect=AssertionError("must not call GitHub")):
        assert gateway.installation_for("ZachShallbetter") == "42"


def test_uninstalled_owner_is_told_how_to_fix_it():
    fresh()
    with patch.dict(os.environ, APP_ENV, clear=False), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.urlopen", side_effect=[resp([install("Example-Org", 900001)]),
                                               resp({"slug": "acp-gateway-app"})]):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        try:
            gateway.installation_for("someone-else")
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("an uninstalled owner must raise")
    assert body["error"] == "OWNER_NOT_INSTALLED" and status == 404
    assert body["owners_available"] == ["Example-Org"], body
    assert "github.com/apps/acp-gateway-app" in body["remedy"], body["remedy"]


def test_discovery_failure_falls_back_to_the_single_installation():
    fresh()
    with patch.dict(os.environ, {**APP_ENV, "ACP_GITHUB_INSTALLATION_ID": "900001"}), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.urlopen", side_effect=OSError("network down")):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        assert gateway.installation_for("Example-Org") == "900001"


# ---- 2. the allowlist can be scoped per owner -----------------------------
def test_allowlist_admits_every_board_of_one_owner():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "zachshallbetter:*,Example-Org:2-9,11"}):
        assert gateway.project_allowed(38, "zachshallbetter")
        assert gateway.project_allowed(9, "Example-Org") and gateway.project_allowed(11, "example-org")
        assert not gateway.project_allowed(38, "Example-Org"), "one owner's rule must not leak to another"
        assert not gateway.project_allowed(10, "Example-Org")


def test_unqualified_entries_still_apply_to_any_owner():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "2-7"}):
        assert gateway.project_allowed(3, "anyone") and gateway.project_allowed(3)
        assert not gateway.project_allowed(38, "anyone")


def test_malformed_allowlist_is_rejected_loudly():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "zachshallbetter:every"}):
        try:
            gateway.allowlist_rules()
        except ValueError:
            return
    raise AssertionError("a typo in the allowlist must fail, not silently allow nothing")


# ---- 3. refusals carry the information the caller was missing -------------
def test_missing_owner_says_which_owners_exist():
    fresh()
    with patch.dict(os.environ, APP_ENV, clear=False), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.urlopen", side_effect=[resp([install("Example-Org", 1), install("zachshallbetter", 2, "User")])]):
        try:
            gateway.project_context("", "38")
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("a call with no owner must raise")
    assert body["error"] == "OWNER_REQUIRED"
    assert body["owners_available"] == ["Example-Org", "zachshallbetter"], body


def test_disallowed_board_names_the_setting_to_change():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "2-9,11"}):
        try:
            gateway.project_context("zachshallbetter", "38")
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("an out-of-allowlist board must raise")
    assert body["error"] == "PROJECT_NOT_ALLOWED" and status == 403
    assert "ACP_PROJECT_ALLOWLIST" in body["remedy"] and "zachshallbetter:38" in body["remedy"]
    assert body["allowlist"] == "2-9,11"


def test_non_numeric_project_points_at_the_listing_endpoint():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}):
        try:
            gateway.project_context("zachshallbetter", "World Runtime")
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("a non-numeric project must raise")
    assert body["error"] == "PROJECT_REQUIRED"
    assert "/internal/projects?owner=zachshallbetter" in body["remedy"]


def test_installed_but_without_projects_permission_says_so():
    fresh()
    miss = {"data": {"organization": None, "user": None}}
    with patch.dict(os.environ, {**APP_ENV, "ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(miss), resp(miss),
                                               resp([install("zachshallbetter", 5, "User", projects=None)])]):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        try:
            gateway.project_context("zachshallbetter", "38")
        except gateway.TargetError as exc:
            status, body = exc.status, exc.payload()
        else:
            raise AssertionError("a board the installation cannot see must raise")
    assert body["error"] == "PROJECTS_PERMISSION_MISSING" and status == 403
    assert body["installation_id"] == 5


# ---- 4. discovery of the boards themselves --------------------------------
def test_project_list_reports_numbers_and_whether_they_are_allowed():
    fresh()
    boards = {"data": {"user": {"projectsV2": {
        "totalCount": 2, "pageInfo": {"hasNextPage": False, "endCursor": None},
        "nodes": [{"number": 38, "title": "Azimuth — World Runtime", "closed": False},
                  {"number": 40, "title": "Scratch", "closed": True}]}}}}
    org_miss = {"data": {"organization": None}, "errors": [{"message": "Could not resolve to an Organization"}]}
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "zachshallbetter:38"}), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(org_miss), resp(boards)]):
        out = gateway.project_list("zachshallbetter")
    assert out["owner_type"] == "user" and out["count"] == 2
    assert [b["number"] for b in out["projects"]] == [38, 40]
    assert [b["allowed"] for b in out["projects"]] == [True, False]


# ---- 5. the field roster a writer needs -----------------------------------
def test_snapshot_asks_for_what_set_field_needs():
    # set-field.sh resolves a single-select by its option id, from the field
    # roster this query returns. Asking only for id/name left every Status write
    # with dataType null and no options -- a read that looks fine and blocks
    # every write built on it.
    assert "dataType" in gateway.PROJECT_QUERY
    assert "ProjectV2SingleSelectField { options { id name } }" in gateway.PROJECT_QUERY
    assert "ProjectV2IterationField" in gateway.PROJECT_QUERY


def test_items_carry_their_field_values():
    # Every consumer of the snapshot -- claim, claims, operate-frontier's Ready
    # selection, the TSV view -- keys off per-item field values. Returning items
    # without fieldValues produced a snapshot that parsed cleanly, counted right,
    # and had an empty `fields` object on every row: no Status, no Agent, nothing
    # to select or claim on.
    assert "fieldValues" in gateway.PROJECT_QUERY
    for kind in ("SingleSelectValue", "TextValue", "NumberValue", "DateValue", "IterationValue"):
        assert f"ProjectV2ItemField{kind}" in gateway.PROJECT_QUERY, kind
    # ...and the item envelope the record builder reads alongside them.
    for field in ("assignees", "labels", "milestone", "closedByPullRequestsReferences",
                  "createdAt", "updatedAt", "DraftIssue"):
        assert field in gateway.PROJECT_QUERY, field


# ---- 6. the personal-token route for user-owned boards --------------------
def test_a_personal_token_serves_an_owner_no_app_can_reach():
    board = {"data": {"user": {"projectV2": {
        "id": "PVT_x", "title": "Azimuth — World Runtime", "number": 38,
        "fields": {"totalCount": 0, "nodes": []},
        "items": {"totalCount": 1, "pageInfo": {"hasNextPage": False},
                  "nodes": [{"id": "I1", "type": "ISSUE", "isArchived": False}]}}}}}
    org_miss = {"data": {"organization": None}}
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*",
                                 "ACP_GITHUB_TOKEN_ZACHSHALLBETTER": "ghp_secret"}), \
         patch("gateway.installation_token", side_effect=AssertionError("must not mint an App token")), \
         patch("gateway.urlopen", side_effect=[resp(org_miss), resp(board)]):
        out = gateway.project_context("zachshallbetter", "38")
    assert out["snapshot_source"] == "personal-token"
    assert out["items_fetched"] == 1
    # the credential itself must never appear in a response
    assert "ghp_secret" not in json.dumps(out)


def test_personal_token_owners_are_listed_by_name_only():
    with patch.dict(os.environ, {"ACP_GITHUB_TOKEN_ZACHSHALLBETTER": "ghp_secret",
                                 "ACP_GITHUB_TOKEN_EXAMPLE_ORG": "ghp_other"}):
        owners = gateway.pat_owners()
    assert owners == ["example-org", "zachshallbetter"], owners
    assert "ghp_secret" not in json.dumps(owners)


def test_env_name_normalises_the_login():
    assert gateway.owner_env_name("zachshallbetter") == "ACP_GITHUB_TOKEN_ZACHSHALLBETTER"
    assert gateway.owner_env_name("Example-Org") == "ACP_GITHUB_TOKEN_EXAMPLE_ORG"


def test_an_uninstalled_owner_hears_about_both_routes():
    fresh()
    with patch.dict(os.environ, APP_ENV, clear=False), \
         patch("gateway.app_jwt", return_value="jwt"), \
         patch("gateway.urlopen", side_effect=[resp([install("Example-Org", 1)]), resp({"slug": "acp"})]):
        os.environ.pop("ACP_GITHUB_INSTALLATIONS", None)
        try:
            gateway.installation_for("someone")
        except gateway.TargetError as exc:
            body = exc.payload()
        else:
            raise AssertionError("must raise")
    assert "install the App" in body["remedy"]
    assert "ACP_GITHUB_TOKEN_SOMEONE" in body["remedy"], body["remedy"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} owner tests passed")
