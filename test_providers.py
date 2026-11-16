"""Provider evidence and the posture report, against recorded response fixtures.

Each fixture has the documented shape of the provider's response (Vercel REST v9/v7,
Railway GraphQL v2, GitHub REST). A fake fetch serves them; nothing touches the network.
"""
import base64, json, os, sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import posture  # noqa: E402
import providers  # noqa: E402

SHA = "c" * 40
NOW = 1_800_000_000.0                       # 2027-01-15T08:00:00Z
DAY = "2027-01-15"
CLAIM = {"owner": "Example-Org", "name": "Widget"}

VERCEL_PROJECT = {
    "id": "prj_widget", "name": "widget", "framework": None, "rootDirectory": None,
    "commandForIgnoringBuildStep": None,
    "link": {"type": "github", "org": "Example-Org", "repo": "Widget", "repoId": 123, "productionBranch": "main"},
    "gitProviderOptions": {"createDeployments": "enabled"},
    "resourceConfig": {"buildMachineType": "standard", "buildMachineSelection": "elastic",
                       "elasticConcurrencyEnabled": True},
}
VERCEL_DEPLOYMENTS = {"deployments": [
    {"uid": "dpl_1", "created": int(NOW * 1000) - 1000, "target": "production", "source": "git"},
    {"uid": "dpl_2", "created": int(NOW * 1000) - 2000, "target": None, "source": "git"},
    {"uid": "dpl_3", "created": int((NOW - 86400) * 1000), "target": None, "source": "cli"},
], "pagination": {"count": 3, "next": None, "prev": None}}

VERCEL_DEPLOYMENT_DETAIL = {"uid": "dpl_1", "resourceConfig": {"buildMachine": {
    "cores": 4, "memory": 8192, "purchaseType": "standard", "machineSelectionType": "elastic",
    "selectionSource": "elastic-algorithm", "defaultPurchaseType": "standard"}}}

RAILWAY_PROJECT = {"data": {"project": {
    "id": "a3dbbfc5-3fe7-4365-a754-9a7856766f05", "name": "agent-control-plane",
    "workspaceId": "75016e16-34ac-462d-b2e3-22312c398829",
    "services": {"edges": [{"node": {"id": "b2f28e52-a113-41c5-b29f-6dcb6a54d3aa", "name": "acp-gateway",
                                     "serviceInstances": {"edges": [{"node": {
                                         "environmentId": "dac18c6b-a1ce-485b-b3a4-a8949dc5ad6e",
                                         "source": {"repo": None, "image": None}}}]}}}]},
    "deploymentTriggers": {"edges": [{"node": {"id": "t1", "branch": "main", "repository": "Example-Org/Widget",
                                               "provider": "github",
                                               "serviceId": "b2f28e52-a113-41c5-b29f-6dcb6a54d3aa",
                                               "environmentId": "dac18c6b-a1ce-485b-b3a4-a8949dc5ad6e"}}]},
    "deployments": {"edges": [{"node": {"id": "d1", "status": "CRASHED", "createdAt": "2027-01-15T07:00:00.000Z",
                                        "serviceId": "b2f28e52-a113-41c5-b29f-6dcb6a54d3aa"}}]},
}}}
RAILWAY_LIMIT = {"data": {"workspace": {"id": "w", "customer": {"usageLimit": {
    "hardLimit": None, "softLimit": 20, "isOverLimit": False}}}}}

CI_UNBOUNDED = """
name: ci
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps: [{run: make test}]
"""
CI_BOUNDED = """
name: ci
on:
  pull_request:
  push:
    branches: [main]
    paths-ignore: ['docs/**']
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy: {matrix: {py: ['3.12', '3.13']}}
    steps: [{run: make test}]
  release:
    uses: ./.github/workflows/release.yml
"""


def content(text):
    return {"type": "file", "encoding": "base64", "content": base64.b64encode(text.encode()).decode()}


class Fake:
    """Serves fixtures by URL; records what was asked; refuses anything unexpected."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, provider, url, token, body=None):
        assert token, "a provider call was made without a credential"
        self.calls.append((provider, url, body["query"].split("(")[0].split()[-1] if body else None))
        for needle, response in self.routes.items():
            if needle in url or (body and needle in body["query"]):
                if isinstance(response, Exception):
                    raise response
                return response
        raise providers.ProviderError(provider, "UNAVAILABLE", "HTTP 404")


def creds():
    return patch.dict(os.environ, {"ACP_VERCEL_TOKEN": "v-token", "ACP_RAILWAY_TOKEN": "r-token"})


def fresh():
    providers._CACHE.clear()


def github_routes(workflow=CI_BOUNDED, vercel_json=None):
    routes = {"/contents/.github/workflows?ref=": [{"type": "file", "path": ".github/workflows/ci.yml"},
                                                   {"type": "file", "path": ".github/workflows/README.md"}],
              "/contents/.github/workflows/ci.yml?ref=": content(workflow)}
    if vercel_json is not None:
        routes["/contents/vercel.json?ref="] = content(json.dumps(vercel_json))
    return routes


POLICY = {"repository": {"owner": "Example-Org", "name": "Widget"},
          "metered": {"production_branches": ["main"],
                      "providers": {"vercel": {"project_ids": ["prj_widget"]},
                                    "railway": {"project_id": "a3dbbfc5-3fe7-4365-a754-9a7856766f05",
                                                "service_ids": ["b2f28e52-a113-41c5-b29f-6dcb6a54d3aa"]}}}}


# ---- transport -------------------------------------------------------------
def test_hosts_are_allowlisted_and_credentials_required():
    for url in ("https://evil.example/x", "http://api.vercel.com/x"):
        try:
            providers._fetch("vercel", url, "t")
        except providers.ProviderError as exc:
            assert exc.kind == "UNAVAILABLE" and "allowlisted" in exc.detail
        else:
            raise AssertionError(url)
    try:
        providers._fetch("vercel", "https://api.vercel.com/v9/projects/x", "")
    except providers.ProviderError as exc:
        assert "credential" in exc.detail
    else:
        raise AssertionError("no token should not call")


def test_railway_queries_are_allowlisted():
    try:
        providers._railway("query { me { email } }", {}, Fake({}))
    except providers.ProviderError as exc:
        assert "allowlisted" in exc.detail
    else:
        raise AssertionError("a free-form query must not be sent")


# ---- Vercel ------------------------------------------------------------------
def test_vercel_project_is_normalised():
    with creds():
        fresh()
        project = providers.vercel_project("prj_widget", NOW, Fake({"/v9/projects/prj_widget": VERCEL_PROJECT}))
        assert project["repository"] == {"owner": "Example-Org", "name": "Widget", "production_branch": "main"}
        assert project["build_machine_selection"] == "elastic" and project["elastic_concurrency"] is True


def test_each_policy_reads_vercel_in_its_own_team():
    with creds(), patch.dict(os.environ, {"ACP_VERCEL_TEAM_ID": "team_default"}):
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": VERCEL_PROJECT, "/v7/deployments": VERCEL_DEPLOYMENTS})
        policy = {"repository": POLICY["repository"],
                  "metered": {"providers": {"vercel": {"project_ids": ["prj_widget"], "team_id": "team_other"}}}}
        providers.build_evidence("hosted_build", policy, CLAIM,
                                 {"trigger": "push", "ref": "refs/heads/feature", "new_sha": SHA}, token_for, NOW, fake)
        providers.posture_snapshot(policy, token_for, NOW, fake)
        vercel_urls = [url for provider, url, _ in fake.calls if provider == "vercel"]
        assert vercel_urls and all("teamId=team_other" in url for url in vercel_urls), vercel_urls
        fresh()
        fake = Fake({"/v9/projects/": VERCEL_PROJECT})
        providers.vercel_project("prj_widget", NOW, fake)
        assert "teamId=team_default" in fake.calls[0][1]


def test_vercel_divergence_is_reported_not_guessed():
    with creds():
        for broken in ({**VERCEL_PROJECT, "gitProviderOptions": {"createDeployments": "sometimes"}},
                       {k: v for k, v in VERCEL_PROJECT.items() if k != "id"},
                       {**VERCEL_PROJECT, "resourceConfig": {"buildMachineType": "quantum"}}):
            fresh()
            try:
                providers.vercel_project("prj_widget", NOW, Fake({"/v9/projects/": broken}))
            except providers.ProviderError as exc:
                assert exc.kind == "DIVERGED", exc.detail
            else:
                raise AssertionError(broken)


def test_vercel_would_build_rules():
    with creds():
        fresh()
        project = providers.vercel_project("prj_widget", NOW, Fake({"/v9/projects/": VERCEL_PROJECT}))
    assert providers.vercel_would_build(project, None, CLAIM, "feature", "push")[0] is True
    assert providers.vercel_would_build(project, {"git": {"deploymentEnabled": {"feature*": False}}},
                                        CLAIM, "feature-x", "push")[0] is False
    assert providers.vercel_would_build(project, {"git": {"deploymentEnabled": False}}, CLAIM, "main", "push")[0] is False
    # GitHub Deployment records off does not stop builds
    assert providers.vercel_would_build({**project, "create_deployments": "disabled"}, None, CLAIM, "x", "push")[0] is True
    assert providers.vercel_would_build(project, None, {"owner": "Other", "name": "Repo"}, "x", "push")[0] is False
    assert providers.vercel_would_build({**project, "create_deployments": "disabled"}, None, CLAIM, "x", "cli_deploy")[0]


def test_vercel_deployments_are_counted_per_day():
    with creds():
        counts = providers.vercel_deployments_per_day("prj_widget", now=NOW,
                                                      fetch=Fake({"/v7/deployments": VERCEL_DEPLOYMENTS}))
        assert counts[DAY] == 2 and counts["2027-01-14"] == 1


# ---- Railway -----------------------------------------------------------------
def test_railway_project_triggers_and_limits():
    with creds():
        fresh()
        fake = Fake({"AcpProject": RAILWAY_PROJECT, "AcpLimit": RAILWAY_LIMIT})
        project = providers.railway_project("a3dbbfc5-3fe7-4365-a754-9a7856766f05", NOW, fake)
        assert project["triggers"][0]["branch"] == "main" and project["deployments_per_day"][DAY] == 1
        assert providers.railway_would_build(project, set(), CLAIM, "main", "push")[0] is True
        assert providers.railway_would_build(project, set(), CLAIM, "feature", "push")[0] is False
        assert providers.railway_would_build(project, set(), CLAIM, "feature", "railway_up")[0] is True
        assert providers.railway_usage_limit("w", NOW, fake)["hard_limit"] is None
        assert all("variables" not in (call[2] or "") for call in fake.calls)


def test_railway_unknown_status_diverges():
    broken = json.loads(json.dumps(RAILWAY_PROJECT))
    broken["data"]["project"]["deployments"]["edges"][0]["node"]["status"] = "EXPLODED"
    with creds():
        fresh()
        try:
            providers.railway_project("p", NOW, Fake({"AcpProject": broken}))
        except providers.ProviderError as exc:
            assert exc.kind == "DIVERGED"
        else:
            raise AssertionError("unknown status must diverge")


def test_railway_graphql_errors_are_unavailable():
    with creds():
        fresh()
        try:
            providers.railway_project("p", NOW, Fake({"AcpProject": {"errors": [{"message": "Not Authorized"}]}}))
        except providers.ProviderError as exc:
            assert exc.kind == "UNAVAILABLE"
        else:
            raise AssertionError("GraphQL errors must not pass as evidence")


# ---- GitHub Actions -----------------------------------------------------------
def test_workflow_analysis():
    unbounded = providers.analyse_workflow("ci.yml", CI_UNBOUNDED)
    assert unbounded["jobs_without_timeout"] == ["test"] and not unbounded["has_concurrency"]
    assert providers.workflow_runs_on(unbounded, "push", "anything")[0] is True
    bounded = providers.analyse_workflow("ci.yml", CI_BOUNDED)
    assert bounded["jobs_without_timeout"] == [] and bounded["has_concurrency"] and bounded["matrix_jobs"] == ["test"]
    assert providers.workflow_runs_on(bounded, "push", "feature")[0] is False
    runs, why = providers.workflow_runs_on(bounded, "push", "main")
    assert runs and "path filter" in why
    assert providers.workflow_runs_on(bounded, "workflow_dispatch", "main")[0] is False
    assert providers.analyse_workflow("bad.yml", "on: [push\n")["parse_error"]


def test_branch_patterns_follow_github():
    assert providers._branch_matches(["release/*"], "release/1")
    assert not providers._branch_matches(["release/*"], "release/1/hotfix")
    assert providers._branch_matches(["release/**"], "release/1/hotfix")
    assert not providers._branch_matches(["**", "!main"], "main")


def test_branch_pattern_grammar_and_fail_closed():
    m = providers._branch_matches
    assert m(["feature/[0-9]*"], "feature/1x") and not m(["feature/[0-9]*"], "feature/x1")
    assert m(["feature/[a-c]"], "feature/b") and not m(["feature/[a-c]"], "feature/d")
    assert m(["rel?"], "re") and m(["rel?"], "rel") and not m(["rel?"], "rell") and not m(["rel?"], "rele")
    assert m(["v1+"], "v111") and not m(["v1+"], "v") and not m(["v1+"], "v12")
    assert m(["a\\*b"], "a*b") and not m(["a\\*b"], "axb")
    assert m(["*"], "main") and not m(["*"], "a/b")
    for bad in ("[abc", "[!a]", "?x", "a\\", "[]", "[z-a]"):
        try:
            m([bad], "x")
        except providers._UnsupportedPattern:
            continue
        raise AssertionError(f"{bad!r} must be unsupported")
    doc = lambda key, pat: providers.analyse_workflow("w.yml", f"on:\n  push:\n    {key}: ['{pat}']\njobs: {{}}\n")
    assert providers.workflow_runs_on(doc("branches", "[oops"), "push", "main")[0] is True
    assert providers.workflow_runs_on(doc("branches-ignore", "[oops"), "push", "main")[0] is True
    assert providers.workflow_runs_on(doc("branches", "feature/[0-9]*"), "push", "feature/1x")[0] is True


def test_branch_pattern_matching_is_linear():
    import time as _t
    start = _t.monotonic()
    assert not providers._branch_matches(["a*a*a*a*a*a*a*a*b"], "a" * 500)
    assert not providers._branch_matches(["a+a+a+a+a+a+a+a+b"], "a" * 500)
    assert _t.monotonic() - start < 1.0


def test_workflow_yaml_aliases_are_refused():
    doc = "a0: &a0 [x, y]\n" + "".join(f"a{i}: &a{i} [*a{i-1}, *a{i-1}]\n" for i in range(1, 41))
    bomb = providers.analyse_workflow("w.yml", doc + "on: [*a40]\njobs: {}\n")
    assert bomb["parse_error"]
    assert providers.workflow_runs_on(bomb, "push", "main")[0] is True
    assert providers.analyse_workflow("w.yml", "base: &b {x: 1}\non: push\nj: *b\n")["parse_error"]


def test_workflow_triggers_and_patterns_must_be_scalars():
    assert providers.analyse_workflow("w.yml", "on: [push, [nested]]\njobs: {}\n")["parse_error"]
    nested = providers.analyse_workflow("w.yml", "on:\n  push:\n    branches: [[a]]\njobs: {}\n")
    assert providers.workflow_runs_on(nested, "push", "main")[0] is True


# ---- composition ---------------------------------------------------------------
def token_for(owner):
    return "gh-token"


def test_build_evidence_for_a_feature_push():
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": VERCEL_PROJECT, "AcpProject": RAILWAY_PROJECT})
        seen = providers.build_evidence("hosted_build", POLICY, CLAIM,
                                        {"trigger": "push", "ref": "refs/heads/feature", "new_sha": SHA},
                                        token_for, NOW, fake)
        assert seen["available"]
        by = {b["provider"]: b["would_build"] for b in seen["builds"]}
        assert by == {"vercel": True, "railway": False, "github_actions": False}, seen["builds"]
        assert len(seen["digest"]) == 64


def test_build_evidence_fails_closed_on_any_provider():
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": providers.ProviderError("vercel", "UNAVAILABLE", "HTTP 503")})
        seen = providers.build_evidence("hosted_build", POLICY, CLAIM,
                                        {"trigger": "push", "ref": "refs/heads/feature", "new_sha": SHA},
                                        token_for, NOW, fake)
        assert seen == {"available": False, "kind": "UNAVAILABLE", "provider": "vercel", "detail": "HTTP 503"}


def test_vercel_json_branch_rule_is_read_at_the_commit():
    with creds():
        fresh()
        fake = Fake({**github_routes(vercel_json={"git": {"deploymentEnabled": {"main": True, "**": False}}}),
                     "/v9/projects/": VERCEL_PROJECT, "AcpProject": RAILWAY_PROJECT})
        seen = providers.build_evidence("hosted_build", POLICY, CLAIM,
                                        {"trigger": "push", "ref": "refs/heads/feature", "new_sha": SHA},
                                        token_for, NOW, fake)
        assert [b for b in seen["builds"] if b["provider"] == "vercel"][0]["would_build"] is False


# ---- posture ------------------------------------------------------------------
def test_posture_ranks_findings_and_gives_exact_fixes():
    with creds():
        fresh()
        fake = Fake({**github_routes(CI_UNBOUNDED), "/v9/projects/": VERCEL_PROJECT,
                     "/v7/deployments": VERCEL_DEPLOYMENTS, "/v13/deployments/": VERCEL_DEPLOYMENT_DETAIL,
                     "AcpProject": RAILWAY_PROJECT,
                     "AcpLimit": RAILWAY_LIMIT, "/actions/runs": {"total_count": 4, "workflow_runs": []},
                     "/check-runs": {"total_count": 2, "check_runs": [
                         {"name": "ci", "status": "completed", "conclusion": "success", "app": {"slug": "github-actions"}},
                         {"name": "Vercel", "status": "completed", "conclusion": "success", "app": {"slug": "vercel"}}]},
                     "settings/billing/usage": providers.ProviderError("github_actions", "UNAVAILABLE", "HTTP 403")})
        snapshot = providers.posture_snapshot(POLICY, token_for, NOW, fake)
    assert snapshot["errors"] == [], snapshot["errors"]
    assert snapshot["github_actions"]["check_runs"]["by_app"] == {"github-actions": 1, "vercel": 1}
    found = posture.findings(snapshot, ledger_rows=[], day=DAY)
    codes = [f["code"] for f in found]
    for code in ("VERCEL_DEPLOYS_EVERY_PUSH", "VERCEL_LARGE_OR_ELASTIC_MACHINE", "VERCEL_ELASTIC_CONCURRENCY",
                 "UNRECORDED_BUILDS", "RAILWAY_NO_HARD_LIMIT", "RAILWAY_DEPLOYS_ON_PUSH", "GHA_PUSH_ANY_BRANCH",
                 "GHA_NO_TIMEOUT", "GHA_NO_CONCURRENCY", "GHA_SPEND_UNREADABLE", "VERCEL_SPEND_CAP_UNVERIFIED"):
        assert code in codes, (code, codes)
    assert [f["severity"] for f in found] == sorted((f["severity"] for f in found),
                                                    key=posture.SEVERITY_ORDER.__getitem__)
    assert all(f["fix"] for f in found)
    machine = next(f for f in found if f["code"] == "VERCEL_LARGE_OR_ELASTIC_MACHINE")
    assert machine["who"] == "owner"
    ignore = next(f for f in found if f["code"] == "VERCEL_DEPLOYS_EVERY_PUSH")
    assert providers_ignore_semantics(ignore["fix"])
    page = posture.render_html(posture.report([snapshot], [], DAY, {"budget_policy_id": "acp-budgets", "version": 1}))
    assert "<script" not in page and "ACP build posture" in page


def providers_ignore_semantics(fix):
    # Vercel skips a build when the Ignored Build Step exits 0: production must exit 1 (build).
    return '"$VERCEL_ENV" = "production" ]; then exit 1; else exit 0' in fix


def test_railway_triggers_on_one_branch_are_one_finding():
    snapshot = {"repository": "Example-Org/Widget", "vercel": [], "github_actions": {"spend": {"readable": True}},
                "railway": {"name": "widget", "triggers": [
                    {"repository": "Example-Org/Widget", "branch": "main", "service_id": "a", "environment_id": "e"},
                    {"repository": "Example-Org/Widget", "branch": "main", "service_id": "b", "environment_id": "e"}],
                    "usage_limit": {"hard_limit": 50}}}
    found = [f for f in posture.findings(snapshot, [], DAY) if f["code"] == "RAILWAY_DEPLOYS_ON_PUSH"]
    assert len(found) == 1 and "2 service environments" in found[0]["problem"]


def test_last_build_machine_overrides_a_reassuring_setting():
    fixed = {**VERCEL_PROJECT, "resourceConfig": {"buildMachineType": "basic", "buildMachineSelection": "fixed"}}
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": fixed, "/v7/deployments": VERCEL_DEPLOYMENTS,
                     "/v13/deployments/": VERCEL_DEPLOYMENT_DETAIL})
        snapshot = providers.posture_snapshot({"repository": POLICY["repository"],
                                               "metered": {"providers": {"vercel": {"project_ids": ["prj_widget"]}}}},
                                              token_for, NOW, fake)
    machine = snapshot["vercel"][0]["last_build_machine"]
    assert machine["selection"] == "elastic" and machine["cores"] == 4 and machine["deployment"] == "dpl_1"
    found = [f for f in posture.findings(snapshot, [], DAY) if f["code"] == "VERCEL_LARGE_OR_ELASTIC_MACHINE"]
    assert found and "last build (2027-01-15) ran on 4 cores, elastic" in found[0]["problem"]
    calm = {**VERCEL_DEPLOYMENT_DETAIL, "resourceConfig": {"buildMachine": {
        "cores": 2, "machineSelectionType": "fixed", "purchaseType": "basic", "selectionSource": "project-setting"}}}
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": fixed, "/v7/deployments": VERCEL_DEPLOYMENTS,
                     "/v13/deployments/": calm})
        snapshot = providers.posture_snapshot({"repository": POLICY["repository"],
                                               "metered": {"providers": {"vercel": {"project_ids": ["prj_widget"]}}}},
                                              token_for, NOW, fake)
    assert "VERCEL_LARGE_OR_ELASTIC_MACHINE" not in [f["code"] for f in posture.findings(snapshot, [], DAY)]
    unknown = {**VERCEL_DEPLOYMENT_DETAIL, "resourceConfig": {"buildMachine": {"machineSelectionType": "quantum"}}}
    with creds():
        fresh()
        try:
            providers.vercel_last_build_machine("prj_widget", NOW, Fake({"/v7/deployments": VERCEL_DEPLOYMENTS,
                                                                         "/v13/deployments/": unknown}))
        except providers.ProviderError as exc:
            assert exc.kind == "DIVERGED"
        else:
            raise AssertionError("unknown selection must diverge")


def test_policy_drift_between_hosts_is_a_finding():
    same = {"policies": [{"policy_id": "a", "version": 2, "signature": "s2", "state": "ACTIVE"}]}
    assert posture.policy_drift(same, same) == []
    behind = {"policies": [{"policy_id": "a", "version": 1, "signature": "s1", "state": "ACTIVE"}]}
    missing = {"policies": []}
    for peer, text in ((behind, "railway: v1 ACTIVE"), (missing, "railway: absent")):
        found = posture.policy_drift(same, peer)
        assert len(found) == 1 and found[0]["code"] == "POLICY_DRIFT" and text in found[0]["problem"]
        assert found[0]["severity"] == "high" and found[0]["fix"]


def test_recorded_builds_clear_the_unrecorded_finding():
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": VERCEL_PROJECT, "/v7/deployments": VERCEL_DEPLOYMENTS})
        snapshot = providers.posture_snapshot({"repository": POLICY["repository"],
                                               "metered": {"providers": {"vercel": {"project_ids": ["prj_widget"]}}}},
                                              token_for, NOW, fake)
    rows = [{"counted": True, "provider": "vercel", "resource_owner": "example-org", "resource_name": "widget"}] * 2
    assert "UNRECORDED_BUILDS" not in [f["code"] for f in posture.findings(snapshot, rows, DAY)]


def test_posture_reports_each_provider_error_without_hiding_the_rest():
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": providers.ProviderError("vercel", "DIVERGED", "x"),
                     "AcpProject": RAILWAY_PROJECT, "AcpLimit": RAILWAY_LIMIT})
        snapshot = providers.posture_snapshot(POLICY, token_for, NOW, fake)
    assert snapshot["railway"] is not None and snapshot["vercel"] == []
    assert any(f["code"] == "PROVIDER_DIVERGED" and f["severity"] == "high"
               for f in posture.findings(snapshot, [], DAY))


# ---- live capacity and the coverage audit -----------------------------------
TEAM_ACTIVITY = {"deployments": [
    {"uid": "d1", "created": int(NOW * 1000) - 1000, "state": "BUILDING", "projectId": "prj_widget", "name": "widget"},
    {"uid": "d2", "created": int(NOW * 1000) - 2000, "state": "READY", "projectId": "prj_other", "name": "other"},
    {"uid": "d3", "created": int(NOW * 1000) - 3000, "readyState": "QUEUED", "name": "other"},
], "pagination": {"next": None}}
TEAM_PROJECTS = {"projects": [
    {"id": "prj_widget", "name": "widget", "link": {"type": "github", "org": "Example-Org", "repo": "Widget"}},
    {"id": "prj_cli", "name": "cli-site"},
], "pagination": {"next": None}}


def test_team_activity_counts_today_and_builds_in_flight_per_project():
    with creds():
        fresh()
        fake = Fake({"/v6/deployments": TEAM_ACTIVITY})
        seen = providers.vercel_team_activity("team_abc", NOW, fake)
    assert seen == {"deployments_today": 3, "in_flight": 2, "truncated": False,
                    "projects_in_flight": {"prj_widget": 1, "widget": 1, "other": 1}}, seen
    assert "teamId=team_abc" in fake.calls[0][1] and "since=" in fake.calls[0][1]


def test_team_activity_refuses_an_unknown_state():
    with creds():
        fresh()
        bad = {"deployments": [{"uid": "d1", "created": 1, "state": "EXPLODED"}]}
        try:
            providers.vercel_team_activity("team_abc", NOW, Fake({"/v6/deployments": bad}))
            raise AssertionError("an unknown state was counted")
        except providers.ProviderError as exc:
            assert exc.kind == "DIVERGED"


def test_service_capacity_reads_each_service_and_never_raises():
    builds = [{"provider": "vercel"}, {"provider": "railway"}, {"provider": "github_actions"}]
    with creds():
        fresh()
        fake = Fake({"/v6/deployments": TEAM_ACTIVITY, "AcpProject": RAILWAY_PROJECT, "AcpLimit": RAILWAY_LIMIT})
        seen = {c["provider"]: c for c in providers.service_capacity(POLICY, builds, NOW, fake)}
        assert seen["vercel"]["source"] == "live" and seen["vercel"]["in_flight"] == 2
        assert seen["railway"] == {"provider": "railway", "source": "live", "deployments_today": 1,
                                   "over_limit": False, "soft_limit": 20, "hard_limit": None}
        assert seen["github_actions"] == {"provider": "github_actions", "source": "ledger"}
        fresh()
        down = providers.service_capacity(POLICY, builds[:1], NOW, Fake({}))
        assert down[0]["source"] == "unavailable" and down[0]["kind"] == "UNAVAILABLE"


def test_build_evidence_names_each_provider_project():
    with creds():
        fresh()
        fake = Fake({**github_routes(), "/v9/projects/": VERCEL_PROJECT, "AcpProject": RAILWAY_PROJECT})
        seen = providers.build_evidence("hosted_build", POLICY, CLAIM,
                                        {"trigger": "push", "ref": "refs/heads/main", "new_sha": SHA},
                                        token_for, NOW, fake)
    ids = {b["provider"]: b["project_id"] for b in seen["builds"]}
    assert ids == {"vercel": "prj_widget", "railway": "a3dbbfc5-3fe7-4365-a754-9a7856766f05",
                   "github_actions": ".github/workflows/ci.yml"}, ids


def test_team_projects_are_read_in_small_pages():
    first = {"projects": [{"id": "prj_a", "name": "a"}], "pagination": {"next": 111}}
    second = {"projects": [{"id": "prj_b", "name": "b"}], "pagination": {"next": None}}

    def fetch(provider, url, token, body=None):
        assert "limit=20" in url
        return second if "from=111" in url else first
    with creds():
        fresh()
        seen = providers.vercel_team_projects("team_abc", NOW, fetch)
    assert [p["id"] for p in seen] == ["prj_a", "prj_b"]


def test_team_projects_carry_their_git_link():
    with creds():
        fresh()
        seen = providers.vercel_team_projects("team_abc", NOW, Fake({"/v9/projects?": TEAM_PROJECTS}))
    assert seen == [{"id": "prj_cli", "name": "cli-site", "linked_repository": None},
                    {"id": "prj_widget", "name": "widget", "linked_repository": "Example-Org/Widget"}]


def test_workflows_of_an_unpushed_commit_are_read_at_its_branch_and_never_cached():
    fresh()
    sha = "c" * 40
    token = lambda owner: "gh-token"
    head = "f" * 40
    fake = Fake({"/commits/main": {"sha": head},
                 f"/contents/.github/workflows?ref={head}": [{"type": "file", "path": ".github/workflows/ci.yml"}],
                 f"/contents/.github/workflows/ci.yml?ref={head}": content(CI_BOUNDED)})
    found = providers.github_workflows("Example-Org", "Widget", sha, token, fake, fallback_ref="main")
    assert [w["path"] for w in found] == [".github/workflows/ci.yml"] and found[0]["read_at"] == "main", found
    assert ("workflows", "example-org", "widget", sha) not in providers._CACHE, "a branch's answer moves"
    assert ("workflows", "example-org", "widget", head) in providers._CACHE, "the branch head's analysis is reused"
    calls = len(fake.calls)
    providers.github_workflows("Example-Org", "Widget", sha, token, fake, fallback_ref="main")
    assert len(fake.calls) - calls == 3, "a repeat reads only the listing, the commit check and the branch head"


def test_no_workflows_is_believed_only_for_a_commit_github_has():
    fresh()
    sha = "d" * 40
    token = lambda owner: "gh-token"
    assert providers.github_workflows("Example-Org", "Widget", sha, token,
                                      Fake({f"/commits/{sha}": {"sha": sha}})) == []
    fresh()
    try:
        providers.github_workflows("Example-Org", "Widget", sha, token, Fake({"/repos/Example-Org/Widget?": {}}),
                                   fallback_ref="feature")
    except providers.ProviderError as exc:
        assert exc.kind in ("UNAVAILABLE", "DIVERGED"), exc
    else:
        raise AssertionError("neither the commit nor a branch was readable, so the answer is unknown")


def test_branch_rules_follow_vercels_glob_and_any_true_semantics():
    rules = lambda d: {"git": {"deploymentEnabled": d}}
    assert providers.vercel_branch_enabled(rules({"*": False, "main": True}), "fix/review") is True, \
        "`*` stops at a slash, so a nested branch is not covered and deploys"
    assert providers.vercel_branch_enabled(rules({"**": False, "main": True}), "fix/review") is False
    assert providers.vercel_branch_enabled(rules({"**": False, "main": True}), "main") is True, "any true rule wins"
    assert providers.vercel_branch_enabled(rules({"experiment-*": False, "*-dev": True}), "experiment-x-dev") is True
    assert providers.vercel_branch_enabled(rules({"dev": False}), "main") is True, "an unnamed branch deploys"


def test_vercel_json_of_an_unpushed_commit_is_read_at_its_branch():
    fresh()
    sha = "e" * 40
    token = lambda owner: "gh-token"
    fake = Fake({"/contents/vercel.json?ref=fix/x": content(json.dumps(
        {"git": {"deploymentEnabled": {"**": False, "main": True}}}))})
    config = providers.github_json_file("Example-Org", "Widget", "vercel.json", sha, token, fake, fallback_ref="fix/x")
    assert config == {"git": {"deploymentEnabled": {"**": False, "main": True}}}, config
    assert providers.vercel_branch_enabled(config, "fix/x") is False, "so ACP no longer counts a preview Vercel skips"
    fresh()
    assert providers.github_json_file("Example-Org", "Widget", "vercel.json", sha, token,
                                      Fake({f"/commits/{sha}": {"sha": sha}}), fallback_ref="fix/x") is None, \
        "a pushed commit with no vercel.json has none"

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} provider tests passed")
