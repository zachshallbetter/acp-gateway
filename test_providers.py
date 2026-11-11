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
                     "/v7/deployments": VERCEL_DEPLOYMENTS, "AcpProject": RAILWAY_PROJECT,
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


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} provider tests passed")
