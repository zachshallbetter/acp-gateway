"""Read-only provider evidence for metered actions: Vercel, Railway and GitHub Actions.

ACP asks the providers two things. Would this push, deploy or merge start a paid
build? And which settings make builds risky (deploys on every push, elastic
machines, no spend cap, workflows without timeouts)? Nothing here writes to a
provider.

Every call goes to an allowlisted HTTPS host with a timeout, a response-size cap
and no redirects. Every response is checked against the fields this module
reads before it is used; a missing or mistyped field raises DIVERGED, and the
caller fails closed. Provider tokens come from ACP's own environment and are
never logged, returned or put in an error.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

import yaml

ALLOWED_HOSTS = frozenset({"api.github.com", "api.vercel.com", "backboard.railway.com"})
TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_WORKFLOW_FILES = 40
MAX_DEPLOYMENT_PAGES = 5
MAX_PROJECT_PAGES = 25       # 500 projects per team
SETTINGS_TTL = 600
CAPACITY_TTL = 30            # live build activity: fresh enough to pace by, without a read per request
RAILWAY_GRAPHQL = "https://backboard.railway.com/graphql/v2"
SCHEMA_VERSION = 1


# The deployment setting that holds each provider's read-only token.
CREDENTIAL_SETTINGS = {"vercel": "ACP_VERCEL_TOKEN", "railway": "ACP_RAILWAY_TOKEN"}


class ProviderError(Exception):
    """Evidence could not be used. kind is UNAVAILABLE or DIVERGED. missing_setting names the
    deployment setting the owner must add when the provider has no credential at all."""

    def __init__(self, provider, kind, detail, missing_setting=None):
        super().__init__(f"{provider}: {detail}")
        self.provider, self.kind, self.detail = provider, kind, detail
        self.missing_setting = missing_setting


class _RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError(urlsplit(req.full_url).hostname or "provider", "UNAVAILABLE",
                            f"refused a {code} redirect")


_OPENER = build_opener(_RefuseRedirect)


def _fetch(provider, url, token, body=None):
    """One bounded HTTPS call to an allowlisted host. Returns parsed JSON."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise ProviderError(provider, "UNAVAILABLE", "host is not allowlisted")
    if not token:
        raise ProviderError(provider, "UNAVAILABLE", "no credential is configured for this provider",
                            missing_setting=CREDENTIAL_SETTINGS.get(provider))
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
               "User-Agent": "acp-gateway"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if parts.hostname == "api.github.com":
        headers["Accept"] = "application/vnd.github+json"
    request = Request(url, data=data, method="POST" if data is not None else "GET", headers=headers)
    try:
        with _OPENER.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except ProviderError:
        raise
    except HTTPError as exc:
        raise ProviderError(provider, "UNAVAILABLE", f"HTTP {exc.code}") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise ProviderError(provider, "UNAVAILABLE", type(exc).__name__) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ProviderError(provider, "DIVERGED", "response exceeds the size cap")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProviderError(provider, "DIVERGED", "response is not JSON") from None


def _need(provider, obj, key, types, where, optional=False):
    """The field this module reads, of the type it expects, or DIVERGED."""
    if not isinstance(obj, dict):
        raise ProviderError(provider, "DIVERGED", f"{where} is not an object")
    if key not in obj or obj[key] is None:
        if optional:
            return None
        raise ProviderError(provider, "DIVERGED", f"{where}.{key} is missing")
    value = obj[key]
    if isinstance(value, bool) and bool not in (types if isinstance(types, tuple) else (types,)):
        raise ProviderError(provider, "DIVERGED", f"{where}.{key} has an unexpected type")
    if not isinstance(value, types):
        raise ProviderError(provider, "DIVERGED", f"{where}.{key} has an unexpected type")
    return value


def _cached(cache, key, ttl, now, load):
    hit = cache.get(key)
    if hit and (ttl is None or now - hit[0] < ttl):
        return hit[1]
    value = load()
    cache[key] = (now, value)
    if len(cache) > 512:
        cache.pop(next(iter(cache)))
    return value


_CACHE: dict = {}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _day(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------- Vercel

MACHINE_TYPES = ("14cpu-28gb", "basic", "enhanced", "standard", "turbo")


def _vercel_url(path, team_id=None, **query):
    # A project lives in one team; the policy names it. ACP_VERCEL_TEAM_ID is only the default.
    team = team_id or os.getenv("ACP_VERCEL_TEAM_ID", "").strip()
    if team:
        query["teamId"] = team
    return "https://api.vercel.com" + path + ("?" + urlencode(query) if query else "")


def vercel_project(project_id, now=None, fetch=_fetch, team_id=None):
    """The project's git link and build settings (GET /v9/projects/{idOrName})."""
    now = time.time() if now is None else now

    def load():
        raw = fetch("vercel", _vercel_url("/v9/projects/" + quote(project_id, safe=""), team_id),
                    os.getenv("ACP_VERCEL_TOKEN", "").strip())
        _need("vercel", raw, "id", str, "project")
        _need("vercel", raw, "name", str, "project")
        link = _need("vercel", raw, "link", dict, "project", optional=True)
        repo = None
        if link is not None:
            if _need("vercel", link, "type", str, "project.link") == "github":
                repo = {"owner": _need("vercel", link, "org", str, "project.link"),
                        "name": _need("vercel", link, "repo", str, "project.link"),
                        "production_branch": _need("vercel", link, "productionBranch", str, "project.link",
                                                   optional=True) or "main"}
            else:
                repo = {"owner": None, "name": None, "production_branch": None}
        # createDeployments says whether Vercel writes GitHub Deployment records, not whether it
        # builds: a project with it disabled still builds every push. It is reported, never used
        # to decide that a push would not build.
        git = _need("vercel", raw, "gitProviderOptions", dict, "project", optional=True) or {}
        create = _need("vercel", git, "createDeployments", str, "project.gitProviderOptions",
                       optional=True) or "enabled"
        if create not in ("enabled", "disabled"):
            raise ProviderError("vercel", "DIVERGED", "project.gitProviderOptions.createDeployments is unknown")
        resource = _need("vercel", raw, "resourceConfig", dict, "project", optional=True) or {}
        machine = _need("vercel", resource, "buildMachineType", str, "project.resourceConfig", optional=True)
        if machine is not None and machine not in MACHINE_TYPES:
            raise ProviderError("vercel", "DIVERGED", "project.resourceConfig.buildMachineType is unknown")
        selection = _need("vercel", resource, "buildMachineSelection", str, "project.resourceConfig",
                          optional=True)
        if selection is not None and selection not in ("elastic", "fixed"):
            raise ProviderError("vercel", "DIVERGED", "project.resourceConfig.buildMachineSelection is unknown")
        return {"id": raw["id"], "name": raw["name"], "repository": repo,
                "create_deployments": create,
                "ignore_command": _need("vercel", raw, "commandForIgnoringBuildStep", str, "project",
                                        optional=True),
                "root_directory": _need("vercel", raw, "rootDirectory", str, "project", optional=True),
                "build_machine_type": machine, "build_machine_selection": selection,
                "elastic_concurrency": _need("vercel", resource, "elasticConcurrencyEnabled", bool,
                                             "project.resourceConfig", optional=True)}

    return _cached(_CACHE, ("vercel-project", team_id, project_id), SETTINGS_TTL, now, load)


def vercel_deployments_per_day(project_id, days=7, now=None, fetch=_fetch, team_id=None):
    """Deployment counts per UTC day, newest first (GET /v7/deployments)."""
    now = time.time() if now is None else now
    since = int((now - days * 86400) * 1000)
    counts, until = {}, None
    for _ in range(MAX_DEPLOYMENT_PAGES):
        query = {"projectId": project_id, "since": since, "limit": 100}
        if until:
            query["until"] = until
        raw = fetch("vercel", _vercel_url("/v7/deployments", team_id, **query),
                    os.getenv("ACP_VERCEL_TOKEN", "").strip())
        rows = _need("vercel", raw, "deployments", list, "deployments")
        for row in rows:
            created = _need("vercel", row, "created", (int, float), "deployments[]")
            _need("vercel", row, "uid", str, "deployments[]")
            counts[_day(created / 1000)] = counts.get(_day(created / 1000), 0) + 1
        page = _need("vercel", raw, "pagination", dict, "deployments", optional=True) or {}
        until = page.get("next")
        if not until or not rows:
            break
    return dict(sorted(counts.items(), reverse=True))


def vercel_last_build_machine(project_id, now=None, fetch=_fetch, team_id=None):
    """The machine the project's latest build actually ran on (GET /v13/deployments/{id}), or None.

    The project setting says what the next build should use; this says what the last one used.
    """
    raw = fetch("vercel", _vercel_url("/v7/deployments", team_id, projectId=project_id, limit=1),
                os.getenv("ACP_VERCEL_TOKEN", "").strip())
    rows = _need("vercel", raw, "deployments", list, "deployments")
    if not rows:
        return None
    uid = _need("vercel", rows[0], "uid", str, "deployments[]")
    created = _need("vercel", rows[0], "created", (int, float), "deployments[]")
    detail = fetch("vercel", _vercel_url("/v13/deployments/" + quote(uid, safe=""), team_id),
                   os.getenv("ACP_VERCEL_TOKEN", "").strip())
    resource = _need("vercel", detail, "resourceConfig", dict, "deployment", optional=True) or {}
    machine = _need("vercel", resource, "buildMachine", dict, "deployment.resourceConfig", optional=True)
    if machine is None:
        return None
    selection = _need("vercel", machine, "machineSelectionType", str, "buildMachine", optional=True)
    if selection is not None and selection not in ("elastic", "fixed"):
        raise ProviderError("vercel", "DIVERGED", "buildMachine.machineSelectionType is unknown")
    return {"deployment": uid, "built_on": _day(created / 1000),
            "cores": _need("vercel", machine, "cores", int, "buildMachine", optional=True),
            "memory_mb": _need("vercel", machine, "memory", int, "buildMachine", optional=True),
            "purchase_type": _need("vercel", machine, "purchaseType", str, "buildMachine", optional=True),
            "selection": selection,
            "selection_source": _need("vercel", machine, "selectionSource", str, "buildMachine", optional=True)}


VERCEL_STATES = frozenset({"BUILDING", "CANCELED", "DELETED", "ERROR", "INITIALIZING", "QUEUED", "READY"})
VERCEL_IN_FLIGHT = frozenset({"BUILDING", "INITIALIZING", "QUEUED"})


def _day_start(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def vercel_team_activity(team_id, now=None, fetch=_fetch):
    """Today's deployments across the team, and those still building, per project (GET /v6/deployments).

    Counts every deployment Vercel made, ACP-authorized or not: dashboard redeploys and unmetered
    projects use the same build capacity.
    """
    now = time.time() if now is None else now

    def load():
        total, in_flight, per_project, until, truncated = 0, 0, {}, None, True
        for _ in range(MAX_DEPLOYMENT_PAGES):
            query = {"since": int(_day_start(now) * 1000), "limit": 100}
            if until:
                query["until"] = until
            raw = fetch("vercel", _vercel_url("/v6/deployments", team_id, **query),
                        os.getenv("ACP_VERCEL_TOKEN", "").strip())
            rows = _need("vercel", raw, "deployments", list, "deployments")
            for row in rows:
                _need("vercel", row, "uid", str, "deployments[]")
                _need("vercel", row, "created", (int, float), "deployments[]")
                state = _need("vercel", row, "state", str, "deployments[]", optional=True) or \
                    _need("vercel", row, "readyState", str, "deployments[]")
                if state not in VERCEL_STATES:
                    raise ProviderError("vercel", "DIVERGED", "deployments[].state is unknown")
                total += 1
                if state in VERCEL_IN_FLIGHT:
                    in_flight += 1
                    for key in (_need("vercel", row, "projectId", str, "deployments[]", optional=True),
                                _need("vercel", row, "name", str, "deployments[]", optional=True)):
                        if key:
                            per_project[key] = per_project.get(key, 0) + 1
            page = _need("vercel", raw, "pagination", dict, "deployments", optional=True) or {}
            until = page.get("next")
            if not until or not rows:
                truncated = False
                break
        return {"deployments_today": total, "in_flight": in_flight, "projects_in_flight": per_project,
                "truncated": truncated}

    return _cached(_CACHE, ("vercel-activity", team_id), CAPACITY_TTL, now, load)


def vercel_team_projects(team_id, now=None, fetch=_fetch):
    """Every project in the team with its git link (GET /v9/projects), for the coverage audit."""
    now = time.time() if now is None else now

    def load():
        # A project object carries its whole build configuration, so a page of 100 can pass the 1 MiB
        # response cap; 20 at a time stays well inside it.
        projects, after = [], None
        for _ in range(MAX_PROJECT_PAGES):
            query = {"limit": 20}
            if after:
                query["from"] = after
            raw = fetch("vercel", _vercel_url("/v9/projects", team_id, **query),
                        os.getenv("ACP_VERCEL_TOKEN", "").strip())
            for row in _need("vercel", raw, "projects", list, "projects"):
                link = _need("vercel", row, "link", dict, "projects[]", optional=True) or {}
                repo = None
                if link.get("type") == "github":
                    repo = f"{_need('vercel', link, 'org', str, 'projects[].link')}/" \
                           f"{_need('vercel', link, 'repo', str, 'projects[].link')}"
                projects.append({"id": _need("vercel", row, "id", str, "projects[]"),
                                 "name": _need("vercel", row, "name", str, "projects[]"),
                                 "linked_repository": repo})
            page = _need("vercel", raw, "pagination", dict, "projects", optional=True) or {}
            after = page.get("next")
            if not after:
                break
        return sorted(projects, key=lambda p: p["id"])

    return _cached(_CACHE, ("vercel-projects", team_id), SETTINGS_TTL, now, load)


def vercel_branch_enabled(config, branch):
    """False when a vercel.json turns git deployments off for this branch."""
    git = (config or {}).get("git")
    if not isinstance(git, dict) or "deploymentEnabled" not in git:
        return True
    setting = git["deploymentEnabled"]
    if isinstance(setting, bool):
        return setting
    if isinstance(setting, dict):
        # Vercel's rules: patterns are minimatch globs (`*` stops at `/`, `**` crosses it), a branch no
        # rule names deploys, and a branch several rules name deploys if any of them is true.
        matched = [enabled for pattern, enabled in setting.items()
                   if isinstance(enabled, bool) and _branch_glob(pattern).fullmatch(branch or "")]
        return True if not matched else any(matched)
    return True


def _branch_glob(pattern):
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out)


def vercel_would_build(project, config, claim, branch, trigger):
    """(would_build, why). A CLI deploy always builds; a git push builds unless turned off."""
    if trigger == "cli_deploy":
        return True, "a CLI deploy always builds"
    repo = project.get("repository") or {}
    if (repo.get("owner") or "").lower() != (claim.get("owner") or "").lower() or \
            (repo.get("name") or "").lower() != (claim.get("name") or "").lower():
        return False, "the Vercel project is not connected to this repository"
    if not vercel_branch_enabled(config, branch):
        return False, "vercel.json git.deploymentEnabled turns this branch off"
    if project.get("ignore_command") or (config or {}).get("ignoreCommand"):
        return True, "an Ignored Build Step may skip this build; ACP counts it"
    return True, "Vercel builds every push to a connected repository"


# ---------------------------------------------------------------- Railway

RAILWAY_PROJECT_QUERY = """
query AcpProject($projectId: String!) {
  project(id: $projectId) {
    id name workspaceId
    services(first: 50) { edges { node { id name
      serviceInstances(first: 20) { edges { node { environmentId source { repo image } } } } } } }
    deploymentTriggers(first: 50) { edges { node { id branch repository provider serviceId environmentId } } }
    deployments(first: 100) { edges { node { id status createdAt serviceId } } }
  }
}"""

RAILWAY_LIMIT_QUERY = """
query AcpLimit($workspaceId: String!) {
  workspace(workspaceId: $workspaceId) { id customer { usageLimit { hardLimit softLimit isOverLimit } } }
}"""

RAILWAY_QUERIES = frozenset({RAILWAY_PROJECT_QUERY, RAILWAY_LIMIT_QUERY})
DEPLOYMENT_STATUSES = frozenset({"BUILDING", "CRASHED", "DEPLOYING", "FAILED", "INITIALIZING", "NEEDS_APPROVAL",
                                 "QUEUED", "REMOVED", "REMOVING", "SKIPPED", "SLEEPING", "SUCCESS", "WAITING"})


def _railway(query, variables, fetch):
    if query not in RAILWAY_QUERIES:
        raise ProviderError("railway", "UNAVAILABLE", "query is not allowlisted")
    raw = fetch("railway", RAILWAY_GRAPHQL, os.getenv("ACP_RAILWAY_TOKEN", "").strip(),
                body={"query": query, "variables": variables})
    if isinstance(raw, dict) and raw.get("errors"):
        raise ProviderError("railway", "UNAVAILABLE", "the GraphQL API returned errors")
    return _need("railway", raw, "data", dict, "response")


def _edges(provider, connection, where):
    edges = _need(provider, connection, "edges", list, where)
    return [_need(provider, edge, "node", dict, where + ".edges[]") for edge in edges]


def railway_project(project_id, now=None, fetch=_fetch):
    """Services, their sources, deploy-on-push triggers and recent deployments."""
    now = time.time() if now is None else now

    def load():
        project = _need("railway", _railway(RAILWAY_PROJECT_QUERY, {"projectId": project_id}, fetch),
                        "project", dict, "data")
        services = []
        for node in _edges("railway", _need("railway", project, "services", dict, "project"), "project.services"):
            sources = []
            for inst in _edges("railway", _need("railway", node, "serviceInstances", dict, "service"),
                               "service.serviceInstances"):
                source = _need("railway", inst, "source", dict, "serviceInstance", optional=True) or {}
                sources.append({"environment_id": _need("railway", inst, "environmentId", str, "serviceInstance"),
                                "repo": _need("railway", source, "repo", str, "source", optional=True),
                                "image": _need("railway", source, "image", str, "source", optional=True)})
            services.append({"id": _need("railway", node, "id", str, "service"),
                             "name": _need("railway", node, "name", str, "service"), "instances": sources})
        triggers = [{"branch": _need("railway", t, "branch", str, "trigger"),
                     "repository": _need("railway", t, "repository", str, "trigger"),
                     "service_id": _need("railway", t, "serviceId", str, "trigger", optional=True),
                     "environment_id": _need("railway", t, "environmentId", str, "trigger")}
                    for t in _edges("railway", _need("railway", project, "deploymentTriggers", dict, "project"),
                                    "project.deploymentTriggers")]
        per_day = {}
        for dep in _edges("railway", _need("railway", project, "deployments", dict, "project"),
                          "project.deployments"):
            status = _need("railway", dep, "status", str, "deployment")
            if status not in DEPLOYMENT_STATUSES:
                raise ProviderError("railway", "DIVERGED", "deployment.status is unknown")
            created = _need("railway", dep, "createdAt", str, "deployment")
            try:
                day = datetime.fromisoformat(created.replace("Z", "+00:00")).strftime("%Y-%m-%d")
            except ValueError:
                raise ProviderError("railway", "DIVERGED", "deployment.createdAt is not a timestamp") from None
            per_day[day] = per_day.get(day, 0) + 1
        return {"id": _need("railway", project, "id", str, "project"),
                "name": _need("railway", project, "name", str, "project"),
                "workspace_id": _need("railway", project, "workspaceId", str, "project", optional=True),
                "services": services, "triggers": triggers,
                "deployments_per_day": dict(sorted(per_day.items(), reverse=True))}

    return _cached(_CACHE, ("railway-project", project_id), SETTINGS_TTL, now, load)


def railway_usage_limit(workspace_id, now=None, fetch=_fetch):
    """The workspace's soft and hard usage limits, in dollars."""
    now = time.time() if now is None else now

    def load():
        workspace = _need("railway", _railway(RAILWAY_LIMIT_QUERY, {"workspaceId": workspace_id}, fetch),
                          "workspace", dict, "data")
        customer = _need("railway", workspace, "customer", dict, "workspace")
        limit = _need("railway", customer, "usageLimit", dict, "customer", optional=True)
        if limit is None:
            return {"hard_limit": None, "soft_limit": None, "over_limit": False}
        return {"hard_limit": _need("railway", limit, "hardLimit", int, "usageLimit", optional=True),
                "soft_limit": _need("railway", limit, "softLimit", int, "usageLimit"),
                "over_limit": _need("railway", limit, "isOverLimit", bool, "usageLimit")}

    return _cached(_CACHE, ("railway-limit", workspace_id), SETTINGS_TTL, now, load)


def railway_would_build(project, service_ids, claim, branch, trigger):
    if trigger == "railway_up":
        return True, "railway up always builds and deploys"
    slug = f"{claim.get('owner')}/{claim.get('name')}".lower()
    for trigger_row in project["triggers"]:
        if service_ids and trigger_row["service_id"] not in service_ids:
            continue
        if trigger_row["repository"].lower() == slug and trigger_row["branch"] == branch:
            return True, f"Railway deploys pushes to {branch}"
    return False, "no Railway deploy trigger watches this branch"


# ---------------------------------------------------------------- GitHub Actions

def _github(path, token_for, owner, fetch):
    return fetch("github_actions", "https://api.github.com" + path, token_for(owner))


def github_file(owner, name, path, sha, token_for, fetch=_fetch):
    """A small file's text at an exact commit, or None when it does not exist."""
    try:
        raw = _github(f"/repos/{quote(owner)}/{quote(name)}/contents/{quote(path)}?ref={quote(sha)}",
                      token_for, owner, fetch)
    except ProviderError as exc:
        if exc.detail == "HTTP 404":
            return None
        raise
    if _need("github_actions", raw, "type", str, "content") != "file":
        return None
    if _need("github_actions", raw, "encoding", str, "content") != "base64":
        raise ProviderError("github_actions", "DIVERGED", "content.encoding is not base64")
    try:
        return base64.b64decode(_need("github_actions", raw, "content", str, "content")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ProviderError("github_actions", "DIVERGED", "content is not UTF-8 text") from None


def github_json_file(owner, name, path, sha, token_for, fetch=_fetch, fallback_ref=None):
    """A JSON file at an exact commit. For a commit GitHub has not received yet (a pre-push), the file
    is read at fallback_ref (the branch, else the default branch), as github_workflows does: the
    commit's own copy cannot be read, and reading nothing would assume the provider's default."""
    text = github_file(owner, name, path, sha, token_for, fetch)
    if text is None and fallback_ref is not None and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha or "") \
            and not _github_commit_exists(owner, name, sha, token_for, fetch):
        try:
            for ref in ([fallback_ref] if fallback_ref else []) + [None]:
                ref = ref or _github_default_branch(owner, name, token_for, fetch)
                text = github_file(owner, name, path, ref, token_for, fetch)
                if text is not None or _github_commit_exists(owner, name, ref, token_for, fetch):
                    break
        except ProviderError:
            text = None                      # unreadable at the branch too: the provider's default applies
    if text is None:
        return None
    try:
        value = json.loads(text)
    except ValueError:
        raise ProviderError("github_actions", "DIVERGED", f"{path} is not JSON") from None
    return value if isinstance(value, dict) else None


class _UnsupportedPattern(ValueError):
    """A filter pattern ACP cannot interpret exactly; the caller assumes the workflow runs."""


def _compile_pattern(body):
    """GitHub filter grammar as [(accepts, min, loop)]: * stops at /, ** crosses it, ? is zero or
    one of the preceding character, + is one or more, [a-z] is a class, backslash escapes."""
    tokens, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c == "*":
            double = body.startswith("**", i)
            i += 2 if double else 1
            tokens.append(((lambda ch: True) if double else (lambda ch: ch != "/"), 0, True))
            continue
        if c in "?+":
            if not tokens or tokens[-1][1:] != (1, False):
                raise _UnsupportedPattern(body)       # nothing single to repeat
            accepts = tokens.pop()[0]
            tokens.append((accepts, 0, False) if c == "?" else (accepts, 1, True))
            i += 1
            continue
        if c == "[":
            j, ranges = i + 1, []
            if j < n and body[j] in "!^":
                raise _UnsupportedPattern(body)       # negated classes are not documented
            while j < n and body[j] != "]":
                lo = body[j]
                if lo == "\\":
                    j += 1
                    if j >= n:
                        raise _UnsupportedPattern(body)
                    lo = body[j]
                if j + 2 < n and body[j + 1] == "-" and body[j + 2] != "]":
                    hi = body[j + 2]
                    if hi < lo:
                        raise _UnsupportedPattern(body)
                    ranges.append((lo, hi))
                    j += 3
                else:
                    ranges.append((lo, lo))
                    j += 1
            if j >= n or not ranges:
                raise _UnsupportedPattern(body)       # unterminated or empty class
            tokens.append(((lambda ch, r=tuple(ranges): any(a <= ch <= b for a, b in r)), 1, False))
            i = j + 1
            continue
        if c == "\\":
            i += 1
            if i >= n:
                raise _UnsupportedPattern(body)
            c = body[i]
        tokens.append(((lambda ch, lit=c: ch == lit), 1, False))
        i += 1
    return tokens


def _pattern_matches(tokens, branch):
    """Set-of-states simulation: time is O(len(tokens) * len(branch)), whatever the pattern."""
    n = len(tokens)

    def close(states):
        out = set()
        for k in states:
            out.add(k)
            while k < n and tokens[k][1] == 0:
                k += 1
                out.add(k)
        return out

    states = close({0})
    for ch in branch:
        step = set()
        for k in states:
            if k < n and tokens[k][0](ch):
                step.add(k if tokens[k][2] else k + 1)
                if tokens[k][2]:
                    step.add(k + 1)
        states = close(step)
        if not states:
            return False
    return n in states


def _branch_matches(patterns, branch):
    """GitHub filter patterns, a leading ! negates. Raises _UnsupportedPattern for any pattern
    ACP cannot read exactly, or a non-scalar one; callers then assume the workflow runs."""
    matched = False
    for pattern in patterns:
        if isinstance(pattern, bool) or not isinstance(pattern, (str, int)):
            raise _UnsupportedPattern("not a scalar")
        pattern = str(pattern)
        negate = pattern.startswith("!")
        if _pattern_matches(_compile_pattern(pattern[1:] if negate else pattern), branch):
            matched = not negate
    return matched


class _NoAliasLoader(yaml.SafeLoader):
    """Workflow text is repository-controlled: aliases can expand a small file into an
    exponentially large structure, so a document that uses one is treated as unparseable."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not accepted")
        return super().compose_node(parent, index)


def _trigger_name(value):
    if isinstance(value, (str, int, bool)):
        return str(value)
    raise ValueError("trigger name is not a scalar")


def _triggers(document):
    # YAML 1.1 reads the bare key `on` as the boolean True.
    on = document.get("on", document.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {_trigger_name(item): None for item in on}
    if isinstance(on, dict):
        return {_trigger_name(key): value for key, value in on.items()}
    return {}


def analyse_workflow(path, text):
    """What a workflow runs on and whether it is bounded."""
    try:
        document = yaml.load(text, Loader=_NoAliasLoader)  # SafeLoader subclass
        triggers = _triggers(document) if isinstance(document, dict) else None
    except (yaml.YAMLError, ValueError):
        return {"path": path, "parse_error": True}
    if triggers is None:
        return {"path": path, "parse_error": True}
    jobs = document.get("jobs") if isinstance(document.get("jobs"), dict) else {}
    top_concurrency = document.get("concurrency") is not None
    unbounded, uncontrolled, matrix = [], [], []
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if job.get("uses"):
            continue                                 # reusable workflow calls take no timeout
        if job.get("timeout-minutes") is None:
            unbounded.append(str(job_id))
        if not top_concurrency and job.get("concurrency") is None:
            uncontrolled.append(str(job_id))
        strategy = job.get("strategy")
        if isinstance(strategy, dict) and strategy.get("matrix") is not None:
            matrix.append(str(job_id))
    return {"path": path, "parse_error": False, "triggers": triggers,
            "jobs_without_timeout": unbounded, "jobs_without_concurrency": uncontrolled,
            "has_concurrency": top_concurrency or (bool(jobs) and not uncontrolled),
            "matrix_jobs": matrix}


def workflow_runs_on(analysis, event, branch):
    """(runs, why) for a push to branch, a workflow_dispatch or a rerun."""
    if analysis.get("parse_error"):
        return True, "the workflow could not be parsed, so ACP assumes it runs"
    triggers = analysis["triggers"]
    if event in ("workflow_dispatch", "rerun"):
        return (event == "rerun" or "workflow_dispatch" in triggers,
                "manual runs are enabled" if "workflow_dispatch" in triggers else "no workflow_dispatch trigger")
    if "push" not in triggers:
        return False, "no push trigger"
    rules = triggers["push"] if isinstance(triggers["push"], dict) else {}
    try:
        if rules.get("branches") is not None:
            patterns = rules["branches"] if isinstance(rules["branches"], list) else [rules["branches"]]
            if not _branch_matches(patterns, branch):
                return False, "the push branch filter excludes this branch"
        elif rules.get("branches-ignore") is not None:
            patterns = rules["branches-ignore"] if isinstance(rules["branches-ignore"], list) else [rules["branches-ignore"]]
            if _branch_matches(patterns, branch):
                return False, "branches-ignore excludes this branch"
        elif rules.get("tags") is not None:
            return False, "the push trigger only runs for tags"
    except _UnsupportedPattern:
        return True, "a branch filter could not be read exactly, so ACP assumes it runs"
    if rules.get("paths") is not None or rules.get("paths-ignore") is not None:
        return True, "a path filter may skip this run; ACP counts it"
    return True, "runs on pushes to this branch"


# A push to a branch with an open pull request starts that PR's pull_request runs (event type
# synchronize), whether or not the workflow also runs on push.
PULL_REQUEST_EVENTS = ("pull_request", "pull_request_target")
PULL_REQUEST_DEFAULT_TYPES = ("opened", "synchronize", "reopened")


def has_pull_request_trigger(analysis):
    return bool(analysis.get("parse_error")) or any(e in analysis["triggers"] for e in PULL_REQUEST_EVENTS)


def pull_request_runs_on(analysis, bases):
    """(runs, why) for a push to a branch with open pull requests into `bases` (their base branches)."""
    if analysis.get("parse_error"):
        return True, "the workflow could not be parsed, so ACP assumes it runs"
    for event in PULL_REQUEST_EVENTS:
        if event not in analysis["triggers"]:
            continue
        rules = analysis["triggers"][event] if isinstance(analysis["triggers"][event], dict) else {}
        types = rules.get("types")
        if types is not None:
            types = types if isinstance(types, list) else [types]
            if "synchronize" not in [str(t) for t in types]:
                continue                             # a push to an open PR is a synchronize event
        for base in bases:
            try:
                if rules.get("branches") is not None:
                    patterns = rules["branches"] if isinstance(rules["branches"], list) else [rules["branches"]]
                    if not _branch_matches(patterns, base):
                        continue
                elif rules.get("branches-ignore") is not None:
                    patterns = rules["branches-ignore"] if isinstance(rules["branches-ignore"], list) \
                        else [rules["branches-ignore"]]
                    if _branch_matches(patterns, base):
                        continue
            except _UnsupportedPattern:
                return True, f"a {event} branch filter could not be read exactly, so ACP assumes it runs"
            if rules.get("paths") is not None or rules.get("paths-ignore") is not None:
                return True, f"runs on {event} for the open pull request into {base}; a path filter may skip it, ACP counts it"
            return True, f"runs on {event} for the open pull request into {base}"
    return False, "no pull_request trigger runs for this branch's open pull requests"


def github_open_pull_request_bases(owner, name, branch, token_for, fetch=_fetch):
    """The base branches of this repository's open pull requests whose head is `branch`. Never cached:
    pull requests open and close between pushes."""
    raw = _github(f"/repos/{quote(owner)}/{quote(name)}/pulls?state=open&per_page=100"
                  f"&head={quote(owner, safe='')}:{quote(branch, safe='')}", token_for, owner, fetch)
    if not isinstance(raw, list):
        raise ProviderError("github_actions", "DIVERGED", "the pull request list is not a list")
    bases = []
    for pull in raw:
        base = _need("github_actions", pull, "base", dict, "pull request")
        ref = _need("github_actions", base, "ref", str, "pull request base")
        if ref not in bases:
            bases.append(ref)
    return bases


def _github_commit_exists(owner, name, sha, token_for, fetch):
    return _github_ref_sha(owner, name, sha, token_for, fetch) is not None


def github_workflows(owner, name, sha, token_for, fetch=_fetch, fallback_ref=None):
    """Every workflow file at an exact commit, analysed. Immutable per commit, so cached.

    A pre-push asks about a commit GitHub has not received yet. Its workflows cannot be read, so
    they are read at fallback_ref (the branch's current head, else the default branch) and marked
    `read_at`; that answer moves with the branch and is never cached. "No workflows" is believed
    only for a commit GitHub has."""
    def listing_at(ref):
        try:
            return _github(f"/repos/{quote(owner)}/{quote(name)}/contents/.github/workflows?ref={quote(ref)}",
                           token_for, owner, fetch)
        except ProviderError as exc:
            if exc.detail == "HTTP 404":
                return None
            raise

    def analyse(listing, ref):
        if not isinstance(listing, list):
            raise ProviderError("github_actions", "DIVERGED", "the workflow listing is not a list")
        paths = []
        for entry in listing[:MAX_WORKFLOW_FILES]:
            path = _need("github_actions", entry, "path", str, "contents[]")
            if _need("github_actions", entry, "type", str, "contents[]") == "file" and \
                    path.endswith((".yml", ".yaml")):
                paths.append(path)
        # Read concurrently: a repository with many workflows read one by one outlasted the push hook's
        # time limit. Results keep the listing's order.
        with ThreadPoolExecutor(max_workers=min(8, len(paths) or 1)) as pool:
            texts = list(pool.map(lambda path: github_file(owner, name, path, ref, token_for, fetch), paths))
        return [analyse_workflow(path, text) for path, text in zip(paths, texts) if text is not None]

    exact = bool(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha or ""))
    hit = _CACHE.get(("workflows", owner.lower(), name.lower(), sha)) if exact else None
    if hit:
        return hit[1]
    listing = listing_at(sha)
    if listing is not None:
        results = analyse(listing, sha)
    elif not exact or _github_commit_exists(owner, name, sha, token_for, fetch):
        results = []                                 # the commit is there and has no workflows
    else:
        for ref in ([fallback_ref] if fallback_ref else []) + [None]:
            ref = ref or _github_default_branch(owner, name, token_for, fetch)
            head = _github_ref_sha(owner, name, ref, token_for, fetch)
            if head is None:
                continue                             # no such branch on GitHub yet
            # The branch head is a commit, so its analysis is cached like any commit's: repeated pre-pushes
            # of one branch read its workflows once.
            return [dict(a, read_at=ref) for a in github_workflows(owner, name, head, token_for, fetch)]
        raise ProviderError("github_actions", "UNAVAILABLE",
                            "neither the commit nor its branch is on GitHub, so its workflows cannot be read")
    if not exact:
        return results                               # a branch name moves; only a commit is cacheable
    return _cached(_CACHE, ("workflows", owner.lower(), name.lower(), sha), None, 0, lambda: results)


def _github_ref_sha(owner, name, ref, token_for, fetch):
    """The commit a branch (or any ref GitHub resolves) points at, or None when GitHub has no such ref.

    Read from the commit list, one entry long: GET /commits/{ref} carries every file's patch, and a
    commit that touches many files outgrew the response cap (1 MB), refusing the push it described."""
    try:
        raw = _github(f"/repos/{quote(owner)}/{quote(name)}/commits?sha={quote(ref, safe='')}&per_page=1",
                      token_for, owner, fetch)
    except ProviderError as exc:
        if exc.detail in ("HTTP 404", "HTTP 422"):
            return None
        raise
    if not isinstance(raw, list):
        raise ProviderError("github_actions", "DIVERGED", "the commit list is not a list")
    if not raw:
        return None
    sha = _need("github_actions", raw[0], "sha", str, "commit")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise ProviderError("github_actions", "DIVERGED", "commit.sha is not an object id")
    return sha


def _github_default_branch(owner, name, token_for, fetch):
    raw = _github(f"/repos/{quote(owner)}/{quote(name)}", token_for, owner, fetch)
    return _need("github_actions", raw, "default_branch", str, "repository")


def github_runs_per_day(owner, name, token_for, days=7, now=None, fetch=_fetch):
    now = time.time() if now is None else now
    counts = {}
    for offset in range(days):
        day = _day(now - offset * 86400)
        raw = _github(f"/repos/{quote(owner)}/{quote(name)}/actions/runs?created={day}&per_page=1",
                      token_for, owner, fetch)
        counts[day] = _need("github_actions", raw, "total_count", int, "workflow runs")
    return counts


def github_check_runs(owner, name, ref, token_for, fetch=_fetch):
    """Check runs on a ref's head commit, by app, so posture shows what each push sets off."""
    raw = _github(f"/repos/{quote(owner)}/{quote(name)}/commits/{quote(ref, safe='')}/check-runs?per_page=100",
                  token_for, owner, fetch)
    total = _need("github_actions", raw, "total_count", int, "check runs")
    by_app = {}
    for run in _need("github_actions", raw, "check_runs", list, "check runs"):
        _need("github_actions", run, "name", str, "check_runs[]")
        app = run.get("app") if isinstance(run.get("app"), dict) else {}
        slug = app.get("slug") if isinstance(app.get("slug"), str) else "unknown"
        by_app[slug] = by_app.get(slug, 0) + 1
    return {"ref": ref, "total": total, "by_app": dict(sorted(by_app.items()))}


MAX_CHECK_RUN_PAGES = 3      # 300 check runs on one commit
# A finished check run passes with these conclusions; any other conclusion fails it.
CHECK_PASSING = frozenset({"success", "neutral", "skipped"})


def github_release_readiness(owner, name, sha, branch, token_for, fetch=_fetch):
    """Whether a commit may be deployed to production: merged into `branch`, and its CI finished green.

    Returns {"sha", "branch", "merged", "checks": {"total", "pending": [...], "failed": [...]},
    "ci_expected"}. `merged` is True when the commit is the branch head or behind it (an ancestor).
    The check runs are GitHub's latest per name on the commit, every app's included."""
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha or ""):
        raise ProviderError("github_actions", "UNAVAILABLE", "the commit is not a full object id")
    try:
        raw = _github(f"/repos/{quote(owner)}/{quote(name)}/compare/{quote(branch, safe='')}...{quote(sha)}",
                      token_for, owner, fetch)
        status = _need("github_actions", raw, "status", str, "compare")
        if status not in ("identical", "behind", "ahead", "diverged"):
            raise ProviderError("github_actions", "DIVERGED", f"compare.status {status!r} is not recognised")
        merged = status in ("identical", "behind")
    except ProviderError as exc:
        if exc.detail not in ("HTTP 404", "HTTP 422"):
            raise
        merged = False                               # the commit or the branch is not on GitHub
    pending, failed, total, seen = [], [], 0, 0
    # An unmerged commit is refused for that alone; its checks are not read.
    for page in range(1, MAX_CHECK_RUN_PAGES + 1 if merged else 1):
        raw = _github(f"/repos/{quote(owner)}/{quote(name)}/commits/{quote(sha)}/check-runs"
                      f"?filter=latest&per_page=100&page={page}", token_for, owner, fetch)
        total = _need("github_actions", raw, "total_count", int, "check runs")
        runs = _need("github_actions", raw, "check_runs", list, "check runs")
        for run in runs:
            label = _need("github_actions", run, "name", str, "check_runs[]")
            state = _need("github_actions", run, "status", str, "check_runs[]")
            conclusion = run.get("conclusion")
            if state != "completed" or conclusion is None:
                pending.append(label)
            elif conclusion not in CHECK_PASSING:
                failed.append(f"{label} ({conclusion})")
        seen += len(runs)
        if seen >= total or not runs:
            break
    if seen < total:
        # More check runs than ACP reads: the unread ones are not known to be green.
        pending.append(f"{total - seen} more check run(s) ACP did not read")
    ci_expected = False
    if merged and total == 0:
        # No check run yet: CI that runs on pushes to this branch has not started, or there is none.
        ci_expected = any(workflow_runs_on(a, "push", branch)[0]
                          for a in github_workflows(owner, name, sha, token_for, fetch))
    return {"sha": sha, "branch": branch, "merged": merged, "ci_expected": ci_expected,
            "checks": {"total": total, "pending": pending, "failed": failed}}


def github_actions_spend(owner, token_for, now=None, fetch=_fetch):
    """This month's Actions spend, when the enhanced billing API lets ACP read it."""
    now = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
    for kind in ("organizations", "users"):
        try:
            raw = _github(f"/{kind}/{quote(owner)}/settings/billing/usage?year={now.year}&month={now.month}",
                          token_for, owner, fetch)
        except ProviderError as exc:
            if exc.kind == "DIVERGED":
                raise
            continue
        items = _need("github_actions", raw, "usageItems", list, "billing usage")
        total = 0.0
        for item in items:
            if _need("github_actions", item, "product", str, "usageItems[]").lower() == "actions":
                total += float(_need("github_actions", item, "netAmount", (int, float), "usageItems[]"))
        return {"readable": True, "account_kind": kind, "actions_net_amount": round(total, 2)}
    return {"readable": False}


# ---------------------------------------------------------------- composition

def _branch(ref):
    return ref[len("refs/heads/"):] if ref and ref.startswith("refs/heads/") else ref


def build_evidence(action, policy, claim, context, token_for, now=None, fetch=_fetch):
    """Which providers this action would build on, and what makes those builds risky.

    Returns {"available": True, "builds": [...], "workflows": [...], "digest": ...}
    or {"available": False, "kind": "UNAVAILABLE"|"DIVERGED", "provider": ..., "detail": ...}.
    """
    owner, name = claim.get("owner") or "", claim.get("name") or ""
    metered = policy.get("metered") or {}
    trigger = context.get("trigger")
    sha = context.get("new_sha")
    branch = _branch(context.get("ref"))
    if action == "production_merge":
        branch = (metered.get("production_branches") or ["main"])[0] if not branch else branch
    providers = metered.get("providers") or {}
    builds, workflows = [], []
    try:
        if trigger in ("push", "merge", "promote", "cli_deploy") and providers.get("vercel"):
            vercel = providers["vercel"]
            config_path = "vercel.json"
            for project_id in vercel.get("project_ids", []):
                project = vercel_project(project_id, now, fetch, vercel.get("team_id"))
                if project.get("root_directory"):
                    config_path = project["root_directory"].strip("/") + "/vercel.json"
                config = github_json_file(owner, name, config_path, sha, token_for, fetch, fallback_ref=branch or "")
                runs, why = vercel_would_build(project, config, claim, branch, trigger)
                builds.append({"provider": "vercel", "project": project["name"], "project_id": project["id"],
                               "would_build": runs, "why": why})
        if trigger in ("push", "merge", "promote", "railway_up") and providers.get("railway"):
            railway = providers["railway"]
            project = railway_project(railway["project_id"], now, fetch)
            runs, why = railway_would_build(project, set(railway.get("service_ids") or []), claim, branch, trigger)
            builds.append({"provider": "railway", "project": project["name"], "project_id": project["id"],
                           "would_build": runs, "why": why})
        if trigger in ("push", "merge", "promote", "workflow_dispatch", "rerun"):
            event = "push" if trigger in ("merge", "promote") else trigger
            analyses = github_workflows(owner, name, sha, token_for, fetch, fallback_ref=branch)
            # Read only when a workflow could run on a pull request: most pushes need no extra call.
            pr_bases = github_open_pull_request_bases(owner, name, branch, token_for, fetch) \
                if trigger == "push" and branch and any(has_pull_request_trigger(a) for a in analyses) else []
            for analysis in analyses:
                if trigger in ("workflow_dispatch", "rerun") and analysis["path"] != context.get("workflow"):
                    continue
                runs, why = workflow_runs_on(analysis, event, branch)
                if not runs and pr_bases:
                    runs, why = pull_request_runs_on(analysis, pr_bases)
                workflows.append({**analysis, "would_run": runs, "why": why})
                builds.append({"provider": "github_actions", "project": analysis["path"],
                               "project_id": analysis["path"], "would_build": runs, "why": why})
        release = None
        production = metered.get("production_branches") or ["main"]
        if trigger == "railway_up" or (trigger == "cli_deploy" and branch in production):
            # A CLI deploy to production ships whatever commit it names, so ACP checks that commit:
            # merged into the production branch, and its CI finished green.
            release = github_release_readiness(owner, name, sha, production[0], token_for, fetch) \
                if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha or "") else {"sha": None, "branch": production[0]}
    except ProviderError as exc:
        return {"available": False, "kind": exc.kind, "provider": exc.provider, "detail": exc.detail,
                **({"missing_setting": exc.missing_setting} if exc.missing_setting else {})}
    body = {"schema_version": SCHEMA_VERSION, "builds": builds,
            "workflows": [{k: v for k, v in w.items() if k != "triggers"} for w in workflows]}
    if release is not None:
        body["release"] = release
    return {"available": True, **body, "digest": digest(body)}


def service_capacity(policy, building, now=None, fetch=_fetch):
    """Live state of each service this request would build on. Never raises: a provider that cannot be
    read is {"source": "unavailable"} and the decision falls back to ACP's own ledger for it.

    Vercel: today's deployments and builds in flight across the team. Railway: today's deployments and
    the workspace usage limit. GitHub Actions has no daily capacity reading, so it is ledger-only.
    """
    now = time.time() if now is None else now
    configured = (policy.get("metered") or {}).get("providers") or {}
    out = []
    for provider in sorted({b["provider"] for b in building}):
        try:
            if provider == "vercel":
                team = (configured.get("vercel") or {}).get("team_id") or os.getenv("ACP_VERCEL_TEAM_ID", "").strip()
                out.append({"provider": "vercel", "source": "live", **vercel_team_activity(team or None, now, fetch)})
            elif provider == "railway" and configured.get("railway"):
                project = railway_project(configured["railway"]["project_id"], now, fetch)
                limit = railway_usage_limit(project["workspace_id"], now, fetch) if project.get("workspace_id") \
                    else {"over_limit": False, "soft_limit": None, "hard_limit": None}
                out.append({"provider": "railway", "source": "live",
                            "deployments_today": project["deployments_per_day"].get(_day(now), 0),
                            "over_limit": limit["over_limit"], "soft_limit": limit["soft_limit"],
                            "hard_limit": limit["hard_limit"]})
            else:
                out.append({"provider": provider, "source": "ledger"})
        except ProviderError as exc:
            out.append({"provider": provider, "source": "unavailable", "kind": exc.kind, "detail": exc.detail})
    return out


def posture_snapshot(policy, token_for, now=None, fetch=_fetch, head_sha=None):
    """Everything the posture report needs for one governed repository.

    Each provider is read independently: one failing does not hide the others.
    """
    now = time.time() if now is None else now
    repo = policy["repository"]
    owner, name = repo["owner"], repo["name"]
    metered = policy.get("metered") or {}
    providers = metered.get("providers") or {}
    head = head_sha or (metered.get("production_branches") or ["main"])[0]
    snapshot = {"schema_version": SCHEMA_VERSION, "repository": f"{owner}/{name}",
                "fetched_at": datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "vercel": [], "railway": None, "github_actions": None, "errors": []}

    def guarded(provider, work):
        try:
            return work()
        except ProviderError as exc:
            snapshot["errors"].append({"provider": exc.provider, "kind": exc.kind, "detail": exc.detail})
            return None

    for project_id in (providers.get("vercel") or {}).get("project_ids", []):
        team_id = (providers.get("vercel") or {}).get("team_id")
        project = guarded("vercel", lambda: vercel_project(project_id, now, fetch, team_id))
        if project:
            project = dict(project)
            project["deployments_per_day"] = guarded(
                "vercel", lambda: vercel_deployments_per_day(project_id, now=now, fetch=fetch, team_id=team_id)) or {}
            project["last_build_machine"] = guarded(
                "vercel", lambda: vercel_last_build_machine(project_id, now=now, fetch=fetch, team_id=team_id))
            project["vercel_json"] = guarded("github_actions", lambda: github_json_file(
                owner, name, (project.get("root_directory") or "").strip("/") + "/vercel.json"
                if project.get("root_directory") else "vercel.json", head, token_for, fetch))
            snapshot["vercel"].append(project)
    if providers.get("railway"):
        project = guarded("railway", lambda: railway_project(providers["railway"]["project_id"], now, fetch))
        if project:
            project = dict(project)
            if project.get("workspace_id"):
                project["usage_limit"] = guarded("railway", lambda: railway_usage_limit(
                    project["workspace_id"], now, fetch))
            snapshot["railway"] = project
    actions = {}
    actions["workflows"] = guarded("github_actions", lambda: github_workflows(
        owner, name, head, token_for, fetch)) or []
    actions["runs_per_day"] = guarded("github_actions", lambda: github_runs_per_day(
        owner, name, token_for, now=now, fetch=fetch)) or {}
    actions["check_runs"] = guarded("github_actions", lambda: github_check_runs(owner, name, head, token_for, fetch))
    actions["spend"] = guarded("github_actions", lambda: github_actions_spend(owner, token_for, now, fetch)) \
        or {"readable": False}
    snapshot["github_actions"] = actions
    return snapshot
