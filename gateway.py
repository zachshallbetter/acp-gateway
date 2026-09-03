#!/usr/bin/env python3
"""Isolated ACP read gateway: health, App status, and owner-agnostic Project reads.

Two design rules shape the whole file:

  1. Which accounts this gateway can read is *discovered*, not deployed. The App
     lists its own installations, so putting the App on another org or on your
     user account is enough -- no env edit, no redeploy, no installation ID
     handed around. See installations()/installation_for().
  2. Every refusal explains itself. A caller (usually a skill) that omits an
     owner, names an uninstalled account, or asks for a board outside the
     allowlist gets back the code, the reason, a remedy, and the data it needs
     to retry correctly -- rather than an opaque 400/502 it has to guess at.
"""
from __future__ import annotations
import base64, hmac, http.server, json, os, subprocess, tempfile, time
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

# One page is 100 -- GitHub's maximum. MAX_PAGES bounds a runaway loop; hitting
# it is reported as truncated rather than passed off as a complete board.
ITEM_PAGE, MAX_PAGES = 100, 20
INSTALLATION_TTL = 300          # seconds to trust the discovered installation list
JWT_TTL = 540                   # GitHub's ceiling is 600; leave a minute of slack


class GatewayError(Exception):
    """A refusal the caller can act on: stable code, reason, remedy, context."""

    def __init__(self, status, code, detail, remedy=None, **context):
        super().__init__(detail)
        self.status, self.code, self.detail, self.remedy, self.context = status, code, detail, remedy, context

    def payload(self):
        body = {"error": self.code, "detail": self.detail}
        if self.remedy:
            body["remedy"] = self.remedy
        body.update(self.context)
        return body


# The two bases keep the historical contract: a bad target is a ValueError (400),
# an upstream/config problem is a RuntimeError (502/503).
class TargetError(GatewayError, ValueError): pass
class UpstreamError(GatewayError, RuntimeError): pass


def configured():
    """App credentials present.

    The installation ID is deliberately *not* part of this any more: one gateway
    now serves every account the App is installed on, resolving the installation
    per owner. ACP_GITHUB_INSTALLATION_ID survives only as a fallback.
    """
    return all(os.getenv(name) for name in ("ACP_GITHUB_APP_ID", "ACP_GITHUB_PRIVATE_KEY"))


def authorized(handler):
    expected = os.getenv("ACP_GATEWAY_TOKEN", "")
    return bool(expected) and hmac.compare_digest(handler.headers.get("Authorization", ""), "Bearer " + expected)


# ---------------------------------------------------------------- App identity

_JWT = {"value": None, "expires": 0.0}
_APP = {"value": None}
_INSTALLATIONS = {"value": None, "fetched_at": 0.0}


def app_jwt():
    """RS256 App JWT, reused until it is nearly expired (each one costs a fork)."""
    if not configured():
        raise UpstreamError(503, "APP_NOT_CONFIGURED",
                            "This gateway has no GitHub App credentials, so it cannot read anything from GitHub.",
                            remedy="Set ACP_GITHUB_APP_ID and ACP_GITHUB_PRIVATE_KEY on the deployment.",
                            configured=False)
    now = time.time()
    if _JWT["value"] and now < _JWT["expires"] - 60:
        return _JWT["value"]
    enc = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    header = enc(b'{"alg":"RS256","typ":"JWT"}')
    payload = enc(json.dumps({"iat": int(now) - 60, "exp": int(now) + JWT_TTL,
                              "iss": os.environ["ACP_GITHUB_APP_ID"]}, separators=(",", ":")).encode())
    signing = f"{header}.{payload}".encode()
    with tempfile.NamedTemporaryFile(mode="w", prefix="acp-key-", delete=False) as key:
        os.chmod(key.name, 0o600); key.write(os.environ["ACP_GITHUB_PRIVATE_KEY"]); key.flush(); path = key.name
    try:
        signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", path], input=signing,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
    finally:
        os.unlink(path)
    _JWT.update(value=signing.decode() + "." + enc(signature), expires=now + JWT_TTL)
    return _JWT["value"]


def app_api(path, method="GET"):
    request = Request("https://api.github.com" + path, method=method, headers={
        "Authorization": "Bearer " + app_jwt(),
        "Accept": "application/vnd.github+json",
        "User-Agent": "acp-gateway",
    })
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def app_identity():
    """The App's own record, for the install URL in remedies. Best effort."""
    if _APP["value"] is None:
        try:
            _APP["value"] = app_api("/app")
        except Exception:
            return {}
    return _APP["value"]


def install_url():
    slug = (app_identity() or {}).get("slug")
    return f"https://github.com/apps/{slug}/installations/new" if slug else None


# ProjectsV2 boards hang off an *owner*, so only an owner-level Projects grant
# reaches them. `repository_projects` is deliberately not in this list: that is
# Projects (classic), repository-scoped, and an installation holding it still
# reads zero ProjectsV2 boards -- counting it here reported a user installation
# as Projects-capable when it could not see a single board.
PROJECT_PERMISSIONS = ("organization_projects", "projects")


def installation_entry(raw):
    account, permissions = raw.get("account") or {}, raw.get("permissions") or {}
    return {
        "login": account.get("login") or "",
        "account_type": account.get("type") or "",
        "installation_id": raw.get("id"),
        "projects_read": any(permissions.get(name) in ("read", "write", "admin") for name in PROJECT_PERMISSIONS),
        "permissions": permissions,
    }


def installations(refresh=False):
    """Every account this App is installed on.

    This is what makes the gateway owner-agnostic: to serve a new org or a
    personal account you install the App there, and the next request (or the
    next cache expiry) picks it up.
    """
    now = time.time()
    if _INSTALLATIONS["value"] is not None and not refresh and now - _INSTALLATIONS["fetched_at"] < INSTALLATION_TTL:
        return _INSTALLATIONS["value"]
    found, page = [], 1
    while page <= 10:
        batch = app_api(f"/app/installations?per_page=100&page={page}")
        if not isinstance(batch, list):
            break
        found.extend(installation_entry(item) for item in batch)
        if len(batch) < 100:
            break
        page += 1
    _INSTALLATIONS.update(value=found, fetched_at=now)
    return found


def known_owners():
    """Logins we can serve right now -- for advice inside an error. Best effort."""
    try:
        return sorted(entry["login"] for entry in installations() if entry["login"])
    except Exception:
        return sorted(installation_overrides())


def owner_installation(owner):
    try:
        return next((e for e in installations() if e["login"].lower() == owner.lower()), None)
    except Exception:
        return None


def installation_overrides():
    """ACP_GITHUB_INSTALLATIONS=<owner>:<id>,<owner>:<id> — pin, skipping discovery."""
    mapping = {}
    for part in os.getenv("ACP_GITHUB_INSTALLATIONS", "").split(","):
        login, _, ident = part.strip().partition(":")
        if login.strip() and ident.strip().isdigit():
            mapping[login.strip().lower()] = ident.strip()
    return mapping


def installation_for(owner):
    """Installation ID that can read `owner`'s boards: pinned, else discovered."""
    pinned = installation_overrides().get(owner.lower())
    if pinned:
        return pinned
    try:
        known = installations()
    except GatewayError:
        raise
    except Exception as exc:
        fallback = os.getenv("ACP_GITHUB_INSTALLATION_ID")
        if fallback:                                  # degraded, but keeps a single-owner deploy alive
            return fallback
        raise UpstreamError(502, "INSTALLATION_LOOKUP_FAILED",
                            f"Could not list this App's installations: {str(exc)[:200]}",
                            remedy="Retry. If it persists, pin the owner with ACP_GITHUB_INSTALLATIONS=<owner>:<id>.")
    for entry in known:
        if entry["login"].lower() == owner.lower():
            return str(entry["installation_id"])
    raise TargetError(404, "OWNER_NOT_INSTALLED",
                      f"The GitHub App behind this gateway is not installed on '{owner}'.",
                      remedy="Install it on that account with Projects: read"
                             + (f" — {install_url()}" if install_url() else "")
                             + ". The gateway discovers the installation itself; no ID to copy, no redeploy.",
                      owner=owner, owners_available=sorted(e["login"] for e in known if e["login"]))


def default_installation():
    ident = os.getenv("ACP_GITHUB_INSTALLATION_ID")
    if ident:
        return ident
    known = installations()
    if len(known) == 1:
        return str(known[0]["installation_id"])
    raise TargetError(400, "OWNER_REQUIRED",
                      "This gateway serves several installations, so a call must name the owner.",
                      remedy="Add ?owner=<github login>. GET /internal/installations lists what is available.",
                      owners_available=[e["login"] for e in known if e["login"]])


def installation_token(owner=None):
    """Short-lived installation token for `owner` (or the default installation)."""
    ident = installation_for(owner) if owner else default_installation()
    return app_api(f"/app/installations/{ident}/access_tokens", method="POST")


# ------------------------------------------------------------------- allowlist

def allowlist_rules():
    """Parse ACP_PROJECT_ALLOWLIST into {owner_lower or None: set|None}.

    Entries are numbers and ranges, optionally owner-qualified:

        2-9,11                      -> those numbers, for any owner
        zachshallbetter:*           -> every board of that user
        Anime-Universe:2-9,11       -> ...qualification carries across commas
        *                           -> every board of every installed owner

    None as a value means "any positive number"; the None key is the bucket for
    unqualified entries, applied to owners with no rule of their own. Default is
    the historical 2-7 so an existing deployment never silently widens.
    """
    rules, current = {}, None
    for part in os.getenv("ACP_PROJECT_ALLOWLIST", "2-7").strip().split(","):
        part = part.strip()
        if not part:
            continue
        login, sep, rule = part.partition(":")
        if sep and login.strip():
            current, rule = login.strip().lower(), rule.strip()
        else:
            rule = login.strip()          # a bare rule continues the current owner scope
        key = current
        if rule == "*":
            rules[key] = None
            continue
        try:
            if "-" in rule[1:]:
                low, _, high = rule.partition("-")
                numbers = range(int(low), int(high) + 1)
            else:
                numbers = [int(rule)]
        except ValueError:
            raise ValueError(f"ACP_PROJECT_ALLOWLIST: cannot parse {part!r}")
        if key in rules and rules[key] is None:
            continue
        rules.setdefault(key, set()).update(numbers)
    return rules


def allowed_projects(owner=None):
    """Board numbers allowed for `owner`; None means any positive number."""
    rules = allowlist_rules()
    if owner and owner.lower() in rules:
        return rules[owner.lower()]
    return rules.get(None, set())


def project_allowed(number, owner=None):
    allowed = allowed_projects(owner)
    return number > 0 if allowed is None else number in allowed


# --------------------------------------------------------------------- GraphQL

PROJECT_QUERY = """
  query($owner:String!, $number:Int!, $after:String) {
    OWNER_ROOT(login:$owner) {
      projectV2(number:$number) {
        id title number
        fields(first:100) { totalCount nodes { __typename ... on ProjectV2FieldCommon { id name } } }
        items(first:%d, after:$after) {
          totalCount
          pageInfo { hasNextPage endCursor }
          nodes { id type isArchived content { __typename
            ... on Issue { title number url state repository { nameWithOwner } }
            ... on PullRequest { title number url state repository { nameWithOwner } }
          } }
        }
      }
    }
  }
""" % ITEM_PAGE

PROJECTS_QUERY = """
  query($owner:String!, $after:String) {
    OWNER_ROOT(login:$owner) {
      projectsV2(first:100, after:$after) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes { number title url closed public shortDescription updatedAt }
      }
    }
  }
"""


def graphql(token: str, query: str, variables: dict):
    payload = json.dumps({"query": query, "variables": variables}).encode()
    request = Request("https://api.github.com/graphql", data=payload, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "acp-gateway",
    })
    with urlopen(request, timeout=10) as response:
        return json.load(response)


def owner_scoped(token, template, variables, root=None):
    """Run an owner-rooted query. A board may be owned by an organization OR a
    user, so both roots are tried until one resolves; `root` pins it thereafter."""
    errors = []
    for candidate in ((root,) if root else ("organization", "user")):
        result = graphql(token, template.replace("OWNER_ROOT", candidate), variables)
        errors.extend(result.get("errors") or [])
        found = (result.get("data") or {}).get(candidate)
        if found:
            return candidate, found, errors
    return None, None, errors


def graphql_notes(errors):
    return [str(error.get("message", error))[:200] for error in errors][:5]


def missing_board(owner, project, errors):
    """Not-found is usually one of two things; say which, and how to fix it."""
    entry = owner_installation(owner)
    if entry and not entry["projects_read"]:
        user = entry["account_type"] == "User"
        return TargetError(403, "PROJECTS_PERMISSION_MISSING",
                           f"The App is installed on '{owner}' ({entry['account_type'].lower()} account) but that "
                           "installation holds no owner-level Projects permission, so it sees no ProjectsV2 board.",
                           remedy=("Add the account-level Projects permission (read) to the App and accept it on this "
                                   "installation. An `organization_projects` grant does not apply to a user account, "
                                   "and `repository_projects` is Projects (classic), which ProjectsV2 ignores."
                                   if user else
                                   "Grant the App's organization Projects permission (read) on "
                                   f"'{owner}' and accept the updated permissions."),
                           owner=owner, account_type=entry["account_type"],
                           installation_id=entry["installation_id"],
                           permissions=entry["permissions"], graphql_errors=graphql_notes(errors))
    return UpstreamError(404, "PROJECT_NOT_FOUND",
                         f"No ProjectsV2 board #{project} is visible to this App for '{owner}'.",
                         remedy=f"List the boards with GET /internal/projects?owner={owner} and use a `number` from "
                                "there. If the board exists but is absent from that list, the App's installation "
                                f"on '{owner}' cannot see it (check its Projects permission).",
                         owner=owner, project=project, graphql_errors=graphql_notes(errors))


def require_owner(owner):
    owner = (owner or "").strip()
    if owner:
        return owner
    raise TargetError(400, "OWNER_REQUIRED", "This call needs ?owner=<github login>.",
                      remedy="Pass the user or organization that owns the board, e.g. "
                             "?owner=<login>&project=<number>. GET /internal/installations lists the owners this "
                             "gateway can currently read.",
                      owners_available=known_owners())


def project_list(owner):
    """Every board `owner` exposes to this App, with the number to ask for next."""
    owner = require_owner(owner)
    token = (installation_token(owner) or {}).get("token")
    if not token:
        raise UpstreamError(502, "TOKEN_UNAVAILABLE", "GitHub installation token response did not contain a token.")
    boards, cursor, pages, root, block, errors = [], None, 0, None, {}, []
    while pages < MAX_PAGES:
        root, found, page_errors = owner_scoped(token, PROJECTS_QUERY, {"owner": owner, "after": cursor}, root)
        errors.extend(page_errors)
        if found is None:
            raise UpstreamError(404, "OWNER_NOT_VISIBLE",
                                f"'{owner}' did not resolve to a user or organization this App can see.",
                                remedy="Check the spelling of the login, and that the App is installed on it.",
                                owner=owner, owners_available=known_owners(), graphql_errors=graphql_notes(errors))
        block = found["projectsV2"] or {}
        for node in block.get("nodes") or []:
            node["allowed"] = project_allowed(node["number"], owner)
            boards.append(node)
        pages += 1
        info = block.get("pageInfo") or {}
        cursor = info.get("endCursor")
        if not info.get("hasNextPage"):
            break
    return {
        "owner": owner, "owner_type": root, "projects": boards,
        "count": len(boards), "total": block.get("totalCount"),
        "allowlist": os.getenv("ACP_PROJECT_ALLOWLIST", "2-7"),
        "note": "Pass a board's `number` as ?project= to /internal/project-context. `allowed:false` means "
                "ACP_PROJECT_ALLOWLIST does not admit it yet.",
    }


def project_context(owner: str, project: str):
    """Read one allowlisted ProjectsV2 board using a short-lived App token.

    Pages through items to the end, and reports its own completeness: a count
    equal to the page size is a cap, not a total, so `truncated` is explicit.
    """
    owner = require_owner(owner)
    project = str(project or "").strip()
    if not project.isdigit():
        raise TargetError(400, "PROJECT_REQUIRED",
                          f"?project= must be a board number; got {project!r}.",
                          remedy=f"Use a `number` from GET /internal/projects?owner={owner} (the trailing number in "
                                 "the board's github.com/.../projects/<n> URL).",
                          owner=owner)
    if not project_allowed(int(project), owner):
        raise TargetError(403, "PROJECT_NOT_ALLOWED",
                          f"Board #{project} of '{owner}' is outside this gateway's allowlist.",
                          remedy=f"Add it to ACP_PROJECT_ALLOWLIST on the deployment — '{owner}:{project}' for that "
                                 f"board, '{owner}:*' for every board of that owner, or '*' for all.",
                          owner=owner, project=int(project),
                          allowlist=os.getenv("ACP_PROJECT_ALLOWLIST", "2-7"))

    token = (installation_token(owner) or {}).get("token")
    if not token:
        raise UpstreamError(502, "TOKEN_UNAVAILABLE", "GitHub installation token response did not contain a token.")

    snapshot, cursor, pages, root, truncated, errors = None, None, 0, None, False, []
    while True:
        root, found, page_errors = owner_scoped(token, PROJECT_QUERY,
                                                {"owner": owner, "number": int(project), "after": cursor}, root)
        errors.extend(page_errors)
        page = (found or {}).get("projectV2")
        if not page:
            if snapshot is None:
                raise missing_board(owner, int(project), errors)
            break
        if snapshot is None:
            snapshot = page
        else:
            snapshot["items"]["nodes"].extend(page["items"]["nodes"])
        info = page["items"].get("pageInfo") or {}
        cursor, pages = info.get("endCursor"), pages + 1
        if not info.get("hasNextPage") or pages >= MAX_PAGES:
            truncated = bool(info.get("hasNextPage"))
            break

    fetched = len(snapshot["items"]["nodes"])
    total = snapshot["items"].get("totalCount")
    return {
        "snapshot": snapshot,
        "snapshot_source": "github-app",
        "allowed": True,
        "owner": owner,
        "owner_type": root,
        "items_fetched": fetched,
        "items_total": total,
        # Explicit, so "I got everything" is never inferred from a count that
        # merely equals the page size.
        "truncated": bool(truncated) or (total is not None and fetched < total),
        "pages": pages,
    }


# ---------------------------------------------------------------------- server

ENDPOINTS = {
    "GET /health": "liveness; unauthenticated",
    "GET /internal/app-status": "credential and allowlist configuration of this deployment",
    "GET /internal/app-probe?owner=": "mint an installation token and report its permissions",
    "GET /internal/installations": "accounts this App can read (?refresh=1 to bypass the cache)",
    "GET /internal/projects?owner=": "boards for one owner, each with the number to pass to project-context",
    "GET /internal/project-context?owner=&project=": "full snapshot of one allowlisted board",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        route, params = urlsplit(self.path).path, parse_qs(urlsplit(self.path).query)
        first = lambda name: (params.get(name, [""])[0] or "").strip()
        if route == "/health":
            self.reply(200, {"status": "ok", "service": "acp-gateway", "app_configured": configured()})
            return
        if not route.startswith("/internal/"):
            self.reply(404, {"error": "NOT_FOUND", "detail": f"No route {route}.", "endpoints": ENDPOINTS})
            return
        if not authorized(self):
            self.reply(401, {"error": "UNAUTHORIZED", "detail": "Missing or wrong bearer token.",
                             "remedy": "Send Authorization: Bearer <ACP_GATEWAY_TOKEN>."})
            return
        try:
            self.reply(200, self.internal(route, first))
        except GatewayError as exc:
            self.reply(exc.status, exc.payload())
        except Exception as exc:
            self.reply(502, {"error": "UPSTREAM_FAILURE", "detail": str(exc)[:240],
                             "remedy": "Check /internal/app-probe; if that mints a token, the failure is board-side."})

    def internal(self, route, first):
        if route == "/internal/app-status":
            pinned = installation_overrides()
            return {"configured": configured(),
                    "installation_resolution": "pinned+discovery" if pinned else "discovery",
                    "pinned_installations": pinned,
                    "fallback_installation_id": os.getenv("ACP_GITHUB_INSTALLATION_ID"),
                    "project_allowlist": os.getenv("ACP_PROJECT_ALLOWLIST", "2-7"),
                    "owners_available": known_owners(),
                    "token_minting": "internal-only",
                    "endpoints": ENDPOINTS}
        if route == "/internal/app-probe":
            owner = first("owner")
            token = installation_token(owner or None)
            return {"configured": True, "installation_token": "minted", "owner": owner or None,
                    "token_expires_at": token.get("expires_at"), "permissions": token.get("permissions", {}),
                    "repositories_url": "/installation/repositories"}
        if route == "/internal/installations":
            found = installations(refresh=first("refresh") in ("1", "true", "yes"))
            return {"installations": found, "count": len(found), "install_url": install_url(),
                    "cache_ttl_seconds": INSTALLATION_TTL,
                    "note": "Any account here can be read without a redeploy; install the App elsewhere to add one."}
        if route == "/internal/projects":
            return project_list(first("owner"))
        if route == "/internal/project-context":
            return project_context(first("owner"), first("project"))
        raise TargetError(404, "NOT_FOUND", f"No route {route}.", endpoints=ENDPOINTS)

    def reply(self, code, body):
        payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def log_message(self, *_):
        pass


def main():
    if not os.getenv("ACP_GATEWAY_TOKEN"):
        raise SystemExit("ACP_GATEWAY_TOKEN is required")
    allowlist_rules()                    # fail fast on a malformed allowlist, not on the first read
    http.server.ThreadingHTTPServer(("0.0.0.0", int(os.getenv("PORT", "8080"))), Handler).serve_forever()


if __name__ == "__main__":
    main()
