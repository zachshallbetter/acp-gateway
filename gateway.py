#!/usr/bin/env python3
"""Isolated ACP read gateway: health and authenticated App configuration status."""
from __future__ import annotations
import base64, hashlib, hmac, http.server, json, os, subprocess, tempfile, time
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

def configured():
    return all(os.getenv(name) for name in ("ACP_GITHUB_APP_ID", "ACP_GITHUB_INSTALLATION_ID", "ACP_GITHUB_PRIVATE_KEY"))

def authorized(handler):
    expected=os.getenv("ACP_GATEWAY_TOKEN", "")
    return bool(expected) and hmac.compare_digest(handler.headers.get("Authorization", ""), "Bearer "+expected)

def installation_token():
    now=int(time.time()); enc=lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    header=enc(b'{"alg":"RS256","typ":"JWT"}'); payload=enc(json.dumps({"iat":now-60,"exp":now+540,"iss":os.environ["ACP_GITHUB_APP_ID"]},separators=(",",":")).encode()); signing=f"{header}.{payload}".encode()
    with tempfile.NamedTemporaryFile(mode="w",prefix="acp-key-",delete=False) as key:
        os.chmod(key.name,0o600); key.write(os.environ["ACP_GITHUB_PRIVATE_KEY"]); key.flush(); path=key.name
    try: signature=subprocess.run(["openssl","dgst","-sha256","-sign",path],input=signing,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
    finally: os.unlink(path)
    jwt=signing.decode()+"."+enc(signature)
    request=Request(f"https://api.github.com/app/installations/{os.environ['ACP_GITHUB_INSTALLATION_ID']}/access_tokens",method="POST",headers={"Authorization":"Bearer "+jwt,"Accept":"application/vnd.github+json","User-Agent":"acp-gateway"})
    with urlopen(request,timeout=10) as response: return json.load(response)

def allowed_projects():
    """Which board numbers this deployment may read.

    Was a hardcoded `2 <= n <= 7` in project_context, which the README told you
    to EDIT PER DEPLOYMENT -- so the allowlist was a code change, and a gateway
    pointed at boards 8, 9 and 11 silently answered 400 for all three. It is
    configuration, so it lives in the environment.

    ACP_PROJECT_ALLOWLIST is a comma list of numbers and ranges ("2-9,11"), or
    "*" for any positive number. Default keeps the historical 2-7 so an existing
    deployment does not silently widen when this ships; widen it deliberately.
    """
    spec = os.getenv("ACP_PROJECT_ALLOWLIST", "2-7").strip()
    if spec == "*":
        return None                      # None means "any positive integer"
    allowed = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part[1:]:
            lo, _, hi = part.partition("-")
            allowed.update(range(int(lo), int(hi) + 1))
        else:
            allowed.add(int(part))
    return allowed

def project_allowed(number: int):
    allowed = allowed_projects()
    return number > 0 if allowed is None else number in allowed

# One page is 100 -- GitHub's maximum. MAX_PAGES bounds a runaway loop; hitting
# it is reported as truncated rather than passed off as a complete board.
ITEM_PAGE, MAX_PAGES = 100, 20

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

def project_context(owner: str, project: str):
    """Read one allowlisted ProjectsV2 board using a short-lived App token.

    Pages through items to the end. The previous version asked for `first:100`
    and returned whatever came back, so a board with more than 100 items was
    silently truncated and the response looked exactly like a complete one --
    a cap indistinguishable from a total. Item count and totalCount are both
    returned now, plus an explicit `truncated` flag, so a caller can tell.
    """
    if not owner or not project.isdigit() or not project_allowed(int(project)):
        raise ValueError("invalid Project target")
    token = installation_token().get("token")
    if not token:
        raise RuntimeError("GitHub installation token response did not contain token")

    # A board may be owned by an organization OR a user; the old query hardcoded
    # `organization`, so a user-owned board reported "not found".
    snapshot, cursor, pages, roots = None, None, 0, ("organization", "user")
    owner_root, truncated = None, False
    while True:
        for root in (roots if owner_root is None else (owner_root,)):
            result = graphql(token, PROJECT_QUERY.replace("OWNER_ROOT", root),
                             {"owner": owner, "number": int(project), "after": cursor})
            found = (result.get("data") or {}).get(root) or {}
            page = found.get("projectV2")
            if page:
                owner_root = root
                break
        else:
            if snapshot is None:
                raise RuntimeError("GitHub Project not found")
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
        "owner_type": owner_root,
        "items_fetched": fetched,
        "items_total": total,
        # Explicit, so "I got everything" is never inferred from a count that
        # merely equals the page size.
        "truncated": bool(truncated) or (total is not None and fetched < total),
        "pages": pages,
    }

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health": self.reply(200, {"status":"ok","service":"acp-gateway","app_configured":configured()}); return
        if self.path == "/internal/app-status" and authorized(self):
            self.reply(200, {"configured":configured(),"installation_id":os.getenv("ACP_GITHUB_INSTALLATION_ID") if configured() else None,"token_minting":"internal-only"}); return
        if self.path == "/internal/app-probe" and authorized(self):
            if not configured(): self.reply(503,{"configured":False}); return
            try:
                token=installation_token(); self.reply(200,{"configured":True,"installation_token":"minted","token_expires_at":token.get("expires_at"),"permissions":token.get("permissions",{}),"repositories_url":"/installation/repositories"})
            except Exception as exc: self.reply(502,{"configured":True,"installation_token":"failed","error":str(exc)[:240]})
            return
        if urlsplit(self.path).path == "/internal/project-context" and authorized(self):
            params = parse_qs(urlsplit(self.path).query)
            owner = params.get("owner", [""])[0]
            project = params.get("project", [""])[0]
            try:
                self.reply(200, project_context(owner, project))
            except ValueError as exc:
                self.reply(400, {"error": str(exc)})
            except Exception:
                self.reply(502, {"error": "PROJECT_CONTEXT_UNAVAILABLE"})
            return
        self.send_error(401 if self.path.startswith("/internal/") else 404)
    def reply(self, code, body):
        payload=json.dumps(body,separators=(",",":"),sort_keys=True).encode(); self.send_response(code); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def log_message(self, *_): pass

def main():
    if not os.getenv("ACP_GATEWAY_TOKEN"): raise SystemExit("ACP_GATEWAY_TOKEN is required")
    server=http.server.ThreadingHTTPServer(("0.0.0.0",int(os.getenv("PORT","8080"))),Handler); server.serve_forever()

if __name__ == "__main__": main()
