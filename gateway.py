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

def project_context(owner: str, project: str):
    """Read one allowlisted ProjectsV2 board using a short-lived App token."""
    if not owner or not project.isdigit() or not 2 <= int(project) <= 7:
        raise ValueError("invalid Project target")
    token = installation_token().get("token")
    if not token:
        raise RuntimeError("GitHub installation token response did not contain token")
    query = """
      query($owner:String!, $number:Int!) {
        organization(login:$owner) {
          projectV2(number:$number) {
            id title number
            fields(first:100) { nodes { __typename ... on ProjectV2FieldCommon { id name } } }
            items(first:100) { nodes { id type isArchived content { __typename
              ... on Issue { title number url state repository { nameWithOwner } }
              ... on PullRequest { title number url state repository { nameWithOwner } }
            } } }
          }
        }
      }
    """
    payload = json.dumps({"query": query, "variables": {"owner": owner, "number": int(project)}}).encode()
    request = Request("https://api.github.com/graphql", data=payload, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "acp-gateway",
    })
    with urlopen(request, timeout=10) as response:
        result = json.load(response)
    if result.get("errors"):
        raise RuntimeError("GitHub Project query failed")
    snapshot = result.get("data", {}).get("organization", {}).get("projectV2")
    if not snapshot:
        raise RuntimeError("GitHub Project not found")
    return {"snapshot": snapshot, "snapshot_source": "github-app", "allowed": True}

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
