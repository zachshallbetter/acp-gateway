"""GitHub App installation-token primitives; never return private credentials."""
from __future__ import annotations
import base64, json, os, subprocess, tempfile, time
from urllib.request import Request, urlopen

def _b64(value: bytes) -> str: return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

class GitHubApp:
    def __init__(self, app_id: str, installation_id: str, private_key: str):
        if not app_id or not installation_id or not private_key: raise ValueError("ACP_GITHUB_APP_ID, ACP_GITHUB_INSTALLATION_ID, and ACP_GITHUB_PRIVATE_KEY are required")
        self.app_id=app_id; self.installation_id=installation_id; self.private_key=private_key

    def jwt(self) -> str:
        now=int(time.time()); header=_b64(b'{"alg":"RS256","typ":"JWT"}'); payload=_b64(json.dumps({"iat":now-60,"exp":now+540,"iss":self.app_id},separators=(",",":")).encode()); signing=f"{header}.{payload}".encode()
        with tempfile.NamedTemporaryFile(mode="w", prefix="acp-key-", delete=False) as key:
            os.chmod(key.name,0o600); key.write(self.private_key); path=key.name
        try:
            sig=subprocess.run(["openssl","dgst","-sha256","-sign",path],input=signing,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True).stdout
        finally: os.unlink(path)
        return signing.decode()+"."+_b64(sig)

    def installation_token(self) -> dict:
        request=Request(f"https://api.github.com/app/installations/{self.installation_id}/access_tokens",method="POST",headers={"Authorization":"Bearer "+self.jwt(),"Accept":"application/vnd.github+json","User-Agent":"agent-control-plane"})
        with urlopen(request,timeout=10) as response: return json.load(response)
