import json, os, subprocess, sys
from unittest.mock import patch
from pathlib import Path
root=Path(__file__).parent
sys.path.insert(0, str(root))
env={**os.environ,"ACP_GATEWAY_TOKEN":"test-token","ACP_GITHUB_APP_ID":"4555426","ACP_GITHUB_INSTALLATION_ID":"12345","ACP_GITHUB_PRIVATE_KEY":"test-key"}
compile((root/"gateway.py").read_text(),str(root/"gateway.py"),"exec")
assert env["ACP_GATEWAY_TOKEN"] and env["ACP_GITHUB_APP_ID"]
with patch.dict(os.environ, env, clear=False), patch("gateway.installation_token", return_value={"token": "test-installation-token"}), patch("gateway.urlopen") as open_url:
    response = type("Response", (), {"__enter__": lambda self: self, "__exit__": lambda *args: None})()
    response.__dict__["read"] = lambda: json.dumps({"data": {"organization": {"projectV2": {"id": "PVT_test", "title": "Manga Verse", "number": 3, "fields": {"nodes": []}, "items": {"nodes": []}}}}}).encode()
    open_url.return_value = response
    assert json.loads(json.dumps(__import__("gateway").project_context("Anime-Universe", "3")))["snapshot"]["number"] == 3
    open_url.assert_called_once()
try:
    __import__("gateway").project_context("Anime-Universe", "99")
except ValueError:
    pass
else:
    raise AssertionError("out-of-scope Project target must be rejected")
print("ACP gateway package tests passed")
