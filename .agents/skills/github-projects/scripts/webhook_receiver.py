#!/usr/bin/env python3
"""Signed GitHub webhook receiver with an authenticated local-supervisor spool."""
from __future__ import annotations
import argparse, hashlib, hmac, http.server, json, os, sqlite3, subprocess, threading, time
from github_app import GitHubApp
from pathlib import Path
from urllib.parse import parse_qs, urlparse

EVENT_VERSION = "github.coordinator.event.v1"
EVENTS = {"projects_v2", "projects_v2_item", "issues", "pull_request", "pull_request_review", "pull_request_review_comment", "pull_request_review_thread", "workflow_run", "issue_comment"}
MAX_BYTES, MAX_ATTEMPTS = 1_048_576, 3

def verify(secret: bytes, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="): return False
    return hmac.compare_digest("sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest(), header)

def db_open(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, check_same_thread=False)
    db.execute("PRAGMA journal_mode=WAL"); db.execute("PRAGMA busy_timeout=5000")
    db.execute("CREATE TABLE IF NOT EXISTS deliveries (delivery_id TEXT PRIMARY KEY, event_name TEXT NOT NULL, received_at INTEGER NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL, last_error TEXT)")
    db.execute("CREATE INDEX IF NOT EXISTS deliveries_ready ON deliveries(status, received_at, delivery_id)"); db.commit(); return db

def enqueue(db, delivery_id, event, payload):
    envelope = {"schema_version": EVENT_VERSION, "delivery_id": delivery_id, "event_name": event, "received_at": int(time.time()), "repository": payload.get("repository", {}).get("full_name"), "issue_number": payload.get("issue", {}).get("number"), "pull_request_number": payload.get("pull_request", {}).get("number"), "payload": payload}
    try:
        db.execute("INSERT INTO deliveries(delivery_id,event_name,received_at,status,payload) VALUES(?,?,?,?,?)", (delivery_id, event, envelope["received_at"], "queued", json.dumps(envelope, separators=(",", ":"), sort_keys=True))); db.commit(); return True
    except sqlite3.IntegrityError: db.rollback(); return False

class Handler(http.server.BaseHTTPRequestHandler):
    def _authorized(self):
        return hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + self.server.service.bridge_token)

    def do_GET(self):  # noqa: N802
        service = self.server.service
        if self.path == "/health":
            queued, processing = service.db.execute("SELECT COALESCE(SUM(status='queued'),0), COALESCE(SUM(status='processing'),0) FROM deliveries").fetchone()
            body = json.dumps({"status":"ok", "schema_version":EVENT_VERSION, "queued":int(queued), "processing":int(processing)}).encode(); self.send_response(200)
        elif self.path.startswith("/internal/deliveries") and self._authorized():
            limit = min(10, max(1, int(parse_qs(urlparse(self.path).query).get("limit", ["1"])[0])))
            rows = service.db.execute("SELECT delivery_id,payload FROM deliveries WHERE status='queued' ORDER BY received_at,delivery_id LIMIT ?", (limit,)).fetchall(); claimed = []
            for delivery, payload in rows:
                if service.db.execute("UPDATE deliveries SET status='processing',attempts=attempts+1 WHERE delivery_id=? AND status='queued'", (delivery,)).rowcount == 1: claimed.append(json.loads(payload))
            service.db.commit(); body = json.dumps({"schema_version":EVENT_VERSION, "deliveries":claimed}, separators=(",", ":")).encode(); self.send_response(200)
        elif self.path == "/internal/github-app-status" and self._authorized():
            body = json.dumps({"configured": service.github_app is not None, "installation_id": service.github_app.installation_id if service.github_app else None, "token_minting":"internal-only"}).encode(); self.send_response(200)
        else: self.send_error(401 if self.path.startswith("/internal/") else 404); return
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        service = self.server.service
        if self.path.startswith("/internal/deliveries/"):
            if not self._authorized(): self.send_error(401); return
            delivery = self.path.rsplit("/", 1)[-1]; length = int(self.headers.get("Content-Length", "-1")); body = self.rfile.read(length) if 0 <= length <= 4096 else b""
            try: status = json.loads(body or b"{}").get("status")
            except json.JSONDecodeError: status = None
            if status not in ("succeeded", "failed"): self.send_error(400); return
            target = "succeeded" if status == "succeeded" else "queued"
            service.db.execute("UPDATE deliveries SET status=?,last_error=? WHERE delivery_id=? AND status='processing'", (target, None if status == "succeeded" else "bridge failure", delivery)); service.db.commit(); self.send_response(204); self.end_headers(); return
        if self.path != "/github/webhook": self.send_error(404); return
        try: size = int(self.headers.get("Content-Length", "-1"))
        except ValueError: size = -1
        body = self.rfile.read(size) if 0 <= size <= MAX_BYTES else b""; event = self.headers.get("X-GitHub-Event", ""); delivery = self.headers.get("X-GitHub-Delivery", "")
        if not body or not delivery or event not in EVENTS or not verify(service.secret, body, self.headers.get("X-Hub-Signature-256")): self.send_error(401); return
        try: payload = json.loads(body)
        except json.JSONDecodeError: self.send_error(400); return
        if not isinstance(payload, dict): self.send_error(400); return
        result = json.dumps({"accepted": True, "duplicate": not enqueue(service.db, delivery, event, payload)}).encode(); self.send_response(202); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(result))); self.end_headers(); self.wfile.write(result)

    def log_message(self, fmt, *args): pass

class Server(http.server.ThreadingHTTPServer):
    def __init__(self, address, service): super().__init__(address, Handler); self.service = service

class Service:
    def __init__(self, path: Path, secret: str, bridge_token: str):
        if not secret or not bridge_token: raise ValueError("WEBHOOK_SECRET and COORDINATOR_BRIDGE_TOKEN are required")
        self.db, self.secret, self.bridge_token = db_open(path), secret.encode(), bridge_token
        app_id=os.getenv("ACP_GITHUB_APP_ID", ""); installation_id=os.getenv("ACP_GITHUB_INSTALLATION_ID", ""); private_key=os.getenv("ACP_GITHUB_PRIVATE_KEY", "")
        self.github_app = GitHubApp(app_id,installation_id,private_key) if any((app_id,installation_id,private_key)) else None
        if any((app_id,installation_id,private_key)) and self.github_app is None: raise ValueError("incomplete ACP GitHub App configuration")

    def run(self, host, port, command):
        server = Server((host, port), self); thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); print(f"receiver listening on {host}:{port}")
        try:
            while True:
                row = self.db.execute("SELECT delivery_id,payload,attempts FROM deliveries WHERE status='queued' ORDER BY received_at,delivery_id LIMIT 1").fetchone()
                if not row: time.sleep(3); continue
                delivery, payload, attempts = row
                if self.db.execute("UPDATE deliveries SET status='processing',attempts=attempts+1 WHERE delivery_id=? AND status='queued'", (delivery,)).rowcount != 1: self.db.commit(); continue
                self.db.commit()
                try: subprocess.run(command, check=True, timeout=120); status, error = "succeeded", None
                except Exception as exc: status, error = ("queued" if attempts + 1 < MAX_ATTEMPTS else "failed"), str(exc)[:500]
                self.db.execute("UPDATE deliveries SET status=?,last_error=? WHERE delivery_id=?", (status,error,delivery)); self.db.commit()
        finally: server.shutdown(); server.server_close(); self.db.close()

def main():
    p = argparse.ArgumentParser(); p.add_argument("--database", type=Path, default=Path(os.getenv("GP_WEBHOOK_DB", ".webhook-deliveries.sqlite3"))); p.add_argument("--secret", default=os.getenv("WEBHOOK_SECRET", "")); p.add_argument("--bridge-token", default=os.getenv("COORDINATOR_BRIDGE_TOKEN", "")); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080"))); p.add_argument("--serve-worker", action="store_true"); p.add_argument("--coordinator-command", nargs="+", default=["/app/coordinator-disabled"]); a=p.parse_args(); service=Service(a.database,a.secret,a.bridge_token)
    if a.serve_worker: service.run(a.host,a.port,a.coordinator_command)
    else: Server((a.host,a.port),service).serve_forever()

if __name__ == "__main__": main()
