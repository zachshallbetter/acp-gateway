"""Exercise the recovery runtime against a disposable local PostgreSQL database.

ACP_TEST_DATABASE_URL must name a loopback database ending in _test. The caller
creates that database; this script applies only this release's migrations.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
import json
import os
import threading
import time
import unittest
from urllib.error import HTTPError
import uuid
from urllib.request import urlopen

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

DSN = os.getenv("ACP_TEST_DATABASE_URL", "").strip()
if not DSN:
    raise SystemExit("ACP_TEST_DATABASE_URL is required; no database tests were run")
target = conninfo_to_dict(DSN)
if (not target.get("dbname", "").endswith("_test")
        or target.get("host") not in ("localhost", "127.0.0.1", "::1")
        or target.get("hostaddr") not in (None, "127.0.0.1", "::1")
        or target.get("service")):
    raise SystemExit("Database tests require an explicit loopback host and a _test database")

# Never inherit a real policy, credential, notification destination, or file store.
for key in list(os.environ):
    if key.startswith("ACP_") or key == "VERCEL":
        del os.environ[key]
os.environ.update({
    "ACP_STORAGE_BACKEND": "postgres", "ACP_DATABASE_URL": DSN,
    "ACP_AUDIT_HASH_CHAIN": "1", "ACP_GATEWAY_TOKEN": "synthetic-test-bearer",
    "ACP_CAPABILITY_SIGNING_KEY": "synthetic-test-capability-signing-key",
})

import gateway
import postgres_store
from db_migrations import apply_migrations, migration_files


class PostgresStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with psycopg.connect(DSN) as connection:
            apply_migrations(connection)
        postgres_store.validate_schema()

    @classmethod
    def tearDownClass(cls):
        postgres_store.close_pool()

    def test_migrations_are_repeatable_and_checksum_drift_is_refused(self):
        with psycopg.connect(DSN, row_factory=dict_row) as connection:
            self.assertEqual(apply_migrations(connection), [])
            connection.execute("UPDATE schema_migrations SET checksum=%s WHERE version=1", ("0" * 64,))
            with self.assertRaisesRegex(postgres_store.StorageError, "migration history"):
                postgres_store._validate_schema_connection(connection)
            connection.rollback()
        postgres_store.validate_schema()

    def test_state_and_audit_rollback_together(self):
        key = "resource:synthetic/rollback"
        with postgres_store.transaction() as store:
            before = store.audit_count()
        with self.assertRaisesRegex(RuntimeError, "synthetic rollback"):
            with postgres_store.transaction():
                gateway.write_security([key], time.time(), authorization_state="LOCKED",
                                       security_version=1, reason="synthetic fixture")
                gateway.note_event([key], time.time(), "LOCKED_ENTERED")
                raise RuntimeError("synthetic rollback")
        with postgres_store.transaction() as store:
            self.assertIsNone(gateway.security_record([key]))
            self.assertEqual(store.audit_count(), before)

    def test_containment_trust_and_audit_survive_reconnection(self):
        key = "resource:synthetic/reconnect"
        with postgres_store.transaction():
            gateway.write_security([key], time.time(), authorization_state="LOCKED",
                                   security_version=2, reason="synthetic fixture")
            gateway.remember_trust("synthetic/reconnect", installed=True, verified_at=time.time())
            gateway.note_event([key], time.time(), "LOCKED_ENTERED")
        postgres_store.close_pool()
        with postgres_store.transaction() as store:
            self.assertEqual(gateway.security_record([key])["authorization_state"], "LOCKED")
            self.assertTrue(postgres_store.TRUST_STATE.get("synthetic/reconnect")["installed"])
            self.assertTrue(gateway.verify_audit_chain(store.audit_chain_batches())["valid"])
            self.assertGreater(store.audit_head()[0], 0)

    def test_concurrent_capability_consumption_commits_once(self):
        keys = ["resource:synthetic/replay", "actor:synthetic-actor"]
        jti = f"synthetic-concurrent-capability-{uuid.uuid4().hex}"
        barrier = threading.Barrier(2)
        now = time.time()

        def consume():
            try:
                with postgres_store.transaction() as store:
                    barrier.wait(timeout=5)
                    store.consume_capability(keys, jti, now, now + 60)
                return "committed"
            except postgres_store.StorageError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: consume(), range(2)))
        self.assertEqual(sorted(results), ["committed", "refused"])
        with postgres_store.transaction() as store:
            self.assertTrue(store.capability_consumed(keys, jti, now))

    def _ledger_row(self, key, sha, now, request_id=None):
        return {"record_key": key, "request_id": request_id or uuid.uuid4().hex, "action": "hosted_build",
                "provider": "vercel", "resource_owner": "synthetic", "resource_name": "metered",
                "ref": "refs/heads/feature", "sha": sha, "caller_kind": "lane", "caller_id": "lane-a",
                "reason": "synthetic budget test", "reason_code": "WITHIN_BUDGET", "counted": True,
                "budget_day": time.strftime("%Y-%m-%d", time.gmtime(now)), "grant_id": None,
                "evidence_digest": None, "created_at": now}

    def test_metered_record_is_written_once_and_counted(self):
        now = time.time()
        key = uuid.uuid4().hex + uuid.uuid4().hex
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        with postgres_store.transaction() as store:
            before = store.ledger_count(day, ["hosted_build"], owner="Synthetic", name="Metered")
            store.ledger_insert(self._ledger_row(key, "d" * 40, now))
        with self.assertRaises(postgres_store.StorageError):
            with postgres_store.transaction() as store:
                store.ledger_insert(self._ledger_row(key, "d" * 40, now))
        with postgres_store.transaction() as store:
            self.assertEqual(store.ledger_get(key)["reason_code"], "WITHIN_BUDGET")
            self.assertEqual(store.ledger_count(day, ["hosted_build"], owner="Synthetic", name="Metered"),
                             before + 1)

    def test_ledger_constraints_refuse_inconsistent_rows(self):
        now = time.time()
        for change in ({"reason_code": "NO_HOSTED_BUILD"}, {"sha": "not-a-sha"}, {"reason": "short"},
                       {"resource_name": None}, {"grant_id": "g-0000000000000000"}):
            with self.subTest(change=change):
                row = {**self._ledger_row(uuid.uuid4().hex + uuid.uuid4().hex, "e" * 40, now), **change}
                with self.assertRaises(postgres_store.StorageError):
                    with postgres_store.transaction() as store:
                        store.ledger_insert(row)

    def test_last_budget_slot_is_taken_once_under_concurrency(self):
        import metering
        now = time.time()
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        owner = f"race-{uuid.uuid4().hex[:8]}"
        barrier = threading.Barrier(2)

        def take(index):
            try:
                with postgres_store.transaction() as store:
                    used = store.ledger_count(day, ["hosted_build"], owner=owner, name="repo")
                    barrier.wait(timeout=5)
                    if used >= 1:
                        return "over"
                    row = self._ledger_row(metering.record_key("race", owner, index), str(index) * 40, now)
                    store.ledger_insert({**row, "resource_owner": owner, "resource_name": "repo"})
                return "committed"
            except postgres_store.StorageError:
                return "refused"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = sorted(executor.map(take, range(2)))
        self.assertEqual(results.count("committed"), 1, results)
        with postgres_store.transaction() as store:
            self.assertEqual(store.ledger_count(day, ["hosted_build"], owner=owner, name="repo"), 1)

    def test_grant_uses_and_lease_release(self):
        now = time.time()
        grant_id = "g-" + uuid.uuid4().hex[:16]
        with postgres_store.transaction() as store:
            store.grant_issue({"grant_id": grant_id, "action": "production_merge", "resource_owner": "synthetic",
                               "resource_name": "granted", "uses_total": 1, "uses_left": 1, "issued_at": now,
                               "expires_at": now + 600, "issued_by": "owner", "reason": "synthetic release"})
        with postgres_store.transaction() as store:
            self.assertEqual(store.grant_take("production_merge", "Synthetic", "Granted", now), grant_id)
        with postgres_store.transaction() as store:
            self.assertIsNone(store.grant_take("production_merge", "synthetic", "granted", now))
        lease = uuid.uuid4().hex + uuid.uuid4().hex
        session = "session-" + uuid.uuid4().hex[:8]
        with postgres_store.transaction() as store:
            store.lease_open({"lease_key": lease, "session_id": session, "model": "claude-opus-5-5",
                              "reason": "synthetic heavy work", "opened_at": now, "expires_at": now + 7200})
            self.assertEqual(store.leases_open(session, now), 1)
        with postgres_store.transaction() as store:
            self.assertTrue(store.lease_release(lease, now + 1))
            self.assertFalse(store.lease_release(lease, now + 2))
            self.assertEqual(store.leases_open(session, now + 3), 0)

    def test_provider_snapshot_latest_wins(self):
        now = time.time()
        subject = "synthetic/" + uuid.uuid4().hex[:8]
        with postgres_store.transaction() as store:
            store.snapshot_put("vercel", subject, "1" * 64, {"vercel": [{"name": "old"}]}, now - 60)
            store.snapshot_put("vercel", subject, "2" * 64, {"vercel": [{"name": "new"}]}, now)
        with postgres_store.transaction() as store:
            body, fetched = store.snapshot_latest("vercel", subject)
            self.assertEqual(body["vercel"][0]["name"], "new")
            self.assertAlmostEqual(fetched, now, delta=1)

    def test_readiness_refuses_missing_schema_without_losing_liveness(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urlopen(base + "/ready", timeout=5) as response:
                self.assertEqual(json.load(response), {"status": "ready", "storage": "postgres"})
            with psycopg.connect(DSN) as connection:
                connection.execute("ALTER TABLE schema_migrations RENAME TO synthetic_missing_migrations")
            try:
                with self.assertRaises(HTTPError) as caught:
                    urlopen(base + "/ready", timeout=10)
                self.assertEqual(caught.exception.code, 503)
                self.assertEqual(json.load(caught.exception),
                                 {"status": "not_ready", "storage": "unavailable"})
                with urlopen(base + "/health", timeout=5) as response:
                    self.assertEqual(json.load(response)["status"], "ok")
            finally:
                with psycopg.connect(DSN) as connection:
                    connection.execute("ALTER TABLE synthetic_missing_migrations RENAME TO schema_migrations")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual([version for version, *_ in migration_files()], [1, 2, 3])
        postgres_store.validate_schema()


if __name__ == "__main__":
    unittest.main()
