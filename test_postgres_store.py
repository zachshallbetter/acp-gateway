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
        self.assertEqual([version for version, *_ in migration_files()], [1, 2])
        postgres_store.validate_schema()


if __name__ == "__main__":
    unittest.main()
