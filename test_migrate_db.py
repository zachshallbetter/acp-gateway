"""Exercise scripts/migrate-db.py against a disposable local PostgreSQL database.

ACP_TEST_DATABASE_URL must name a loopback database ending in _test. Each test
creates and drops its own database beside it, so the caller's database is untouched.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

DSN = os.getenv("ACP_TEST_DATABASE_URL", "").strip()
if not DSN:
    raise SystemExit("ACP_TEST_DATABASE_URL is required; no database tests were run")
target = conninfo_to_dict(DSN)
if (not target.get("dbname", "").endswith("_test")
        or target.get("host") not in ("localhost", "127.0.0.1", "::1")
        or target.get("service")):
    raise SystemExit("Database tests require an explicit loopback host and a _test database")

ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "scripts" / "migrate-db.py"


class MigrateDbTests(unittest.TestCase):
    def setUp(self):
        self.dbname = f"acp_migrate_{uuid.uuid4().hex[:8]}_test"
        with psycopg.connect(DSN, autocommit=True) as connection:
            connection.execute(f'CREATE DATABASE "{self.dbname}"')
        self.url = make_conninfo(DSN, dbname=self.dbname)

    def tearDown(self):
        with psycopg.connect(DSN, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{self.dbname}" WITH (FORCE)')

    def run_script(self, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACP_")}
        env["ACP_DATABASE_MIGRATION_URL"] = self.url
        cp = subprocess.run([sys.executable, str(SCRIPT), *args], cwd=ROOT, env=env,
                            capture_output=True, text=True)
        self.assertNotIn(self.url, cp.stdout + cp.stderr, "the connection string is never printed")
        return cp

    def test_check_reports_pending_without_writing(self):
        cp = self.run_script("--check")
        self.assertEqual(cp.returncode, 3, cp.stderr)
        report = json.loads(cp.stdout)
        self.assertEqual(report["status"], "pending")
        self.assertEqual(report["applied_versions"], [])
        self.assertEqual(report["pending_versions"], ["0001", "0002", "0003", "0004"])
        with psycopg.connect(self.url) as connection:
            self.assertIsNone(connection.execute(
                "SELECT to_regclass('public.schema_migrations')").fetchone()[0])

    def test_apply_then_check_is_current_and_reapply_is_a_no_op(self):
        first = self.run_script()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["applied_versions"], ["0001", "0002", "0003", "0004"])
        again = self.run_script()
        self.assertEqual(json.loads(again.stdout)["applied_versions"], [])
        cp = self.run_script("--check")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(json.loads(cp.stdout)["status"], "current")

    def test_check_flags_a_checksum_conflict(self):
        self.assertEqual(self.run_script().returncode, 0)
        with psycopg.connect(self.url) as connection:
            connection.execute("UPDATE schema_migrations SET checksum = %s WHERE version = 1", ("0" * 64,))
        cp = self.run_script("--check")
        self.assertEqual(cp.returncode, 1)
        report = json.loads(cp.stdout)
        self.assertEqual((report["status"], report["checksum_mismatch_versions"]), ("conflict", ["0001"]))
        refused = self.run_script()
        self.assertEqual(refused.returncode, 1)
        self.assertIn("checksum mismatch", refused.stderr)

    def test_missing_url_names_the_setting(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ACP_")}
        cp = subprocess.run([sys.executable, str(SCRIPT), "--check"], cwd=ROOT, env=env,
                            capture_output=True, text=True)
        self.assertEqual(cp.returncode, 2)
        self.assertIn("ACP_DATABASE_MIGRATION_URL", cp.stderr)


if __name__ == "__main__":
    unittest.main()
