"""Exercise scripts/vercel-build.py against a disposable local PostgreSQL database.

ACP_TEST_DATABASE_URL must name a loopback database ending in _test. Each test
creates and drops its own database beside it.
"""
from __future__ import annotations

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
SCRIPT = ROOT / "scripts" / "vercel-build.py"


class VercelBuildTests(unittest.TestCase):
    def setUp(self):
        self.dbname = f"acp_build_{uuid.uuid4().hex[:8]}_test"
        with psycopg.connect(DSN, autocommit=True) as connection:
            connection.execute(f'CREATE DATABASE "{self.dbname}"')
        self.url = make_conninfo(DSN, dbname=self.dbname)

    def tearDown(self):
        with psycopg.connect(DSN, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{self.dbname}" WITH (FORCE)')

    def build(self, vercel_env, url=None):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("ACP_") and k not in ("VERCEL", "VERCEL_ENV", "POSTGRES_URL", "DATABASE_URL")}
        if vercel_env:
            env.update(VERCEL="1", VERCEL_ENV=vercel_env)
        if url:
            env["ACP_DATABASE_URL"] = url
        cp = subprocess.run([sys.executable, str(SCRIPT)], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertNotIn(self.url, cp.stdout + cp.stderr, "the database URL is never printed")
        return cp

    def test_preview_build_migrates_an_empty_database(self):
        cp = self.build("preview", self.url)
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn('"applied_versions": ["0001", "0002"]', cp.stdout)
        self.assertIn('"status": "current"', cp.stdout)
        again = self.build("preview", self.url)
        self.assertEqual(again.returncode, 0)
        self.assertIn('"status": "current"', again.stdout)
        self.assertNotIn("preview migrate", again.stdout, "a current database is not migrated again")

    def test_production_build_fails_when_migrations_are_pending_and_writes_nothing(self):
        cp = self.build("production", self.url)
        self.assertEqual(cp.returncode, 1)
        self.assertIn("production database is pending", cp.stdout)
        self.assertIn("ACP-authorized", cp.stdout)
        with psycopg.connect(self.url) as connection:
            self.assertIsNone(connection.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0])

    def test_production_build_passes_on_a_current_database(self):
        self.assertEqual(self.build("preview", self.url).returncode, 0)
        cp = self.build("production", self.url)
        self.assertEqual(cp.returncode, 0, cp.stdout)
        self.assertIn('"status": "current"', cp.stdout)

    def test_preview_build_explains_a_database_migrated_by_another_release_and_writes_nothing(self):
        self.assertEqual(self.build("preview", self.url).returncode, 0)
        with psycopg.connect(self.url) as connection:
            connection.execute("INSERT INTO schema_migrations (version, checksum, applied_at) "
                               "VALUES (3, %s, CURRENT_TIMESTAMP)", ("a" * 64,))
        cp = self.build("preview", self.url)
        self.assertEqual(cp.returncode, 1)
        self.assertIn("migrated by a different release", cp.stdout)
        self.assertIn("versions this release does not ship: 0003", cp.stdout)
        self.assertIn("Reset the Preview database branch", cp.stdout)
        with psycopg.connect(self.url) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0], 3)

    def test_missing_database_url_fails_the_build_and_local_runs_are_skipped(self):
        cp = self.build("production")
        self.assertEqual(cp.returncode, 1)
        self.assertIn("no database URL", cp.stdout)
        local = self.build(None, self.url)
        self.assertEqual(local.returncode, 0)
        self.assertIn("database step skipped", local.stdout)


if __name__ == "__main__":
    unittest.main()
