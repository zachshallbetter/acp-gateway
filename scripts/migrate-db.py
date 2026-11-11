#!/usr/bin/env python3
"""Check or apply ACP's versioned PostgreSQL migrations.

The connection string comes from ACP_DATABASE_MIGRATION_URL and is never printed.

    scripts/migrate-db.py --check   read-only: report applied, pending and mismatched versions
    scripts/migrate-db.py           apply pending migrations in one serializable transaction

--check exits 0 when the database matches this release, 3 when migrations are pending,
and 1 when the recorded history conflicts with this release.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

if os.getenv("ACP_STORAGE_BACKEND", "postgres").strip().lower() != "postgres":
    raise SystemExit("scripts/migrate-db.py requires ACP_STORAGE_BACKEND=postgres")
os.environ["ACP_STORAGE_BACKEND"] = "postgres"

import psycopg

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from db_migrations import MigrationError, applied_history, apply_migrations, classify
import postgres_store


def check(dsn: str) -> dict:
    with psycopg.connect(postgres_store.secure_database_dsn(dsn), connect_timeout=5) as connection:
        connection.read_only = True
        return classify(applied_history(connection))


def apply(dsn: str) -> list[int]:
    with psycopg.connect(postgres_store.secure_database_dsn(dsn), connect_timeout=5) as connection:
        with connection.transaction():
            connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            return apply_migrations(connection)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report migration state without writing")
    args = parser.parse_args()
    dsn = os.getenv("ACP_DATABASE_MIGRATION_URL", "").strip()
    if not dsn:
        print("ACP_DATABASE_MIGRATION_URL is required; it names the database to check or migrate",
              file=sys.stderr)
        return 2
    try:
        if args.check:
            report = check(dsn)
            print(json.dumps(report, sort_keys=True))
            return {"current": 0, "pending": 3}.get(report["status"], 1)
        applied = apply(dsn)
    except MigrationError as exc:
        print(f"Migration refused: {exc}", file=sys.stderr)
        return 1
    except psycopg.Error as exc:
        state = getattr(exc, "sqlstate", None)
        detail = f" (SQLSTATE {state})" if state else ""
        print(f"Database {'check' if args.check else 'migration'} failed{detail}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError) as exc:
        print(f"Migration files could not be read ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps({"applied_versions": [f"{version:04d}" for version in applied],
                      "status": "ok"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
