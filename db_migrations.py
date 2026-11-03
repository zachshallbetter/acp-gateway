"""Canonical manifest for ACP's versioned PostgreSQL migrations."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
MIGRATIONS = ROOT / "migrations"
MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_[a-z0-9_]+\.sql$")
MIGRATION_LOCK_KEY = 1094920193


class MigrationError(RuntimeError):
    pass


def migration_files() -> list[tuple[int, str, str, str]]:
    found = []
    for path in sorted(MIGRATIONS.glob("*.sql")):
        match = MIGRATION_NAME.fullmatch(path.name)
        if not match:
            raise MigrationError(f"unsupported migration filename: {path.name}")
        source = path.read_bytes()
        found.append((int(match.group("version")), path.name,
                      hashlib.sha256(source).hexdigest(), source.decode("utf-8")))
    versions = [entry[0] for entry in found]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError("migration versions must be contiguous and start at 0001")
    return found


def apply_migrations(connection, *, acquire_lock: bool = True) -> list[int]:
    """Apply the manifest inside the caller's transaction."""
    if acquire_lock:
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (MIGRATION_LOCK_KEY,))
    exists_row = connection.execute(
        "SELECT to_regclass('public.schema_migrations') IS NOT NULL AS present"
    ).fetchone()
    exists = exists_row["present"] if isinstance(exists_row, Mapping) else exists_row[0]
    applied = {}
    if exists:
        rows = connection.execute(
            "SELECT version, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        applied = ({row["version"]: row["checksum"] for row in rows}
                   if rows and isinstance(rows[0], Mapping) else dict(rows))

    available = migration_files()
    known = {version for version, *_ in available}
    if set(applied) - known:
        raise MigrationError("database contains a migration version absent from this release")
    applied_versions = sorted(applied)
    if applied_versions != [version for version, *_ in available[:len(applied_versions)]]:
        raise MigrationError("database migration history is not a contiguous prefix")

    pending = []
    for version, _name, checksum, sql in available:
        recorded = applied.get(version)
        if recorded is not None:
            if recorded.strip() != checksum:
                raise MigrationError(f"migration checksum mismatch at version {version:04d}")
            continue
        connection.execute(sql)
        connection.execute(
            "INSERT INTO schema_migrations (version, checksum, applied_at) "
            "VALUES (%s, %s, CURRENT_TIMESTAMP)",
            (version, checksum),
        )
        pending.append(version)
    return pending
