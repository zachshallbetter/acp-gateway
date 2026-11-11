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
# The first line of a migration that only adds. Reviewed like the SQL under it: the claim is what
# lets a release that does not ship the migration keep running on a database that has it.
ADDITIVE_MARKER = "-- acp-migration: additive"


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


def is_additive(sql: str) -> bool:
    first = next((line.strip() for line in sql.splitlines() if line.strip()), "")
    return first == ADDITIVE_MARKER


def _row(row, key, index):
    return row[key] if isinstance(row, Mapping) else row[index]


def applied_history(connection) -> dict[int, tuple[str, bool]] | None:
    """{version: (checksum, additive)} as the database records it, or None with no history table."""
    present = _row(connection.execute(
        "SELECT to_regclass('public.schema_migrations') IS NOT NULL AS present").fetchone(), "present", 0)
    if not present:
        return None
    has_flag = _row(connection.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' "
        "AND table_name = 'schema_migrations' AND column_name = 'additive') AS present").fetchone(), "present", 0)
    rows = connection.execute(
        "SELECT version, trim(checksum) AS checksum" + (", additive" if has_flag else ", false AS additive")
        + " FROM schema_migrations ORDER BY version").fetchall()
    return {_row(r, "version", 0): (_row(r, "checksum", 1), bool(_row(r, "additive", 2))) for r in rows}


def classify(applied: dict[int, tuple[str, bool]] | None) -> dict:
    """How a database's migration history relates to this release. The one resolver for it.

    current: every migration this release ships is applied, unchanged; any newer ones are all
    additive (listed in ahead_additive_versions) -- this release can run.
    pending: some of this release's migrations are not applied yet.
    conflict: a checksum differs, the history has a gap, or a newer migration is not additive.
    """
    applied = applied or {}
    available = migration_files()
    expected = {version: checksum for version, _name, checksum, _sql in available}
    mismatched = sorted(v for v, (c, _a) in applied.items() if v in expected and c != expected[v])
    newer = sorted(set(applied) - set(expected))
    pending = sorted(set(expected) - set(applied))
    gap = bool(applied) and sorted(applied) != list(range(1, max(applied) + 1))
    ahead_ok = [v for v in newer if applied[v][1]]
    blocking = [v for v in newer if not applied[v][1]]
    if newer and pending:
        blocking = newer                             # a newer migration on top of a missing one is never ours to run
    status = "conflict" if mismatched or gap or blocking else ("pending" if pending else "current")
    fmt = lambda versions: [f"{v:04d}" for v in versions]
    return {"status": status, "applied_versions": fmt(sorted(applied)), "pending_versions": fmt(pending),
            "checksum_mismatch_versions": fmt(mismatched), "unknown_versions": fmt(blocking),
            "ahead_additive_versions": fmt([] if blocking else ahead_ok), "history_has_gap": gap}


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
        has_flag = _row(connection.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' "
            "AND table_name = 'schema_migrations' AND column_name = 'additive') AS present").fetchone(),
            "present", 0)
        if has_flag:
            connection.execute(
                "INSERT INTO schema_migrations (version, checksum, applied_at, additive) "
                "VALUES (%s, %s, CURRENT_TIMESTAMP, %s)", (version, checksum, is_additive(sql)))
        else:
            connection.execute(
                "INSERT INTO schema_migrations (version, checksum, applied_at) "
                "VALUES (%s, %s, CURRENT_TIMESTAMP)", (version, checksum))
        pending.append(version)
    return pending
