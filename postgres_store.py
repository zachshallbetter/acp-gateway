"""Bounded PostgreSQL state and audit storage for ACP runtime instances.

Database mode is explicit and never falls back to local files. Callers must
open one request transaction before accessing the state mapping or audit APIs.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import atexit
import json
import os
from pathlib import Path
import re
import threading

import certifi
from db_migrations import migration_files


class StorageError(RuntimeError):
    """A storage operation failed; protected decisions must fail closed."""


_VERCEL_RUNTIME = bool(os.getenv("VERCEL"))
_BACKEND = os.getenv("ACP_STORAGE_BACKEND", "postgres" if _VERCEL_RUNTIME else "file").strip().lower()
if _BACKEND not in ("file", "postgres"):
    raise StorageError("ACP_STORAGE_BACKEND must be file or postgres")
if _VERCEL_RUNTIME and _BACKEND != "postgres":
    raise StorageError("Vercel requires PostgreSQL storage; file-backed authority is not supported")
if _BACKEND == "postgres":
    try:
        import psycopg
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool
    except ImportError as exc:
        raise StorageError("PostgreSQL storage dependencies are not installed") from exc
else:
    psycopg = None
    dict_row = None
    ConnectionPool = None

_POOL: ConnectionPool | None = None
_POOL_LOCK = threading.Lock()
_ACTIVE: ContextVar["PostgresStore | None"] = ContextVar("acp_postgres_store", default=None)
_SUBJECT_KEY = re.compile(r"^(resource|actor):(.+)$")
MAX_STATE_ROWS = 5000
MAX_AUDIT_BATCH = 200


def enabled() -> bool:
    return _BACKEND == "postgres"


def database_configured() -> bool:
    return any(os.getenv(name, "").strip()
               for name in ("ACP_DATABASE_URL", "POSTGRES_URL", "DATABASE_URL"))


def _positive_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise StorageError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise StorageError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _database_dsn() -> str:
    dsn = (os.getenv("ACP_DATABASE_URL", "").strip()
           or os.getenv("POSTGRES_URL", "").strip()
           or os.getenv("DATABASE_URL", "").strip())
    if not dsn:
        raise StorageError("ACP_DATABASE_URL or a supported PostgreSQL integration URL is required")
    return secure_database_dsn(dsn)


def secure_database_dsn(dsn: str) -> str:
    """Require hostname-verified TLS with an explicit CA trust bundle."""
    parsed_dsn = psycopg.conninfo.conninfo_to_dict(dsn)
    host = parsed_dsn.get("host", "")
    local_host = not host or host in ("localhost", "127.0.0.1", "::1") or host.startswith("/")
    if not local_host:
        # Provider integration URLs commonly default to sslmode=require.
        # Upgrade those connections to hostname-verifying TLS instead of
        # accepting weaker TLS or requiring manual URL edits. Serverless
        # runtimes may lack system CA roots, so use a maintained bundle unless
        # an operator supplied a private trust bundle.
        dsn = psycopg.conninfo.make_conninfo(
            dsn,
            sslmode="verify-full",
            sslrootcert=parsed_dsn.get("sslrootcert") or certifi.where(),
        )
    return dsn


def _pool() -> ConnectionPool:
    global _POOL
    if not enabled():
        raise StorageError("PostgreSQL storage is not enabled")
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                dsn = _database_dsn()
                # Serverless instances multiply at platform scale-out. Keep one
                # database connection per warm Vercel instance unless an
                # operator explicitly budgets a larger global pool.
                default_maximum = 1 if _VERCEL_RUNTIME else 2
                maximum_limit = 2 if _VERCEL_RUNTIME else 4
                maximum = _positive_int("ACP_DATABASE_POOL_MAX", default_maximum, 1, maximum_limit)
                timeout = _positive_int("ACP_DATABASE_TIMEOUT_SECONDS", 5, 1, 15)
                _POOL = ConnectionPool(
                    conninfo=dsn,
                    min_size=0,
                    max_size=maximum,
                    max_waiting=maximum * 2,
                    timeout=timeout,
                    kwargs={
                        "connect_timeout": timeout,
                        "row_factory": dict_row,
                    },
                    open=True,
                )
    return _POOL


def validate_schema() -> None:
    """Require exact migration history before serving database-backed state."""
    try:
        with _pool().connection(timeout=5) as connection:
            _set_transaction_limits(connection)
            _validate_schema_connection(connection)
    except StorageError:
        raise
    except (psycopg.Error, OSError) as exc:
        state = getattr(exc, "sqlstate", None)
        detail = f" SQLSTATE {state}" if state else ""
        raise StorageError("database schema validation failed" + detail) from exc


def close_pool() -> None:
    global _POOL
    if _POOL is not None:
        _POOL.close()
        _POOL = None


@contextmanager
def transaction():
    """Open a bounded serializable request transaction and bind its unit of work."""
    if not enabled():
        yield None
        return
    if _ACTIVE.get() is not None:
        raise StorageError("nested ACP storage transactions are not supported")
    try:
        with _pool().connection(timeout=5) as connection:
            with connection.transaction():
                connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                _set_transaction_limits(connection)
                _validate_schema_connection(connection)
                store = PostgresStore(connection)
                token = _ACTIVE.set(store)
                try:
                    yield store
                finally:
                    _ACTIVE.reset(token)
        store.run_after_commit()
    except StorageError:
        raise
    except psycopg.Error as exc:
        state = getattr(exc, "sqlstate", None)
        detail = f" SQLSTATE {state}" if state else ""
        raise StorageError("database transaction failed" + detail) from exc


def _set_transaction_limits(connection) -> None:
    """Set bounded per-transaction timeouts compatible with PgBouncer."""
    connection.execute("SET LOCAL statement_timeout = '5000ms'")
    connection.execute("SET LOCAL lock_timeout = '1500ms'")
    connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10000ms'")


def current() -> "PostgresStore":
    store = _ACTIVE.get()
    if store is None:
        raise StorageError("database state accessed outside a request transaction")
    return store


def _validate_schema_connection(connection) -> None:
    available = migration_files()
    recorded = connection.execute(
        "SELECT version, checksum FROM schema_migrations ORDER BY version"
    ).fetchall()
    expected = [(version, digest) for version, _name, digest, _sql in available]
    actual = [(row["version"], row["checksum"].strip()) for row in recorded]
    if actual != expected:
        raise StorageError("database migration history does not match this release")
    head = connection.execute(
        "SELECT chain_id FROM audit_chain_heads WHERE chain_id = 'primary'"
    ).fetchone()
    if head is None:
        raise StorageError("database audit-chain head is not initialized")


def _timestamp(value, *, default_now=False):
    if value is None:
        return datetime.now(timezone.utc) if default_now else None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (float, int)):
        return datetime.fromtimestamp(value, timezone.utc)
    if isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise StorageError("stored timestamp has an invalid format") from exc
    raise StorageError("stored timestamp has an unsupported type")


def _epoch(value):
    parsed = _timestamp(value)
    return parsed.timestamp() if parsed else None


def _iso(value):
    parsed = _timestamp(value)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ") if parsed else None


def _json(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _subject(key: str) -> tuple[str, str]:
    match = _SUBJECT_KEY.fullmatch(key)
    if not match:
        raise StorageError("unsupported security-state key")
    kind, subject_id = match.groups()
    if kind == "resource" and "/" not in subject_id:
        raise StorageError("resource state key has no owner/name")
    return kind, subject_id


def _resource(subject_kind: str, subject_id: str) -> tuple[str, str] | None:
    if subject_kind != "resource":
        return None
    owner, name = subject_id.split("/", 1)
    return owner, name


class PostgresStore:
    def __init__(self, connection):
        self.connection = connection
        self._cache: dict[str, dict | None] = {}
        self._dirty: set[str] = set()
        self._callbacks = []

    def after_commit(self, callback):
        self._callbacks.append(callback)

    def run_after_commit(self):
        for callback in self._callbacks:
            callback()

    def get_state(self, key: str):
        if key in self._cache:
            return self._cache[key]
        if key.startswith("incident:"):
            record = self._load_incident(key[len("incident:"):])
        elif key == "chain:head":
            row = self.connection.execute(
                "SELECT sequence, head_hash FROM audit_chain_heads WHERE chain_id = 'primary'"
            ).fetchone()
            record = {"hash": row["head_hash"], "sequence": row["sequence"]} if row else None
        else:
            record = self._load_subject(key)
        self._cache[key] = record
        return record

    def mark_dirty(self, key: str) -> None:
        if key in self._cache and key != "chain:head":
            self._dirty.add(key)

    def set_state(self, key: str, value: dict) -> None:
        if not isinstance(value, dict):
            raise StorageError("security-state values must be objects")
        if key.startswith("incident:"):
            self._cache[key] = value
        elif key == "chain:head":
            raise StorageError("audit chain heads are updated only with an audit event")
        else:
            _subject(key)
            self._cache[key] = value
        self._dirty.add(key)

    def items(self):
        rows = self.connection.execute(
            "SELECT * FROM security_state ORDER BY subject_kind, subject_id LIMIT %s",
            (MAX_STATE_ROWS + 1,)
        ).fetchall()
        if len(rows) > MAX_STATE_ROWS:
            raise StorageError("security-state scan exceeds the configured bound")
        incidents = self.connection.execute(
            "SELECT * FROM incidents ORDER BY incident_id LIMIT %s",
            (MAX_STATE_ROWS + 1,)
        ).fetchall()
        if len(incidents) > MAX_STATE_ROWS:
            raise StorageError("incident scan exceeds the configured bound")
        keys = [f"{row['subject_kind']}:{row['subject_id']}" for row in rows]
        keys.extend("incident:" + row["incident_id"] for row in incidents)
        self._load_subject_rows(rows)
        for row in incidents:
            key = "incident:" + row["incident_id"]
            self._cache.setdefault(key, self._decode_incident(row))
        return [(key, self._cache[key]) for key in keys]

    def prefetch(self, keys):
        missing = []
        for key in keys:
            if key not in self._cache and not key.startswith("incident:"):
                missing.append(key)
        if missing:
            subjects = [_subject(key) for key in missing]
            rows = self.connection.execute(
                "SELECT * FROM security_state WHERE (subject_kind, subject_id) "
                "IN (SELECT * FROM unnest(%s::text[], %s::text[]))",
                ([kind for kind, _ in subjects], [subject_id for _, subject_id in subjects])
            ).fetchall()
            self._load_subject_rows(rows)
            for key in missing:
                self._cache.setdefault(key, None)

    def _load_subject_rows(self, rows):
        if not rows:
            return
        subjects = [(row["subject_kind"], row["subject_id"]) for row in rows]
        kinds, ids = [item[0] for item in subjects], [item[1] for item in subjects]
        records = {}
        resource_pairs = []
        for row in rows:
            kind, subject_id = row["subject_kind"], row["subject_id"]
            key = f"{kind}:{subject_id}"
            record = {"key": key, "authorization_state": row["authorization_state"],
                      "trust_state": row["trust_state"], "security_version": row["security_version"],
                      "violations": row["violations"], "attempts": row["attempts"],
                      "incident_id": row["incident_id"], "reason": row["reason"],
                      "opened_at": _epoch(row["opened_at"]), "updated_at": _epoch(row["updated_at"]),
                      "cleared_at": _epoch(row["cleared_at"])}
            snapshot = row["state_snapshot"]
            if isinstance(snapshot, str):
                snapshot = json.loads(snapshot)
            if not isinstance(snapshot, dict) or snapshot.get("version") != 1:
                raise StorageError("security-state snapshot has an unsupported version")
            for field in ("recovery", "consumed"):
                if field in snapshot:
                    record[field] = snapshot[field]
            if row["expected_ref"] is not None:
                record["expected_target"] = {"ref": row["expected_ref"], "sha": row["expected_sha"],
                                              "authorization_id": row["recovery_authorization_id"]}
            records[(kind, subject_id)] = record
            resource = _resource(kind, subject_id)
            if resource:
                resource_pairs.append(resource)
        if resource_pairs:
            owners, names = [pair[0] for pair in resource_pairs], [pair[1] for pair in resource_pairs]
            pair_sql = ("JOIN unnest(%s::text[], %s::text[]) AS requested(resource_owner,resource_name) "
                        "USING (resource_owner, resource_name)")
            counters = self.connection.execute(
                "SELECT subject_kind,subject_id,counter_name,counter_value FROM security_counters "
                "WHERE (subject_kind,subject_id) IN (SELECT * FROM unnest(%s::text[],%s::text[])) "
                "ORDER BY subject_kind,subject_id,counter_name", (kinds, ids)
            ).fetchall()
            signals = self.connection.execute(
                "SELECT subject_kind,subject_id,signal FROM security_signals "
                "WHERE (subject_kind,subject_id) IN (SELECT * FROM unnest(%s::text[],%s::text[])) "
                "ORDER BY subject_kind,subject_id,signal", (kinds, ids)
            ).fetchall()
            for item in counters:
                records[(item["subject_kind"], item["subject_id"])].setdefault("counters", {})[
                    item["counter_name"]] = item["counter_value"]
            for item in signals:
                records[(item["subject_kind"], item["subject_id"])].setdefault("signals", []).append(item["signal"])
            baseline = self.connection.execute(
                "SELECT resource_owner,resource_name,path,sha256,authorization_id,authorized_by,advanced_at "
                "FROM artifact_baselines " + pair_sql + " ORDER BY resource_owner,resource_name,path",
                (owners, names)
            ).fetchall()
            for item in baseline:
                rec = records[("resource", item["resource_owner"] + "/" + item["resource_name"])]
                rec.setdefault("baseline", {})[item["path"]] = {
                    "sha256": item["sha256"].strip(), "authorization_id": item["authorization_id"],
                    "authorized_by": item["authorized_by"], "at": _epoch(item["advanced_at"])}
            grants = self.connection.execute(
                "SELECT * FROM artifact_change_grants " + pair_sql +
                "WHERE expires_at > CURRENT_TIMESTAMP ORDER BY resource_owner,resource_name,path LIMIT %s",
                (owners, names, MAX_STATE_ROWS + 1)
            ).fetchall()
            if len(grants) > MAX_STATE_ROWS:
                raise StorageError("artifact-grant scan exceeds the configured bound")
            for item in grants:
                rec = records[("resource", item["resource_owner"] + "/" + item["resource_name"])]
                rec.setdefault("artifact_grants", {})[item["authorization_id"]] = {
                    "authorization_id": item["authorization_id"], "artifact": item["path"],
                    "expected_old_sha256": item["expected_sha256"].strip() if item["expected_sha256"] else None,
                    "authorized_new_sha256": item["authorized_sha256"].strip(),
                    "authorized_by": item["authorized_by"], "expires_at": _epoch(item["expires_at"]),
                    "single_use": True, "consumed": item["consumed_at"] is not None,
                    "consumed_at": _epoch(item["consumed_at"])}
            snapshots = self.connection.execute(
                "SELECT DISTINCT ON (resource_owner,resource_name) resource_owner,resource_name,snapshot_id,"
                "status,unresolved,checked_at,checkpoint,evidence FROM integrity_snapshots " + pair_sql +
                "ORDER BY resource_owner,resource_name,checked_at DESC LIMIT %s",
                (owners, names, MAX_STATE_ROWS + 1)
            ).fetchall()
            if len(snapshots) > MAX_STATE_ROWS:
                raise StorageError("integrity-snapshot scan exceeds the configured bound")
            for item in snapshots:
                rec = records[("resource", item["resource_owner"] + "/" + item["resource_name"])]
                evidence = item["evidence"]
                if isinstance(evidence, str):
                    evidence = json.loads(evidence)
                rec["integrity"] = {"snapshot_id": item["snapshot_id"], "status": item["status"],
                                    "unresolved": item["unresolved"], "checked_at": _epoch(item["checked_at"]),
                                    "checkpoint": item["checkpoint"], **(evidence.get("integrity") or {})}
                if evidence.get("observations"):
                    rec["observations"] = evidence["observations"]
        for (kind, subject_id), record in records.items():
            self._cache.setdefault(f"{kind}:{subject_id}", record)

    def _decode_incident(self, row):
        incident_id = row["incident_id"]
        result = {"incident_id": incident_id, "status": row["status"], "severity": row["severity"],
                  "actor_id": row["actor_id"], "primary_reason": row["primary_reason"],
                  "recovery_required": row["recovery_required"], "security_version": row["security_version"],
                  "related_event_count": row["related_event_count"], "opened_at": _iso(row["opened_at"]),
                  "last_event_at": _iso(row["last_event_at"]), "resolved_at": _iso(row["resolved_at"]),
                  "current_authorization_state": row["current_authorization_state"],
                  "current_trust_state": row["current_trust_state"], "authorization_id": row["authorization_id"]}
        if row["resource_owner"]:
            result["resource_id"] = row["resource_owner"] + "/" + row["resource_name"]
        return result

    def flush(self):
        for key in sorted(self._dirty):
            record = self._cache[key]
            if record is None:
                continue
            if key.startswith("incident:"):
                self._save_incident(record)
            else:
                self._save_subject(key, record)
        self._dirty.clear()

    def _load_subject(self, key):
        self.prefetch([key])
        return self._cache[key]

    def _load_incident(self, incident_id):
        row = self.connection.execute("SELECT * FROM incidents WHERE incident_id=%s", (incident_id,)).fetchone()
        return self._decode_incident(row) if row else None

    def _save_subject(self, key, record):
        kind, subject_id = _subject(key)
        if subject_id == "" or record.get("authorization_state") not in (
                "NORMAL", "QUARANTINED", "LOCKED", "RECOVERY_AUTHORIZED", "VERIFY_RECOVERY"):
            raise StorageError("security state violates the canonical state contract")
        expected = record.get("expected_target") or {}
        self.connection.execute(
            "INSERT INTO security_state (subject_kind, subject_id, authorization_state, trust_state, "
            "security_version, violations, attempts, incident_id, reason, expected_ref, expected_sha, "
            "recovery_authorization_id, opened_at, updated_at, cleared_at, state_snapshot) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb) "
            "ON CONFLICT (subject_kind, subject_id) DO UPDATE SET "
            "authorization_state=EXCLUDED.authorization_state, trust_state=EXCLUDED.trust_state, "
            "security_version=EXCLUDED.security_version, violations=EXCLUDED.violations, "
            "attempts=EXCLUDED.attempts, incident_id=EXCLUDED.incident_id, reason=EXCLUDED.reason, "
            "expected_ref=EXCLUDED.expected_ref, expected_sha=EXCLUDED.expected_sha, "
            "recovery_authorization_id=EXCLUDED.recovery_authorization_id, updated_at=EXCLUDED.updated_at, "
            "cleared_at=EXCLUDED.cleared_at, state_snapshot=EXCLUDED.state_snapshot",
            (kind, subject_id, record["authorization_state"], record.get("trust_state"),
             int(record.get("security_version", 0)), int(record.get("violations", 0)),
             int(record.get("attempts", 0)), record.get("incident_id"), record.get("reason"),
             expected.get("ref"), expected.get("sha"), expected.get("authorization_id"),
             _timestamp(record.get("opened_at"), default_now=True),
             _timestamp(record.get("updated_at"), default_now=True), _timestamp(record.get("cleared_at")),
             _json({"version": 1, **{name: record[name] for name in ("recovery", "consumed")
                                    if name in record}}))
        )
        self._save_counters(kind, subject_id, record.get("counters") or {})
        self._save_signals(kind, subject_id, record.get("signals") or [])
        resource = _resource(kind, subject_id)
        if resource:
            self._save_resource_state(resource, record)

    def _save_counters(self, kind, subject_id, counters):
        self.connection.execute("DELETE FROM security_counters WHERE subject_kind=%s AND subject_id=%s",
                                (kind, subject_id))
        for name, value in sorted(counters.items()):
            self.connection.execute(
                "INSERT INTO security_counters (subject_kind, subject_id, counter_name, counter_value) "
                "VALUES (%s,%s,%s,%s)", (kind, subject_id, name, int(value)))

    def _save_signals(self, kind, subject_id, signals):
        self.connection.execute("DELETE FROM security_signals WHERE subject_kind=%s AND subject_id=%s",
                                (kind, subject_id))
        for signal in sorted(set(signals)):
            self.connection.execute(
                "INSERT INTO security_signals (subject_kind, subject_id, signal) VALUES (%s,%s,%s)",
                (kind, subject_id, signal))

    def _save_resource_state(self, resource, record):
        owner, name = resource
        recovery = record.get("recovery")
        if recovery and all(recovery.get(key) for key in
                            ("authorization_id", "operation", "ref", "observed_sha", "target_sha",
                             "authorized_by", "expires_at")):
            self.connection.execute(
                "INSERT INTO recovery_grants (authorization_id, resource_owner, resource_name, incident_id, "
                "operation, ref, observed_sha, target_sha, authorized_by, expires_at, consumed_at, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (authorization_id) DO UPDATE SET consumed_at=EXCLUDED.consumed_at",
                (recovery["authorization_id"], owner, name, recovery.get("incident_id"), recovery["operation"],
                 recovery["ref"], recovery["observed_sha"], recovery["target_sha"], recovery["authorized_by"],
                 _timestamp(recovery["expires_at"]), _timestamp(recovery.get("consumed_at")),
                 _timestamp(recovery.get("created_at") or record.get("updated_at"), default_now=True)))
        for path, baseline in sorted((record.get("baseline") or {}).items()):
            self.connection.execute(
                "INSERT INTO artifact_baselines (resource_owner, resource_name, path, sha256, "
                "authorization_id, authorized_by, advanced_at) VALUES (%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (resource_owner, resource_name, path) DO UPDATE SET sha256=EXCLUDED.sha256, "
                "authorization_id=EXCLUDED.authorization_id, authorized_by=EXCLUDED.authorized_by, "
                "advanced_at=EXCLUDED.advanced_at",
                (owner, name, path, baseline["sha256"], baseline["authorization_id"],
                 baseline["authorized_by"], _timestamp(baseline.get("at"), default_now=True)))
        for authorization_id, grant in sorted((record.get("artifact_grants") or {}).items()):
            self.connection.execute(
                "INSERT INTO artifact_change_grants (authorization_id, resource_owner, resource_name, path, "
                "expected_sha256, authorized_sha256, authorized_by, expires_at, consumed_at, created_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (authorization_id) DO UPDATE SET consumed_at=EXCLUDED.consumed_at",
                (authorization_id, owner, name, grant["artifact"],
                 grant.get("expected_old_sha256"), grant["authorized_new_sha256"], grant["authorized_by"],
                 _timestamp(grant["expires_at"]), _timestamp(grant.get("consumed_at")),
                 _timestamp(grant.get("created_at") or record.get("updated_at"), default_now=True)))
        if "integrity" in record:
            integrity = record.get("integrity") or {}
            snapshot_id = integrity.get("snapshot_id") or integrity.get("request_id")
            if not snapshot_id:
                raise StorageError("integrity snapshot is missing its stable snapshot_id")
            evidence = {"version": 1, "observations": record.get("observations") or {},
                        "integrity": {key: value for key, value in integrity.items()
                                      if key not in ("snapshot_id", "status", "unresolved", "checked_at", "checkpoint")}}
            self.connection.execute(
                "INSERT INTO integrity_snapshots (snapshot_id, resource_owner, resource_name, status, "
                "unresolved, checked_at, checkpoint, evidence_version, evidence) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s::jsonb) "
                "ON CONFLICT (snapshot_id) DO UPDATE SET status=EXCLUDED.status, unresolved=EXCLUDED.unresolved, "
                "checked_at=EXCLUDED.checked_at, checkpoint=EXCLUDED.checkpoint, evidence=EXCLUDED.evidence",
                (snapshot_id, owner, name, integrity.get("status", "UNVERIFIED"),
                 bool(integrity.get("unresolved")), _timestamp(integrity.get("checked_at") or record.get("updated_at"),
                                                                  default_now=True),
                 integrity.get("checkpoint"), _json(evidence)))

    def _save_incident(self, record):
        incident_id = record.get("incident_id")
        if not incident_id:
            raise StorageError("incident record has no identity")
        resource_id = record.get("resource_id")
        resource = resource_id.split("/", 1) if resource_id and "/" in resource_id else (None, None)
        status = record.get("status", "OPEN")
        resolved_at = _timestamp(record.get("resolved_at"))
        if (status == "RESOLVED") != (resolved_at is not None):
            raise StorageError("resolved incident timestamp does not match its status")
        self.connection.execute(
            "INSERT INTO incidents (incident_id, status, severity, actor_id, resource_owner, resource_name, "
            "primary_reason, recovery_required, security_version, related_event_count, opened_at, last_event_at, "
            "resolved_at, current_authorization_state, current_trust_state, authorization_id) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
            "ON CONFLICT (incident_id) DO UPDATE SET status=EXCLUDED.status, severity=EXCLUDED.severity, "
            "actor_id=EXCLUDED.actor_id, resource_owner=EXCLUDED.resource_owner, resource_name=EXCLUDED.resource_name, "
            "primary_reason=EXCLUDED.primary_reason, recovery_required=EXCLUDED.recovery_required, "
            "security_version=EXCLUDED.security_version, related_event_count=EXCLUDED.related_event_count, "
            "last_event_at=EXCLUDED.last_event_at, resolved_at=EXCLUDED.resolved_at, "
            "current_authorization_state=EXCLUDED.current_authorization_state, "
            "current_trust_state=EXCLUDED.current_trust_state, authorization_id=EXCLUDED.authorization_id",
            (incident_id, status, record.get("severity", "NOTICE"), record.get("actor_id"),
             resource[0], resource[1], record.get("primary_reason") or "unspecified",
             bool(record.get("recovery_required")), int(record.get("security_version", 0)),
             int(record.get("related_event_count", 0)), _timestamp(record.get("opened_at"), default_now=True),
             _timestamp(record.get("last_event_at"), default_now=True), resolved_at,
             record.get("current_authorization_state"), record.get("current_trust_state"),
             record.get("authorization_id")))

    def audit_head(self, lock=False):
        suffix = " FOR UPDATE" if lock else ""
        row = self.connection.execute(
            "SELECT sequence, head_hash FROM audit_chain_heads WHERE chain_id='primary'" + suffix
        ).fetchone()
        if row is None:
            raise StorageError("audit-chain head is not initialized")
        return row["sequence"], row["head_hash"].strip()

    def append_audit(self, record):
        sequence, previous = self.audit_head(lock=True)
        if record.get("previous_hash") != previous:
            raise StorageError("audit-chain head changed during the request")
        sequence += 1
        evidence = _json({"version": 1, "record": record})
        if len(evidence.encode("utf-8")) > 65536:
            raise StorageError("audit evidence exceeds the 64 KiB storage bound")
        self.connection.execute(
            "INSERT INTO audit_events (sequence,event_id,event_type,occurred_at,severity,request_id,"
            "parent_request_id,incident_id,actor_id,agent_id,resource_id,policy_id,policy_version,"
            "evidence_version,evidence,previous_hash,event_hash) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s::jsonb,%s,%s)",
            (sequence, record["event_id"], record["event_type"], _timestamp(record["timestamp"]),
             record["severity"], record.get("request_id"), record.get("parent_request_id"),
             record.get("incident_id"), record.get("actor_id"), record.get("agent_id"),
             record.get("resource_id"), record.get("policy_id"), record.get("policy_version"),
             evidence, previous, record["event_hash"])
        )
        cursor = self.connection.execute(
            "UPDATE audit_chain_heads SET sequence=%s, head_hash=%s, updated_at=CURRENT_TIMESTAMP "
            "WHERE chain_id='primary' AND sequence=%s AND head_hash=%s",
            (sequence, record["event_hash"], sequence - 1, previous)
        )
        if cursor.rowcount != 1:
            raise StorageError("audit-chain head update lost its serialization check")
        return sequence

    def audit_events(self, *, limit=MAX_AUDIT_BATCH, offset=0, since=None, filters=None):
        if not 1 <= limit <= MAX_AUDIT_BATCH or offset < 0:
            raise StorageError("audit query is outside its bound")
        clauses, parameters = [], []
        if since is not None:
            clauses.append("occurred_at >= %s")
            parameters.append(_timestamp(since))
        filters = filters or {}
        columns = {"incident_id": "incident_id", "actor": "actor_id", "agent": "agent_id",
                   "resource": "resource_id", "event_type": "event_type", "severity": "severity"}
        for filter_name, column in columns.items():
            if filters.get(filter_name):
                clauses.append(f"{column} = %s")
                parameters.append(filters[filter_name])
        query = "SELECT sequence,evidence FROM audit_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY sequence DESC LIMIT %s OFFSET %s"
        parameters.extend((limit, offset))
        rows = self.connection.execute(query, parameters).fetchall()
        records = []
        for row in rows:
            evidence = row["evidence"]
            if isinstance(evidence, str):
                evidence = json.loads(evidence)
            record = evidence.get("record") if isinstance(evidence, dict) else None
            if not isinstance(record, dict):
                raise StorageError("audit event evidence has an unsupported version")
            records.append(record)
        return records

    def audit_query(self, *, limit, offset, now, retention, since=None, filters=None):
        if not 1 <= limit <= MAX_AUDIT_BATCH or not 0 <= offset <= 10000:
            raise StorageError("audit query is outside its bound")
        clauses, parameters = [], []
        if since is not None:
            clauses.append("occurred_at >= %s")
            parameters.append(_timestamp(since))
        retention_clauses = []
        for severity, days in sorted((retention or {}).items()):
            retention_clauses.append("(severity=%s AND occurred_at >= %s)")
            parameters.extend((severity, _timestamp(now - days * 86400)))
        if retention_clauses:
            clauses.append("(" + " OR ".join(retention_clauses) + ")")
        filters = filters or {}
        typed = {"incident_id": "incident_id", "actor": "actor_id", "agent": "agent_id",
                 "resource": "resource_id", "event_type": "event_type", "severity": "severity"}
        for key, column in typed.items():
            if filters.get(key):
                clauses.append(f"lower({column}) = lower(%s)")
                parameters.append(filters[key])
        json_fields = {"decision": "decision", "state": "authorization_state"}
        for key, field in json_fields.items():
            if filters.get(key):
                path = "{record,decision}" if field == "decision" else "{record,authorization_state}"
                clauses.append(f"lower(evidence #>> '{path}') = lower(%s)")
                parameters.append(filters[key])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        matched = self.connection.execute(
            "SELECT count(*) AS matched FROM audit_events" + where, parameters
        ).fetchone()["matched"]
        query_parameters = [*parameters, limit, offset]
        rows = self.connection.execute(
            "SELECT evidence FROM audit_events" + where + " ORDER BY sequence DESC LIMIT %s OFFSET %s",
            query_parameters
        ).fetchall()
        records = []
        for row in rows:
            evidence = row["evidence"]
            if isinstance(evidence, str):
                evidence = json.loads(evidence)
            record = evidence.get("record") if isinstance(evidence, dict) else None
            if not isinstance(record, dict):
                raise StorageError("audit event evidence has an unsupported version")
            records.append(record)
        return records, matched

    def audit_summary(self, since):
        rows = self.connection.execute(
            "SELECT event_type, severity, count(*) AS count FROM audit_events "
            "WHERE occurred_at >= %s GROUP BY event_type, severity",
            (_timestamp(since),)
        ).fetchall()
        by_event = {}
        by_severity = {}
        for row in rows:
            by_event[row["event_type"]] = by_event.get(row["event_type"], 0) + row["count"]
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + row["count"]
        open_count = self.connection.execute(
            "SELECT count(*) AS count FROM incidents WHERE status <> 'RESOLVED'"
        ).fetchone()["count"]
        return by_event, by_severity, open_count

    def audit_chain_batches(self):
        after = 0
        while True:
            rows = self.connection.execute(
                "SELECT sequence, evidence FROM audit_events WHERE sequence > %s "
                "ORDER BY sequence LIMIT %s", (after, MAX_AUDIT_BATCH)
            ).fetchall()
            if not rows:
                return
            batch = []
            for row in rows:
                evidence = row["evidence"]
                if isinstance(evidence, str):
                    evidence = json.loads(evidence)
                record = evidence.get("record") if isinstance(evidence, dict) else None
                if not isinstance(record, dict):
                    raise StorageError("audit event evidence has an unsupported version")
                batch.append(record)
                after = row["sequence"]
            yield from batch

    def count_open_incidents(self):
        return self.connection.execute(
            "SELECT count(*) AS count FROM incidents WHERE status <> 'RESOLVED'"
        ).fetchone()["count"]

    def audit_count(self, *, since=None, filters=None):
        clauses, parameters = [], []
        if since is not None:
            clauses.append("occurred_at >= %s")
            parameters.append(_timestamp(since))
        filters = filters or {}
        columns = {"incident_id": "incident_id", "actor": "actor_id", "agent": "agent_id",
                   "resource": "resource_id", "event_type": "event_type", "severity": "severity"}
        for filter_name, column in columns.items():
            if filters.get(filter_name):
                clauses.append(f"{column} = %s")
                parameters.append(filters[filter_name])
        query = "SELECT count(*) AS matched FROM audit_events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        return self.connection.execute(query, parameters).fetchone()["matched"]

    def trust_observation(self, key):
        if "/" not in key:
            raise StorageError("trust observation key has an invalid form")
        owner, name = key.split("/", 1)
        row = self.connection.execute(
            "SELECT installation_state, observed_at FROM trust_observations "
            "WHERE resource_owner=%s AND resource_name=%s AND provider='github'",
            (owner, name)
        ).fetchone()
        if not row or row["installation_state"] != "PRESENT":
            return None
        return {"installed": True, "verified_at": _epoch(row["observed_at"])}

    def remember_trust(self, key, fields):
        if fields.get("installed") is not True:
            raise StorageError("ACP records only positive provider trust observations")
        if "/" not in key:
            raise StorageError("trust observation key has an invalid form")
        owner, name = key.split("/", 1)
        self.connection.execute(
            "INSERT INTO trust_observations (resource_owner, resource_name, provider, "
            "installation_state, observed_at, evidence_version) VALUES (%s,%s,'github','PRESENT',%s,1) "
            "ON CONFLICT (resource_owner, resource_name, provider) DO UPDATE SET "
            "installation_state='PRESENT', observed_at=EXCLUDED.observed_at, evidence_version=1",
            (owner, name, _timestamp(fields.get("verified_at"), default_now=True)))

    def capability_consumed(self, keys, jti, now):
        resource = next((key[len("resource:"):] for key in keys if key.startswith("resource:")), None)
        actor = next((key[len("actor:"):] for key in keys if key.startswith("actor:")), None)
        if not resource or "/" not in resource or not actor or str(jti).startswith("static:"):
            return False
        owner, name = resource.split("/", 1)
        return self.connection.execute(
            "SELECT 1 FROM consumed_capabilities WHERE jti=%s AND resource_owner=%s "
            "AND resource_name=%s AND actor_id=%s AND expires_at > %s",
            (jti, owner, name, actor, _timestamp(now))
        ).fetchone() is not None

    def consume_capability(self, keys, jti, now, expires_at):
        resource = next((key[len("resource:"):] for key in keys if key.startswith("resource:")), None)
        actor = next((key[len("actor:"):] for key in keys if key.startswith("actor:")), None)
        if not resource or "/" not in resource or not actor or str(jti).startswith("static:"):
            return
        owner, name = resource.split("/", 1)
        cursor = self.connection.execute(
            "INSERT INTO consumed_capabilities (jti,resource_owner,resource_name,actor_id,consumed_at,expires_at) "
            "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (jti) DO NOTHING",
            (jti, owner, name, actor, _timestamp(now), _timestamp(expires_at))
        )
        if cursor.rowcount != 1:
            raise StorageError("capability was consumed concurrently")


    # ---------------------------------------------------------- metered actions

    _LEDGER_COLUMNS = ("record_key", "request_id", "action", "provider", "resource_owner", "resource_name",
                       "ref", "sha", "caller_kind", "caller_id", "reason", "reason_code", "counted",
                       "budget_day", "grant_id", "evidence_digest", "created_at")

    def ledger_get(self, key):
        row = self.connection.execute(
            "SELECT " + ", ".join(self._LEDGER_COLUMNS) + " FROM spend_ledger WHERE record_key=%s", (key,)
        ).fetchone()
        if row is None:
            return None
        return {**row, "budget_day": row["budget_day"].isoformat(), "created_at": _epoch(row["created_at"])}

    def ledger_insert(self, row):
        values = [row[column] for column in self._LEDGER_COLUMNS]
        values[self._LEDGER_COLUMNS.index("created_at")] = _timestamp(row["created_at"])
        cursor = self.connection.execute(
            "INSERT INTO spend_ledger (" + ", ".join(self._LEDGER_COLUMNS) + ") VALUES ("
            + ", ".join(["%s"] * len(values)) + ") ON CONFLICT (record_key) DO NOTHING", values)
        if cursor.rowcount != 1:
            raise StorageError("metered action was recorded concurrently")

    def ledger_count(self, day, actions, owner=None, name=None, provider=None, distinct_sha=False):
        clauses, parameters = ["counted", "budget_day = %s", "action = ANY(%s)"], [day, list(actions)]
        for column, value in (("resource_owner", owner), ("resource_name", name), ("provider", provider)):
            if value is not None:
                clauses.append(f"{column} = %s")
                parameters.append(value.lower() if column != "provider" else value)
        measure = "count(DISTINCT sha)" if distinct_sha else "count(*)"
        return self.connection.execute(
            f"SELECT {measure} AS count FROM spend_ledger WHERE " + " AND ".join(clauses), parameters
        ).fetchone()["count"]

    def ledger_day(self, day):
        rows = self.connection.execute(
            "SELECT " + ", ".join(self._LEDGER_COLUMNS) + " FROM spend_ledger WHERE budget_day = %s "
            "ORDER BY created_at, record_key LIMIT %s", (day, MAX_STATE_ROWS)).fetchall()
        return [{**row, "budget_day": row["budget_day"].isoformat(), "created_at": _epoch(row["created_at"])}
                for row in rows]

    def grant_issue(self, row):
        self.connection.execute(
            "INSERT INTO budget_grants (grant_id, action, resource_owner, resource_name, uses_total, uses_left, "
            "issued_at, expires_at, issued_by, reason) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (row["grant_id"], row["action"], row["resource_owner"], row["resource_name"], row["uses_total"],
             row["uses_left"], _timestamp(row["issued_at"]), _timestamp(row["expires_at"]), row["issued_by"],
             row["reason"]))

    def grant_take(self, action, owner, name, now):
        row = self.connection.execute(
            "UPDATE budget_grants SET uses_left = uses_left - 1 WHERE grant_id = ("
            "SELECT grant_id FROM budget_grants WHERE action=%s AND uses_left > 0 AND expires_at > %s "
            "AND (resource_owner IS NULL OR (resource_owner=%s AND resource_name=%s)) "
            "ORDER BY grant_id LIMIT 1 FOR UPDATE) RETURNING grant_id",
            (action, _timestamp(now), (owner or "").lower(), (name or "").lower())).fetchone()
        return row["grant_id"] if row else None

    def lease_get(self, key):
        row = self.connection.execute(
            "SELECT lease_key, session_id, model, opened_at, expires_at, released_at FROM subagent_leases "
            "WHERE lease_key=%s", (key,)).fetchone()
        if row is None:
            return None
        return {**row, "opened_at": _epoch(row["opened_at"]), "expires_at": _epoch(row["expires_at"]),
                "released_at": _epoch(row["released_at"])}

    def lease_open(self, row):
        self.connection.execute(
            "INSERT INTO subagent_leases (lease_key, session_id, model, reason, opened_at, expires_at) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (row["lease_key"], row["session_id"], row["model"], row["reason"], _timestamp(row["opened_at"]),
             _timestamp(row["expires_at"])))

    def leases_open(self, session_id, now):
        return self.connection.execute(
            "SELECT count(*) AS count FROM subagent_leases WHERE session_id=%s AND released_at IS NULL "
            "AND expires_at > %s", (session_id, _timestamp(now))).fetchone()["count"]

    def lease_release(self, key, now):
        cursor = self.connection.execute(
            "UPDATE subagent_leases SET released_at=%s WHERE lease_key=%s AND released_at IS NULL",
            (_timestamp(now), key))
        return cursor.rowcount == 1

    def snapshot_put(self, provider, subject, digest, body, fetched_at, schema_version=1):
        self.connection.execute(
            "INSERT INTO provider_snapshots (provider, subject, digest, schema_version, fetched_at, body) "
            "VALUES (%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT (provider, subject, digest) "
            "DO UPDATE SET fetched_at = EXCLUDED.fetched_at",
            (provider, subject, digest, schema_version, _timestamp(fetched_at), _json(body)))

    def snapshot_latest(self, provider, subject):
        row = self.connection.execute(
            "SELECT body, fetched_at FROM provider_snapshots WHERE provider=%s AND subject=%s "
            "ORDER BY fetched_at DESC, digest LIMIT 1", (provider, subject)).fetchone()
        return (row["body"], _epoch(row["fetched_at"])) if row else (None, None)

    def _save_audit_chain_head(self, record):
        raise StorageError("audit-chain head is written atomically with its event")


class SecurityStateMapping:
    """Dict-compatible facade over bounded, request-local PostgreSQL reads."""

    def get(self, key, default=None):
        value = current().get_state(key)
        current().mark_dirty(key)
        return default if value is None else value

    def setdefault(self, key, default=None):
        value = current().get_state(key)
        if value is not None:
            return value
        current().set_state(key, default)
        return default

    def __getitem__(self, key):
        value = current().get_state(key)
        if value is None:
            raise KeyError(key)
        current().mark_dirty(key)
        return value

    def __setitem__(self, key, value):
        current().set_state(key, value)

    def items(self):
        return current().items()


class TrustStateMapping:
    def get(self, key, default=None):
        value = current().trust_observation(key)
        return default if value is None else value


SECURITY_STATE = SecurityStateMapping()
TRUST_STATE = TrustStateMapping()
atexit.register(close_pool)
