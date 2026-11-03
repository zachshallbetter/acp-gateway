CREATE TABLE IF NOT EXISTS schema_migrations (
    version integer PRIMARY KEY CHECK (version > 0),
    checksum char(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL
);

CREATE TABLE policy_heads (
    owner text NOT NULL,
    repository text NOT NULL,
    policy_id text NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version > 0),
    digest char(64) NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    signing_key_id text NOT NULL,
    activated_at timestamptz NOT NULL,
    PRIMARY KEY (owner, repository),
    UNIQUE (owner, repository, policy_id)
);

CREATE TABLE incidents (
    incident_id text PRIMARY KEY,
    status text NOT NULL CHECK (status IN (
        'OPEN', 'CONTAINED', 'RECOVERY_AUTHORIZED', 'VERIFYING', 'RESOLVED'
    )),
    severity text NOT NULL CHECK (severity IN (
        'INFO', 'NOTICE', 'WARNING', 'HIGH', 'CRITICAL'
    )),
    actor_id text,
    resource_owner text,
    resource_name text,
    primary_reason text NOT NULL,
    recovery_required boolean NOT NULL DEFAULT false,
    security_version bigint NOT NULL DEFAULT 0 CHECK (security_version >= 0),
    related_event_count bigint NOT NULL DEFAULT 0 CHECK (related_event_count >= 0),
    opened_at timestamptz NOT NULL,
    last_event_at timestamptz NOT NULL,
    resolved_at timestamptz,
    CHECK ((resource_owner IS NULL) = (resource_name IS NULL)),
    CHECK ((status = 'RESOLVED') = (resolved_at IS NOT NULL))
);

CREATE INDEX incidents_opened_status_idx ON incidents (status, last_event_at)
    WHERE status <> 'RESOLVED';
CREATE INDEX incidents_resource_idx ON incidents (resource_owner, resource_name, last_event_at);
CREATE INDEX incidents_actor_idx ON incidents (actor_id, last_event_at);

CREATE TABLE security_state (
    subject_kind text NOT NULL CHECK (subject_kind IN ('resource', 'actor')),
    subject_id text NOT NULL CHECK (subject_id <> ''),
    authorization_state text NOT NULL CHECK (authorization_state IN (
        'NORMAL', 'QUARANTINED', 'LOCKED', 'RECOVERY_AUTHORIZED', 'VERIFY_RECOVERY'
    )),
    trust_state text CHECK (trust_state IS NULL OR trust_state IN (
        'VERIFIED', 'SELF_REPORTED', 'UNVERIFIED', 'QUARANTINED'
    )),
    security_version bigint NOT NULL DEFAULT 0 CHECK (security_version >= 0),
    violations bigint NOT NULL DEFAULT 0 CHECK (violations >= 0),
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    incident_id text REFERENCES incidents (incident_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    reason text,
    expected_ref text,
    expected_sha text,
    recovery_authorization_id text,
    opened_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    cleared_at timestamptz,
    state_snapshot jsonb NOT NULL DEFAULT '{"version":1}'::jsonb
        CHECK (jsonb_typeof(state_snapshot) = 'object'),
    PRIMARY KEY (subject_kind, subject_id)
);

CREATE INDEX security_state_incident_idx ON security_state (incident_id)
    WHERE incident_id IS NOT NULL;

CREATE TABLE security_counters (
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    counter_name text NOT NULL CHECK (counter_name IN (
        'ordinary_denial_count', 'protected_attempt_while_quarantined',
        'policy_tamper_count', 'identity_mismatch_count',
        'forged_authorization_count', 'credential_extraction_count',
        'recovery_mismatch_count', 'alternate_agent_count',
        'delegation_after_denial_count'
    )),
    counter_value bigint NOT NULL CHECK (counter_value >= 0),
    PRIMARY KEY (subject_kind, subject_id, counter_name),
    FOREIGN KEY (subject_kind, subject_id)
        REFERENCES security_state (subject_kind, subject_id) ON DELETE RESTRICT
);

CREATE TABLE security_signals (
    subject_kind text NOT NULL,
    subject_id text NOT NULL,
    signal text NOT NULL CHECK (signal <> ''),
    PRIMARY KEY (subject_kind, subject_id, signal),
    FOREIGN KEY (subject_kind, subject_id)
        REFERENCES security_state (subject_kind, subject_id) ON DELETE RESTRICT
);

CREATE TABLE recovery_grants (
    authorization_id text PRIMARY KEY,
    resource_owner text NOT NULL,
    resource_name text NOT NULL,
    incident_id text REFERENCES incidents (incident_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    operation text NOT NULL,
    ref text NOT NULL,
    observed_sha text NOT NULL,
    target_sha text NOT NULL,
    authorized_by text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX recovery_grants_scope_idx
    ON recovery_grants (resource_owner, resource_name, operation, ref, expires_at);

CREATE TABLE consumed_capabilities (
    jti text PRIMARY KEY,
    resource_owner text NOT NULL,
    resource_name text NOT NULL,
    actor_id text NOT NULL,
    consumed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > consumed_at)
);

CREATE INDEX consumed_capabilities_expiry_idx ON consumed_capabilities (expires_at);

CREATE TABLE trust_observations (
    resource_owner text NOT NULL,
    resource_name text NOT NULL,
    provider text NOT NULL,
    installation_state text NOT NULL CHECK (installation_state IN ('UNKNOWN', 'PRESENT', 'ABSENT')),
    observed_at timestamptz NOT NULL,
    evidence_version integer NOT NULL CHECK (evidence_version > 0),
    PRIMARY KEY (resource_owner, resource_name, provider)
);

CREATE TABLE artifact_baselines (
    resource_owner text NOT NULL,
    resource_name text NOT NULL,
    path text NOT NULL,
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    authorization_id text NOT NULL,
    authorized_by text NOT NULL,
    advanced_at timestamptz NOT NULL,
    PRIMARY KEY (resource_owner, resource_name, path),
    UNIQUE (authorization_id)
);

CREATE TABLE artifact_change_grants (
    authorization_id text PRIMARY KEY,
    resource_owner text NOT NULL,
    resource_name text NOT NULL,
    path text NOT NULL,
    expected_sha256 char(64) CHECK (expected_sha256 IS NULL OR expected_sha256 ~ '^[0-9a-f]{64}$'),
    authorized_sha256 char(64) NOT NULL CHECK (authorized_sha256 ~ '^[0-9a-f]{64}$'),
    authorized_by text NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX artifact_change_grants_scope_idx
    ON artifact_change_grants (resource_owner, resource_name, path, expires_at);

CREATE TABLE integrity_snapshots (
    snapshot_id text PRIMARY KEY,
    resource_owner text NOT NULL,
    resource_name text NOT NULL,
    status text NOT NULL,
    unresolved boolean NOT NULL,
    checked_at timestamptz NOT NULL,
    checkpoint text,
    evidence_version integer NOT NULL CHECK (evidence_version > 0),
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object')
);

CREATE INDEX integrity_snapshots_resource_time_idx
    ON integrity_snapshots (resource_owner, resource_name, checked_at DESC);

CREATE TABLE audit_events (
    sequence bigint PRIMARY KEY CHECK (sequence > 0),
    event_id text NOT NULL UNIQUE,
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL,
    severity text NOT NULL CHECK (severity IN ('INFO', 'NOTICE', 'WARNING', 'HIGH', 'CRITICAL')),
    request_id text,
    parent_request_id text,
    incident_id text REFERENCES incidents (incident_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    actor_id text,
    agent_id text,
    resource_id text,
    policy_id text,
    policy_version integer CHECK (policy_version IS NULL OR policy_version > 0),
    evidence_version integer NOT NULL CHECK (evidence_version > 0),
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
    previous_hash char(64) NOT NULL CHECK (previous_hash = '' OR previous_hash ~ '^[0-9a-f]{64}$'),
    event_hash char(64) NOT NULL UNIQUE CHECK (event_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX audit_events_time_idx ON audit_events (occurred_at, sequence);
CREATE INDEX audit_events_type_severity_idx ON audit_events (event_type, severity, occurred_at);
CREATE INDEX audit_events_incident_idx ON audit_events (incident_id, sequence)
    WHERE incident_id IS NOT NULL;

CREATE TABLE audit_chain_heads (
    chain_id text PRIMARY KEY,
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    head_hash char(64) NOT NULL DEFAULT ''
        CHECK (head_hash = '' OR head_hash ~ '^[0-9a-f]{64}$'),
    updated_at timestamptz NOT NULL
);

CREATE TABLE request_idempotency (
    principal_id text NOT NULL,
    idempotency_key text NOT NULL,
    operation text NOT NULL,
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    response_status smallint NOT NULL CHECK (response_status BETWEEN 100 AND 599),
    response_ciphertext bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (principal_id, idempotency_key),
    CHECK (expires_at > created_at),
    CHECK (octet_length(response_ciphertext) <= 65536)
);

CREATE INDEX request_idempotency_expiry_idx ON request_idempotency (expires_at);

CREATE TABLE notification_outbox (
    outbox_id text PRIMARY KEY,
    event_id text NOT NULL REFERENCES audit_events (event_id) ON DELETE RESTRICT,
    destination_id text NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at timestamptz NOT NULL,
    delivered_at timestamptz,
    last_error_code text,
    UNIQUE (event_id, destination_id)
);

CREATE INDEX notification_outbox_pending_idx ON notification_outbox (available_at)
    WHERE delivered_at IS NULL;
