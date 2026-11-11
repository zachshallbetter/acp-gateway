-- Metered actions: what ACP allowed that costs money or reaches production.
-- Expand only. Nothing existing is altered.

CREATE TABLE budget_grants (
    grant_id text PRIMARY KEY CHECK (grant_id ~ '^g-[0-9a-f]{16}$'),
    action text NOT NULL CHECK (action IN (
        'hosted_build', 'production_merge', 'manual_ci', 'local_heavy_build', 'heavy_subagent'
    )),
    resource_owner text,
    resource_name text,
    uses_total integer NOT NULL CHECK (uses_total BETWEEN 1 AND 50),
    uses_left integer NOT NULL CHECK (uses_left >= 0),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    issued_by text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 512),
    CHECK (uses_left <= uses_total),
    CHECK (expires_at > issued_at),
    CHECK ((resource_owner IS NULL) = (resource_name IS NULL))
);

CREATE TABLE spend_ledger (
    record_key text PRIMARY KEY CHECK (record_key ~ '^[0-9a-f]{64}$'),
    request_id text NOT NULL UNIQUE,
    action text NOT NULL CHECK (action IN (
        'hosted_build', 'production_merge', 'manual_ci', 'local_heavy_build', 'heavy_subagent'
    )),
    provider text NOT NULL CHECK (provider IN ('vercel', 'railway', 'github_actions', 'local', 'claude')),
    resource_owner text,
    resource_name text,
    ref text,
    sha text CHECK (sha IS NULL OR sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    caller_kind text NOT NULL CHECK (caller_kind IN ('shared', 'lane', 'coordinator', 'owner')),
    caller_id text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 512),
    -- Only allowed actions are recorded; a refusal leaves no row, so a retry after a grant is not blocked.
    reason_code text NOT NULL CHECK (reason_code IN ('WITHIN_BUDGET', 'GRANT_APPLIED', 'NO_HOSTED_BUILD')),
    counted boolean NOT NULL,
    budget_day date NOT NULL,
    grant_id text REFERENCES budget_grants (grant_id),
    evidence_digest text CHECK (evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    CHECK (counted = (reason_code <> 'NO_HOSTED_BUILD')),
    CHECK (grant_id IS NULL OR reason_code = 'GRANT_APPLIED'),
    CHECK ((resource_owner IS NULL) = (resource_name IS NULL))
);

CREATE INDEX spend_ledger_repo_day_idx
    ON spend_ledger (budget_day, action, resource_owner, resource_name) WHERE counted;
CREATE INDEX spend_ledger_provider_day_idx
    ON spend_ledger (budget_day, action, provider) WHERE counted;

CREATE TABLE subagent_leases (
    lease_key text PRIMARY KEY CHECK (lease_key ~ '^[0-9a-f]{64}$'),
    session_id text NOT NULL,
    model text NOT NULL,
    reason text NOT NULL CHECK (length(reason) BETWEEN 8 AND 512),
    opened_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    released_at timestamptz,
    CHECK (expires_at > opened_at),
    CHECK (released_at IS NULL OR released_at >= opened_at)
);

CREATE INDEX subagent_leases_open_idx ON subagent_leases (session_id, expires_at) WHERE released_at IS NULL;

CREATE TABLE provider_snapshots (
    provider text NOT NULL CHECK (provider IN ('vercel', 'railway', 'github_actions')),
    subject text NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    schema_version integer NOT NULL CHECK (schema_version >= 1),
    fetched_at timestamptz NOT NULL,
    body jsonb NOT NULL CHECK (pg_column_size(body) <= 262144),
    PRIMARY KEY (provider, subject, digest)
);

CREATE INDEX provider_snapshots_latest_idx ON provider_snapshots (provider, subject, fetched_at DESC);
