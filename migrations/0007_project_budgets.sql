-- acp-migration: additive
-- Per-project budgets: each metered build records the provider project it built (a Vercel project id,
-- a Railway project id, a workflow path), so ACP budgets and paces each project on each service.
-- An ACP-decided priority push is recorded as PRIORITY_GRANTED. Older releases insert no project and
-- never PRIORITY_GRANTED, so every existing row and insert still satisfies the new checks.
ALTER TABLE spend_ledger
    ADD COLUMN project text CHECK (project IS NULL OR length(project) BETWEEN 1 AND 256);

ALTER TABLE spend_ledger
    DROP CONSTRAINT spend_ledger_reason_code_check,
    ADD CONSTRAINT spend_ledger_reason_code_check CHECK (reason_code IN (
        'WITHIN_BUDGET', 'GRANT_APPLIED', 'NO_HOSTED_BUILD', 'PRIORITY_GRANTED'
    ));

CREATE INDEX spend_ledger_project_idx
    ON spend_ledger (provider, project, created_at) WHERE counted;
