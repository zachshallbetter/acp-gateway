-- acp-migration: additive
-- The signed deployment documents (the policy registry, the caller registry and the budget policy),
-- versioned and append-only. Both production hosts read the newest version, so a signed change takes
-- effect without a redeploy and is no longer bound by a host's environment-variable size limit.
-- Signatures are still verified with the deployment's own key: a row here grants nothing by itself.
CREATE TABLE signed_documents (
    name text NOT NULL CHECK (name IN ('policy', 'callers', 'budget')),
    version integer NOT NULL CHECK (version > 0),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document text NOT NULL CHECK (length(document) BETWEEN 2 AND 4194304),
    written_by text NOT NULL CHECK (length(written_by) BETWEEN 1 AND 128),
    written_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (name, version)
);
