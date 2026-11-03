ALTER TABLE incidents
    ADD COLUMN current_authorization_state text CHECK (
        current_authorization_state IS NULL OR current_authorization_state IN (
            'A0', 'A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7'
        )
    ),
    ADD COLUMN current_trust_state text CHECK (
        current_trust_state IS NULL OR current_trust_state IN ('T0', 'T1', 'T2', 'T3')
    ),
    ADD COLUMN authorization_id text;

INSERT INTO audit_chain_heads (chain_id, sequence, head_hash, updated_at)
VALUES ('primary', 0, '', CURRENT_TIMESTAMP)
ON CONFLICT (chain_id) DO NOTHING;
