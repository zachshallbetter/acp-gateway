-- acp-migration: additive
-- build_admission: the machine register asks ACP before a build takes a slot, and an admitted build is
-- recorded in the spend ledger like local_heavy_build. The action lists widen to include it; every
-- existing row and every older release's insert still satisfies the new check.
ALTER TABLE budget_grants
    DROP CONSTRAINT budget_grants_action_check,
    ADD CONSTRAINT budget_grants_action_check CHECK (action IN (
        'hosted_build', 'production_merge', 'manual_ci', 'local_heavy_build', 'heavy_subagent', 'build_admission'
    ));

ALTER TABLE spend_ledger
    DROP CONSTRAINT spend_ledger_action_check,
    ADD CONSTRAINT spend_ledger_action_check CHECK (action IN (
        'hosted_build', 'production_merge', 'manual_ci', 'local_heavy_build', 'heavy_subagent', 'build_admission'
    ));
