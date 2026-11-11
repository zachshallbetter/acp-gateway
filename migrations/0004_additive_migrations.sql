-- acp-migration: additive
-- Records, per applied migration, whether it only adds (tables, columns with defaults, indexes).
-- A running release accepts a newer schema only when every migration it does not ship is additive,
-- so applying an additive migration no longer takes the running release down.
ALTER TABLE schema_migrations ADD COLUMN additive boolean NOT NULL DEFAULT false;
