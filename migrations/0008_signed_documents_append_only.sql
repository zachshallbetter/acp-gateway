-- acp-migration: additive
-- Signed documents are append-only (0005): a new version is a new row. Enforce it, so no writer --
-- a release, a script or a mistaken query -- can rewrite or remove a version other hosts trusted.
-- No release updates or deletes these rows, so the running release is unaffected.
CREATE FUNCTION signed_documents_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'signed_documents is append-only: write a new version instead';
END;
$$;

CREATE TRIGGER signed_documents_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON signed_documents
    FOR EACH STATEMENT EXECUTE FUNCTION signed_documents_append_only();
