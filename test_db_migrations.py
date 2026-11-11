"""The migration-history resolver, without a database: which histories a release may run on."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import db_migrations  # noqa: E402

AVAILABLE = db_migrations.migration_files()
SHIPPED = {version: (checksum, db_migrations.is_additive(sql)) for version, _n, checksum, sql in AVAILABLE}
TOP = max(SHIPPED)


def test_marker_is_the_first_line_only():
    assert db_migrations.is_additive("\n-- acp-migration: additive\nALTER TABLE t ADD COLUMN c int;")
    assert not db_migrations.is_additive("ALTER TABLE t DROP COLUMN c;\n-- acp-migration: additive")
    assert not db_migrations.is_additive("-- acp-migration: additive-ish\n")
    assert db_migrations.is_additive([sql for v, _n, _c, sql in AVAILABLE if v == 4][0])


def test_exactly_this_release_is_current():
    report = db_migrations.classify(SHIPPED)
    assert report["status"] == "current" and report["ahead_additive_versions"] == []


def test_a_newer_additive_migration_keeps_this_release_running():
    report = db_migrations.classify({**SHIPPED, TOP + 1: ("f" * 64, True), TOP + 2: ("e" * 64, True)})
    assert report["status"] == "current", report
    assert report["ahead_additive_versions"] == [f"{TOP + 1:04d}", f"{TOP + 2:04d}"]


def test_a_newer_migration_that_is_not_additive_stops_it():
    report = db_migrations.classify({**SHIPPED, TOP + 1: ("f" * 64, True), TOP + 2: ("e" * 64, False)})
    assert report["status"] == "conflict" and report["unknown_versions"] == [f"{TOP + 2:04d}"]
    assert report["ahead_additive_versions"] == []


def test_missing_changed_or_gapped_history_is_never_current():
    missing = {v: s for v, s in SHIPPED.items() if v != TOP}
    assert db_migrations.classify(missing)["status"] == "pending"
    changed = {**SHIPPED, 1: ("0" * 64, False)}
    assert db_migrations.classify(changed)["status"] == "conflict"
    gapped = {v: s for v, s in SHIPPED.items() if v != 2}
    assert db_migrations.classify(gapped)["status"] == "conflict"
    ahead_of_a_hole = {**missing, TOP + 1: ("f" * 64, True)}
    assert db_migrations.classify(ahead_of_a_hole)["status"] == "conflict"
    assert db_migrations.classify(None)["status"] == "pending"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} migration-history tests passed")
