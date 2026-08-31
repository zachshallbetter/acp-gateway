"""Tests for the three limits that blocked comprehensive project access.

Each corresponds to a defect the previous gateway had, and each fails against
that version -- the point of writing them as regressions rather than as
descriptions of the new code.
"""
import json, os, sys
from pathlib import Path
from unittest.mock import patch

root = Path(__file__).parent
sys.path.insert(0, str(root))
os.environ.setdefault("ACP_GATEWAY_TOKEN", "test-token")
import gateway  # noqa: E402

def resp(body):
    r = type("R", (), {"__enter__": lambda self: self, "__exit__": lambda *a: None})()
    r.__dict__["read"] = lambda: json.dumps(body).encode()
    return r

def board(nodes, has_next=False, cursor=None, total=None, root_key="organization"):
    return {"data": {root_key: {"projectV2": {
        "id": "PVT_x", "title": "B", "number": 9,
        "fields": {"totalCount": 0, "nodes": []},
        "items": {"totalCount": total if total is not None else len(nodes),
                  "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                  "nodes": nodes}}}}}

def item(i):
    return {"id": f"I{i}", "type": "ISSUE", "isArchived": False, "content": {"__typename": "Issue"}}

# ---- 1. the allowlist is configuration, not a code edit -------------------
def test_allowlist_default_matches_the_old_hardcoded_range():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("ACP_PROJECT_ALLOWLIST", None)
        assert gateway.project_allowed(3) and gateway.project_allowed(7)
        assert not gateway.project_allowed(9), "default must not silently widen"

def test_allowlist_can_admit_the_boards_that_were_unreachable():
    # 8 Worlds, 9 Evidence, 11 Publication Ingestion — all 400ed before.
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "2-9,11"}):
        for n in (2, 8, 9, 11):
            assert gateway.project_allowed(n), n
        assert not gateway.project_allowed(10)

def test_allowlist_wildcard_and_rejection_of_nonsense():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}):
        assert gateway.project_allowed(9999)
        assert not gateway.project_allowed(0) and not gateway.project_allowed(-1)

# ---- 2. more than 100 items is paged, not silently truncated --------------
def test_pages_past_the_hundred_item_cap():
    pages = [board([item(i) for i in range(100)], has_next=True, cursor="c1", total=150),
             board([item(i) for i in range(100, 150)], has_next=False, total=150)]
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(p) for p in pages]) as u:
        out = gateway.project_context("Anime-Universe", "9")
    assert out["items_fetched"] == 150, out["items_fetched"]
    assert out["items_total"] == 150
    assert out["truncated"] is False
    assert out["pages"] == 2 and u.call_count == 2

def test_truncation_is_reported_not_hidden():
    # A board still paging when MAX_PAGES is hit must say so. The old gateway
    # returned exactly 100 items and no way to tell it was a cap.
    pages = [board([item(i) for i in range(100)], has_next=True, cursor=f"c{p}", total=99999)
             for p in range(gateway.MAX_PAGES)]
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(p) for p in pages]):
        out = gateway.project_context("Anime-Universe", "9")
    assert out["truncated"] is True
    assert out["pages"] == gateway.MAX_PAGES

def test_short_count_against_totalcount_is_also_truncation():
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(board([item(1)], has_next=False, total=40))]):
        out = gateway.project_context("Anime-Universe", "9")
    assert out["truncated"] is True, "1 of 40 fetched must not read as complete"

# ---- 3. user-owned boards, not organizations only ------------------------
def test_falls_back_to_a_user_owned_board():
    org_miss = {"data": {"organization": None},
                "errors": [{"message": "Could not resolve to an Organization"}]}
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(org_miss), resp(board([item(1)], root_key="user"))]):
        out = gateway.project_context("someuser", "9")
    assert out["owner_type"] == "user"
    assert out["items_fetched"] == 1

def test_genuinely_missing_board_still_raises():
    miss = {"data": {"organization": None, "user": None}}
    with patch.dict(os.environ, {"ACP_PROJECT_ALLOWLIST": "*"}), \
         patch("gateway.installation_token", return_value={"token": "t"}), \
         patch("gateway.urlopen", side_effect=[resp(miss), resp(miss)]):
        try:
            gateway.project_context("nobody", "9")
        except RuntimeError:
            return
    raise AssertionError("a missing board must raise, not return an empty snapshot")

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("  ok", fn.__name__)
    print(f"{len(fns)} access tests passed")
