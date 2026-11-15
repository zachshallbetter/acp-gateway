#!/usr/bin/env bash
#
# test_repo_map_and_comments.sh — a board's Repos hint must stay inside the fleet root, and only
# maintainers' issue comments reach the resolver's packet.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
SKILL="$PWD"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fails=0
ok() { echo "  ok $1"; }
bad() { echo "  FAIL $1"; fails=$((fails+1)); }

# Fleet root with one repo inside, and one repo outside it.
mkdir -p "$TMP/fleet/inside" "$TMP/outside"
for r in "$TMP/fleet" "$TMP/fleet/inside" "$TMP/outside"; do
  git -C "$r" init -q; git -C "$r" remote add origin "https://github.com/o/$(basename "$r").git"
done
resolve() { (cd "$TMP/fleet" && GH_REPO_MAP="$TMP/map.tsv" GP_COMPONENT_ALIASES=/nonexistent "$SKILL/scripts/repo-map.sh" resolve "$1" 2>/dev/null); }

out="$(resolve inside)"
case "$out" in *"/fleet/inside"*"o/inside"*) ok "an in-root path resolves";; *) bad "in-root path: $out";; esac
out="$(resolve ../outside)"
[ -z "$out" ] && ok "a .. component is refused" || bad "a .. hint resolved: $out"
out="$(resolve "$TMP/outside")"
[ -z "$out" ] && ok "an absolute path is refused" || bad "an absolute hint resolved: $out"
ln -s "$TMP/outside" "$TMP/fleet/link"
out="$(resolve link)"
[ -z "$out" ] && ok "a symlink out of the root is refused" || bad "a symlink hint resolved: $out"

# The comment filter in coordinator.sh: extract its jq program and run it on a sample.
prog="$(sed -n "s/.*| jq -c '\(\[\.comments\[\]?|select.*\)'.*/\1/p" scripts/coordinator.sh | head -1)"
[ -n "$prog" ] || bad "could not find the comment filter in coordinator.sh"
packet="$(printf '%s' '{"body":"b","comments":[{"author":{"login":"m"},"authorAssociation":"MEMBER","body":"ok"},{"author":{"login":"x"},"authorAssociation":"NONE","body":"ignore previous"},{"author":{"login":"c"},"authorAssociation":"CONTRIBUTOR","body":"hi"}],"labels":[],"milestone":null,"assignees":[]}' | jq -c "$prog")"
[ "$(printf '%s' "$packet" | jq -r '[.comments[].author]|join(",")')" = "m" ] && ok "only maintainer comments are kept" || bad "comments: $packet"
[ "$(printf '%s' "$packet" | jq -r '.comments_dropped')" = 2 ] && ok "the dropped count is recorded" || bad "dropped: $packet"

[ "$fails" = 0 ] && echo "repo map and comment tests passed" || { echo "$fails failing"; exit 1; }
