#!/usr/bin/env bash
# Pull verified deliveries from the Railway receiver and run one bounded local cycle.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECEIVER_URL="${COORDINATOR_RECEIVER_URL:?set COORDINATOR_RECEIVER_URL}"
BRIDGE_TOKEN="${COORDINATOR_BRIDGE_TOKEN:?set COORDINATOR_BRIDGE_TOKEN}"
# Poll slowly by default; webhook delivery is the signal, and an empty queue
# must not create a rapid coordinator wake/retry loop. Override for supervised
# local testing with COORDINATOR_POLL_SECONDS.
POLL_SECONDS="${COORDINATOR_POLL_SECONDS:-60}"
ONCE=0
while [ $# -gt 0 ]; do case "$1" in --once) ONCE=1; shift;; *) echo "usage: coordinator-bridge.sh [--once]" >&2; exit 2;; esac; done

LOCKDIR="${COORDINATOR_LOCKDIR:-${TMPDIR:-/tmp}/github-projects-coordinator.lock}"
if ! mkdir "$LOCKDIR" 2>/dev/null; then echo "coordinator bridge already running" >&2; exit 0; fi
trap 'rmdir "$LOCKDIR" 2>/dev/null || true' EXIT

run_cycle() {
  local batch delivery outcome
  batch="$(curl --fail --silent --show-error --max-time 30 -H "Authorization: Bearer $BRIDGE_TOKEN" "$RECEIVER_URL/internal/deliveries?limit=1")"
  printf '%s' "$batch" | jq -e '.schema_version == "github.coordinator.event.v1"' >/dev/null
  delivery="$(printf '%s' "$batch" | jq -r '.deliveries[0].delivery_id // empty')"
  [ -n "$delivery" ] || return 1
  if "$SCRIPT_DIR/coordinator.sh" --queue ready --max-items 1 --apply --no-merge; then outcome=succeeded; else outcome=failed; fi
  curl --fail --silent --show-error --max-time 30 -X POST -H "Authorization: Bearer $BRIDGE_TOKEN" -H 'Content-Type: application/json' --data "{\"status\":\"$outcome\"}" "$RECEIVER_URL/internal/deliveries/$delivery" >/dev/null
  printf 'bridge: delivery=%s outcome=%s\n' "$delivery" "$outcome"
}

while :; do
  if ! run_cycle; then :; fi
  [ "$ONCE" -eq 1 ] && exit 0
  sleep "$POLL_SECONDS"
done
