#!/usr/bin/env bash
# onboard-project.sh — wire a repository to this ACP gateway.
#
#   scripts/onboard-project.sh <repo-path> [--owner O --project N] [--govern [--apply]] [--dry-run]
#
# Does the four things a project needs, and nothing else:
#
#   1. Vendors the `github-projects` skill into <repo>/.agents/skills/
#   2. Un-ignores `.agents/` in the repo's .gitignore  (see WHY #1)
#   3. Writes ACP_GATEWAY_URL / ACP_GATEWAY_TOKEN into <repo>/.env.local,
#      pulled from Railway, never printed                (see WHY #2)
#   4. Optionally binds the repo to a board via .agents/board.env
#
# Then it VERIFIES, because none of the above proves the path works:
# /health, an authenticated owner read, and — if a board was named — that the
# gateway reports that board as allowed=true. A formal-project-bootstrap project
# (PROJECT_PROFILE.json + scripts/acp-check.py) is also checked with its own
# acp-check, which additionally asks whether a policy governs the repository.
#
# --govern registers the repository's policy (scripts/register-policy.py, from
# the project's `scripts/acp.py policy` candidate when it has one). Without
# --apply that is a dry run; with it, ACP_POLICY is set on Railway, which
# redeploys the gateway.
#
# WHY #1. A global core.excludesFile that ignores `.agents/` (a common
# scaffolding default, and the one on this machine) makes `git add` report
# success while staging nothing. The skill then exists on exactly one machine
# and vanishes on the next clone. A global ignore cannot be overridden from
# anywhere but the repo's own .gitignore, so the negation must be written there.
#
# WHY #2. The token is a bearer credential for a service that mints GitHub App
# installation tokens. It belongs only in a git-ignored file. This script
# refuses to write it if .env.local is not actually ignored — checked with
# `git check-ignore`, not by reading .gitignore, because only git knows the
# answer once a global excludesfile is in play.
set -euo pipefail

GATEWAY_DEFAULT="https://acp-gateway-production.up.railway.app"
RAILWAY_SERVICE="${ACP_RAILWAY_SERVICE:-acp-gateway}"
RAILWAY_ENV="${ACP_RAILWAY_ENV:-production}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO=""; OWNER=""; PROJECT=""; DRY=0; GOVERN=0; APPLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --owner) OWNER="$2"; shift 2;;
    --project) PROJECT="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    --govern) GOVERN=1; shift;;
    --apply) APPLY=1; shift;;
    -h|--help) sed -n '2,38p' "$0"; exit 0;;
    *) REPO="$1"; shift;;
  esac
done
[ -n "$REPO" ] || { echo "usage: $0 <repo-path> [--owner O --project N] [--govern [--apply]] [--dry-run]" >&2; exit 2; }

REPO="$(cd "$REPO" && git rev-parse --show-toplevel)" || { echo "error: $REPO is not a git repository" >&2; exit 2; }
say() { printf '%s\n' "$*"; }
run() { [ "$DRY" = 1 ] && { say "    would: $*"; return 0; }; "$@"; }

# Preflight: refuse before mutating anything. A run that fails halfway leaves
# a repo half-configured, which is worse than one that never started.
ENVF="$REPO/.env.local"
if ! (cd "$REPO" && git check-ignore -q .env.local 2>/dev/null); then
  echo "error: .env.local is not git-ignored in $REPO — refusing to write a bearer token" >&2
  echo "remedy: add '.env.local' (or '.env*') to .gitignore, then re-run" >&2
  exit 1
fi

say "onboarding $REPO"
[ "$DRY" = 1 ] && say "  (dry run — nothing will be written)"

# 1. Vendor the skill. This repo's own copy is the source of truth; the global
#    one is the fallback for a machine that has no checkout of the gateway.
SRC="$HERE/.agents/skills/github-projects"
[ -d "$SRC" ] || SRC="$HOME/.claude/skills/github-projects"
[ -d "$SRC" ] || { echo "error: no github-projects skill found to vendor" >&2; exit 1; }
DST="$REPO/.agents/skills/github-projects"
if [ -d "$DST" ]; then
  say "  skill: already vendored"
else
  say "  skill: vendoring from $SRC"
  run mkdir -p "$(dirname "$DST")"
  run cp -R "$SRC" "$DST"
  [ "$DRY" = 1 ] || { rm -f "$DST/.DS_Store"; chmod +x "$DST"/scripts/*.sh 2>/dev/null || true; }
fi

# 2. Un-ignore .agents/ — see WHY #1.
if (cd "$REPO" && git check-ignore -q .agents/skills/github-projects/SKILL.md 2>/dev/null); then
  say "  gitignore: .agents/ is ignored (global excludesfile) — adding negation"
  if [ "$DRY" != 1 ]; then
    printf '\n# `.agents/` is tracked here: a global core.excludesFile that ignores it\n# makes `git add` silently stage nothing. Stated here because a global ignore\n# cannot be overridden anywhere else.\n!.agents/\n!**/.agents/\n' >> "$REPO/.gitignore"
  else say "    would: append !.agents/ to .gitignore"; fi
else
  say "  gitignore: .agents/ already trackable"
fi

# 3. Credentials → .env.local. Ignore status was checked in preflight.
if grep -q '^ACP_GATEWAY_URL=' "$ENVF" 2>/dev/null; then
  say "  credentials: already present in .env.local — left alone"
elif [ "$DRY" = 1 ]; then
  say "    would: append ACP_GATEWAY_URL / ACP_GATEWAY_TOKEN to .env.local"
else
  command -v railway >/dev/null || { echo "error: railway CLI not found; install it or set ACP_GATEWAY_TOKEN" >&2; exit 1; }
  TOKEN="${ACP_GATEWAY_TOKEN:-$(railway variables --service "$RAILWAY_SERVICE" --environment "$RAILWAY_ENV" --json 2>/dev/null | jq -r '.ACP_GATEWAY_TOKEN // empty')}"
  [ -n "$TOKEN" ] || { echo "error: could not read ACP_GATEWAY_TOKEN from Railway ($RAILWAY_SERVICE/$RAILWAY_ENV)" >&2; echo "remedy: 'railway link' to the agent-control-plane project, or export ACP_GATEWAY_TOKEN" >&2; exit 1; }
  { printf '\n# ACP gateway — board READS route here instead of local gh credentials.\n'
    printf '# Railway: service %s, environment %s. Never commit this file.\n' "$RAILWAY_SERVICE" "$RAILWAY_ENV"
    printf 'ACP_GATEWAY_URL=%s\n' "${ACP_GATEWAY_URL:-$GATEWAY_DEFAULT}"
    printf 'ACP_GATEWAY_TOKEN=%s\n' "$TOKEN"; } >> "$ENVF"
  say "  credentials: written to .env.local (token not printed)"
fi

# 4. Bind the board, if one was named.
if [ -n "$OWNER" ] && [ -n "$PROJECT" ]; then
  BOARD="$REPO/.agents/board.env"
  if [ -f "$BOARD" ]; then say "  board.env: already present — left alone"
  else
    say "  board.env: binding $OWNER #$PROJECT"
    [ "$DRY" = 1 ] || printf '# Committed. The gateway secret lives in .env.local, never here.\nGH_PROJECT_OWNER=%s\nGH_PROJECT_NUMBER=%s\n' "$OWNER" "$PROJECT" > "$BOARD"
  fi
fi

# 5. Verify. Configuration is not proof.
[ "$DRY" = 1 ] && { say "verify: skipped (dry run)"; exit 0; }
URL="$(sed -n 's/^ACP_GATEWAY_URL=//p' "$ENVF" | tr -d '"' | head -1)"
TOK="$(sed -n 's/^ACP_GATEWAY_TOKEN=//p' "$ENVF" | tr -d '"' | head -1)"
say "verify:"
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 20 "$URL/health") || code=000
say "  /health → HTTP $code"
[ "$code" = 200 ] || { echo "error: gateway not healthy at $URL" >&2; exit 1; }
if [ -n "$OWNER" ]; then
  body="$(curl -sS --max-time 25 -H "Authorization: Bearer $TOK" "$URL/internal/projects?owner=$OWNER")"
  if printf '%s' "$body" | jq -e '.error' >/dev/null 2>&1; then
    printf '%s' "$body" | jq -r '"  refused: \(.error) — \(.detail)\n  remedy:  \(.remedy // "-")"' >&2
    exit 1
  fi
  say "  owner $OWNER → $(printf '%s' "$body" | jq -r '(.projects // []) | length') boards visible"
  if [ -n "$PROJECT" ]; then
    allowed="$(printf '%s' "$body" | jq -r --argjson n "$PROJECT" '(.projects // [])[] | select(.number==$n) | .allowed')"
    say "  board #$PROJECT → allowed=${allowed:-not-visible}"
    [ "$allowed" = true ] || { echo "  remedy: add '$OWNER:*' or '$PROJECT' to ACP_PROJECT_ALLOWLIST on the gateway service" >&2; exit 1; }
  fi
fi

# 6. Governance. Wiring proves the gateway answers; only a policy makes it govern.
BOOTSTRAP=0
[ -f "$REPO/PROJECT_PROFILE.json" ] && [ -f "$REPO/scripts/acp-check.py" ] && BOOTSTRAP=1
if [ "$GOVERN" = 1 ]; then
  CANDIDATE="$(mktemp -t acp-policy.XXXXXX)"
  if [ "$BOOTSTRAP" = 1 ] && [ -f "$REPO/scripts/acp.py" ]; then
    (cd "$REPO" && python3 scripts/acp.py policy) > "$CANDIDATE"
    REG=(--from "$CANDIDATE")
  else
    REMOTE="$(cd "$REPO" && git remote get-url origin)"
    TAIL="${REMOTE%.git}"; NAME="${TAIL##*/}"; TAIL="${TAIL%/*}"; ROWNER="${TAIL##*[:/]}"
    REG=(--owner "$ROWNER" --name "$NAME")
    [ -n "$OWNER" ] && [ -n "$PROJECT" ] && REG+=(--board "$OWNER:$PROJECT")
  fi
  say "governance:"
  if [ "$APPLY" = 1 ]; then python3 "$HERE/scripts/register-policy.py" "${REG[@]}" --apply
  else python3 "$HERE/scripts/register-policy.py" "${REG[@]}"; fi
  rm -f "$CANDIDATE"
fi
if [ "$BOOTSTRAP" = 1 ]; then
  say "bootstrap acp-check:"
  if ! (cd "$REPO" && python3 scripts/acp-check.py); then
    # Only an ungoverned repository is tolerated here; any other refusal stops.
    (cd "$REPO" && python3 scripts/acp-check.py --allow-ungoverned >/dev/null 2>&1) || exit 1
    if [ "$GOVERN" = 1 ] && [ "$APPLY" = 1 ]; then say "  policy set; it is enforced once the redeploy finishes — re-run acp-check then"
    else say "  not governed yet: re-run with --govern (dry run), then --govern --apply"; fi
  fi
fi
say "done."
