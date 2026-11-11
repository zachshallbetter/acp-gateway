# Metered actions: client contract and rollout

ACP decides five actions that cost money or reach production: `hosted_build`, `production_merge`,
`manual_ci`, `local_heavy_build` and `heavy_subagent`. The README's Policy authority section says how
ACP decides them. This document covers what a client sends, what it does with the answer, and how the
feature reaches production.

## Request

`POST /internal/authorize` with `Authorization: Bearer <token>` (the caller's own token from
`ACP_CALLERS`, or the shared bearer) and `Content-Type: application/json`:

```json
{
  "action": "hosted_build",
  "agent_id": "lane-media",
  "session_id": "<Claude Code session id>",
  "actor_id": "github-user:<id>",
  "repository_claim": {"owner": "OWNER", "name": "NAME", "remote_url": "https://github.com/OWNER/NAME.git",
                       "head_sha": "<40 hex>"},
  "context": {"trigger": "push", "ref": "refs/heads/feature-x", "new_sha": "<40 hex>",
              "reason": "preview for the media upload change"},
  "principal": {"client_type": "fpb-harness", "client_version": "0.8.1"}
}
```

| Action | Required `context` | Optional |
|---|---|---|
| `hosted_build` | `trigger` (`push`, `cli_deploy`, `railway_up`), `ref`, `new_sha`, `reason` | `provider` to count one provider only |
| `production_merge` | `trigger` (`merge`, `promote`), `ref` (the production branch), `new_sha` (the merge result), `reason` | |
| `manual_ci` | `trigger` (`workflow_dispatch`, `rerun`), `workflow` (`.github/workflows/<file>.yml`), `ref`, `new_sha`, `reason`; `run_id` for a rerun | |
| `local_heavy_build` | `tool_use_id`, `machine_id`, `reason` | `repository_claim` |
| `heavy_subagent` | `tool_use_id`, `model` (opus or fable), `reason`, and top-level `session_id` | `repository_claim` |

`ref` is a full `refs/heads/...` name and `new_sha` a full commit id. `reason` is one sentence, 8 to
512 characters. The client does not decide which providers build: ACP reads that from the providers
at `new_sha`.

## Response

The standard decision envelope, plus:

| Field | When | Meaning |
|---|---|---|
| `remedy` | every refusal | The next step. Show it to the agent as written. |
| `builds` | repository actions | `[{provider, project, would_build, why}]` for each connected provider and workflow. |
| `budget` | repository actions | `{day, usage: [{scope, used, limit}], exceeded?}` |
| `authorized_action` | `ALLOW` | `{action, ref, new_sha, trigger, workflow?, run_id?}`. Proceed with exactly this. |
| `lease_id` | `heavy_subagent` `ALLOW` | Send it to `POST /internal/subagent/release` when the subagent stops. |
| `replayed` | a repeat of an allowed request | The earlier record stands; nothing was counted again. |
| `caller_kind` | metered actions | `shared`, `lane`, `coordinator` or `owner`, as ACP identified the caller. |

## What the hook does

| Answer | Hook effect |
|---|---|
| `ALLOW` | Allow the tool call. For `heavy_subagent`, remember `lease_id` for the stop event. |
| `DENY`, `AUTH_REQUIRED`, `REVERIFY_REQUIRED`, `QUARANTINE`, `LOCKED` | Deny the tool call with `reason` and `remedy` in `permissionDecisionReason`, so the agent sees the way forward. |
| No answer (unreachable, timeout, non-JSON, 5xx) for `hosted_build`, `production_merge`, `manual_ci` | Deny: no paid build without a decision. Say that ACP was unreachable and that the work can be committed locally and pushed later. |
| No answer for `local_heavy_build` | Fall back to the local rule: run it through `reg build`. |
| No answer for `heavy_subagent` | Fall back to the local rule: light models only. |

The hook never retries a refusal unchanged. A retry with the same commit after a grant, a budget
reset or a fixed workflow is the normal path, and is safe: allowed actions are recorded once.

HOLD and the secrets guard stay local and owner-only. ACP does not replace them.

## Rollout

Each step is the owner's, in order. Nothing in this change sets a variable, applies a migration or
deploys.

1. **Migration 0003.** Applied 2026-11-11. At the time the release check was exact, so the running
   deployment answered 503 until the new one was promoted. From migration 0004 on, a migration whose
   first line is `-- acp-migration: additive` is recorded as such, and a running release keeps serving
   on a database that is ahead of it only by additive migrations; see "Migrations" in the README.
2. **Budget policy.** `scripts/policy-admin.py budget-policy --apply` signs the default limits into
   `ACP_BUDGET_POLICY` on both hosts. Every `policy-admin.py` write goes to Vercel and Railway together.
3. **Provider credentials.** Set `ACP_VERCEL_TOKEN` (scoped to every team that holds a metered project),
   `ACP_RAILWAY_TOKEN` and, optionally, a default `ACP_VERCEL_TEAM_ID` on the deployment. The GitHub App needs read access to Actions and Checks for run counts. Organization
   billing reads need the organization's Administration (read) permission. Personal-account Actions
   spend is not readable through an App, so the posture report lists it as unreadable.
4. **Meter repositories.** `scripts/policy-admin.py meter OWNER/NAME --vercel <project id> [--vercel-team <team id>]
   [--railway-project <id> --railway-service <id>] --apply` for each governed repository.
5. **Callers.** `scripts/policy-admin.py caller <id> --kind coordinator --repo OWNER/* --apply` for each
   coordinator, and `--kind lane` for each lane. Until then the shared bearer counts as a lane.
6. **Posture.** `scripts/posture-report.py --refresh` and fix the high findings.
7. **Hooks.** Release the bootstrap's thin-client hooks (tracked in the bootstrap repository).

Railway on file storage answers every metered action with `BUDGET_LEDGER_UNAVAILABLE`, pointing
clients at the PostgreSQL endpoint. Set `ACP_STORAGE_BACKEND=postgres` and the shared database URL on
Railway to have both hosts enforce the same budgets.
