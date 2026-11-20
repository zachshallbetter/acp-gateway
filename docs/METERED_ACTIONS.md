# Metered actions: client contract and rollout

ACP decides five actions that cost money or reach production: `hosted_build`, `production_merge`,
`manual_ci`, `local_heavy_build` and `heavy_subagent`, and a sixth that shares the machine:
`build_admission`, asked by the `reg` build register before a build takes a slot. The README's Policy authority section says how
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
| `hosted_build` | `trigger` (`push`, `cli_deploy`, `railway_up`), `ref`, `new_sha`, `reason` | `ref` may be left out for `cli_deploy` and `railway_up`, which deploy the linked project from any checkout, detached included; `railway_up`, and `cli_deploy` to a production branch, must name in `new_sha` a commit merged into the production branch whose check runs passed (`acp deploy` does this); `priority` `{blocking: continue_work\|release\|fix, reason}` when the agent cannot continue without this push |
| `production_merge` | `trigger` (`merge`, `promote`), `ref` (the production branch), `new_sha` (the merge result), `reason` | |
| `manual_ci` | `trigger` (`workflow_dispatch`, `rerun`), `workflow` (`.github/workflows/<file>.yml`), `ref`, `new_sha`, `reason`; `run_id` for a rerun | |
| `local_heavy_build` | `tool_use_id`, `machine_id`, `reason` | `repository_claim` |
| `heavy_subagent` | `tool_use_id`, `model` (opus or fable), `reason`, and top-level `session_id` | `repository_claim` |
| `build_admission` | `tool_use_id` (the register's ticket), `machine_id`, `reason`, `admission` (below) | `repository_claim`, top-level `session_id` |

`admission` is the register's facts at the moment of admission: `{contract, project, repo, label,
command, cache (shared, private, not_cargo), attribution {session_id, host_session_id,
message_address, subagent, interactive}, running [{project, command, session_id, receipt_id, since}],
queued_projects [...]}`. ACP evaluates four properties on them, each SATISFIED, VIOLATED or GRAY:
`attributable` (a session, or the owner at a terminal), `not_duplicate` (no identical build running for
the project), `within_project_share` (the project holds fewer slots than the contract allows while
other projects wait) and `shared_cache`. The contract maps them to a decision:

| Property state | Default contract | Decision |
|---|---|---|
| `not_duplicate` VIOLATED | `duplicates: refuse` | `DENY BUILD_DUPLICATE`, naming the running build and how to combine steps |
| `attributable` GRAY | `unattributed: refuse_unless_interactive` | `DENY BUILD_UNATTRIBUTED` |
| `shared_cache` VIOLATED | `private_cache: note` | recorded; `refuse` makes it `DENY BUILD_PRIVATE_CACHE` |
| `within_project_share` VIOLATED | `project_slots_while_others_wait: 1` | `REVERIFY_REQUIRED PROJECT_SHARE_EXCEEDED`: the register keeps it queued and asks again |
| otherwise | | `ALLOW BUILD_ADMITTED` |

The contract is the signed budget policy's optional `build_admission` block (`version`,
`project_slots_while_others_wait`, `duplicates`, `unattributed`, `private_cache`); a policy without
one uses the defaults above. Every answer carries `admission_state` and `admission_contract`, and
the audit event records the project, command and attribution.

`ref` is a full `refs/heads/...` name and `new_sha` a full commit id. `reason` is one sentence, 8 to
512 characters. The client does not decide which providers build: ACP reads that from the providers
at `new_sha`.

## Response

The standard decision envelope, plus:

| Field | When | Meaning |
|---|---|---|
| `remedy` | every refusal | The next step. Show it to the agent as written. |
| `grant_request` | a refusal an owner grant would clear | `{action, repository, uses, expires, reason, command}`: `command` is complete and runnable as is, with the request's reason. Show it to the owner. |
| `builds` | repository actions | `[{provider, project, project_id, would_build, why}]` for each connected provider and workflow. |
| `budget` | repository actions | `{day, usage: [{scope, used, limit, limit_source?, source?, enforced?}], exceeded?}`. Scopes: `project <provider>/<name>` and `service <provider>` are enforced; the repository and deployment-wide totals carry `enforced: false`. The audit record of a decision that crossed a limit carries the same `budget.exceeded` (`scope`, `used`, `limit`, `kind`); decisions within budget carry no `budget` there. |
| `advice` | repository actions, allow and refusal | `{project_usage: [{provider, project, used_today, limit, limit_source, builds_last_30m, last_build_seconds_ago}], service: [{provider, source, ceiling, deployments_today, in_flight, lower_bound?}], triggers: [{provider, project, would_build, why}], recommendations: [{code, text}], resets_at}`; on a budget refusal also `usage_by_repository: [{repository, used}]`. Recommendation codes: `BATCH_PUSHES`, `NEAR_LIMIT`, `WAIT_FOR_INFLIGHT`, `PREVIEW_BUILDS`, `SAME_COMMIT`, `MULTI_SERVICE`, `SERVICE_BUSY`, `WORKFLOW_UNBOUNDED_ON_BRANCH` (a workflow read at the branch lacks a timeout or concurrency group; advice only, the merge is refused until it is bounded), `CAPACITY_UNREAD` (a service's live activity could not be read, so its in-flight cap is not applied and its count is ACP's ledger; or `lower_bound` marks a count past what ACP reads in one pass). Show each `text` to the agent. |
| `retry_after` | `REVERIFY_REQUIRED` `BUILD_PACED`, `BUILD_IN_FLIGHT`, `BUILD_BURST`, `SERVICE_AT_CAPACITY`, `CI_PENDING`, `PROVIDER_EVIDENCE_UNAVAILABLE` with no credential | Seconds until asking again can succeed. Commit locally meanwhile. For a missing credential it is an hour: the owner must act first. |
| `provider_error` | `PROVIDER_EVIDENCE_UNAVAILABLE`, `PROVIDER_RESPONSE_DIVERGED` | `{provider, kind}`, plus `missing_setting` (`ACP_VERCEL_TOKEN`, `ACP_RAILWAY_TOKEN`) when the provider has no credential: the remedy says not to retry and names the setting the owner adds to the ACP deployment on every host. |
| `release` | a production CLI deploy refused for its commit | `{sha, branch, merged, ci_expected, checks: {total, pending, failed}}`: whether `new_sha` is on the production branch, and its check runs still going and failed, by name. |
| `retryable` | `false` on a refusal only the owner can clear: `ACTION_NOT_IN_POLICY`, `POLICY_NOT_FOUND`, `POLICY_INVALID`, `POLICY_INACTIVE`, `REPOSITORY_NOT_GOVERNED`, `METERED_ACTION_NOT_ENABLED` | Do not ask again; hand the `remedy` to the coordinator. |
| `owner_command` | `ACTION_NOT_IN_POLICY` | `policy-admin.py meter OWNER/NAME --protect ACTION --apply`, with the deployment's `ACP_GRANT_COMMAND_PREFIX`. ACP supports the action but the repository's policy omits it; only the owner can add it. |
| `priority_request` | a refusal priority would clear | `{field: "context.priority", blocking: [...], remaining_today, example}`. |
| `resets_at` | budget refusals | When today's budgets reset (00:00 UTC). |
| `authorized_action` | `ALLOW` | `{action, ref, new_sha, trigger, workflow?, run_id?}`. Proceed with exactly this. |
| `lease_id` | `heavy_subagent` `ALLOW` | Send it to `POST /internal/subagent/release` when the subagent stops. |
| `replayed` | a repeat of an allowed request | The earlier record stands; nothing was counted again. This includes a merge whose builds ACP already counted for the push of the same commit, and the reverse. |
| `caller_kind` | metered actions | `shared`, `lane`, `coordinator` or `owner`, as ACP identified the caller. |

## What the hook does

| Answer | Hook effect |
|---|---|
| `ALLOW` | Allow the tool call. For `heavy_subagent`, remember `lease_id` for the stop event. |
| `DENY`, `AUTH_REQUIRED`, `REVERIFY_REQUIRED`, `QUARANTINE`, `LOCKED` | Deny the tool call with `reason` and `remedy` in `permissionDecisionReason`, so the agent sees the way forward. |
| No answer (unreachable, timeout, non-JSON, 5xx) for `hosted_build`, `production_merge`, `manual_ci` | Deny: no paid build without a decision. Say that ACP was unreachable and that the work can be committed locally and pushed later. |
| No answer for `local_heavy_build` | Fall back to the local rule: run it through `reg build`. |
| No answer for `heavy_subagent` | Fall back to the local rule: light models only. |
| No answer for `build_admission`, or a reason outside the admission vocabulary | The register applies the same default contract itself and says so in its receipt (`decided_by: register`). |

On every answer the hook prints each `advice.recommendations[].text`; with `retry_after` it says when
to ask again, and with `priority_request` how to ask for priority (`ACP_PRIORITY="<blocking>: <reason>"`
in the bootstrap client).

A CLI deploy (`cli_deploy`, `railway_up`), `workflow_dispatch` or `rerun` starts a new run each time, so each invocation is counted. `context.tool_use_id` names one tool call: the same caller may repeat it within ten minutes and it is counted once; another caller, or the same one later, gets `DENY INVOCATION_REUSED`: send the id of the actual tool call, or none. For `heavy_subagent` the same refusal answers an id whose lease was already released.

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
2. **Budget policy.** `scripts/policy-admin.py budget-policy --apply` signs the default limits and stores
   them. Every `policy-admin.py` write is one signed document in the shared database, which both hosts load
   within seconds (README, "Policy configuration and signing").
3. **Provider credentials.** Set `ACP_VERCEL_TOKEN` (scoped to every team that holds a metered project),
   `ACP_RAILWAY_TOKEN` and, optionally, a default `ACP_VERCEL_TEAM_ID` on the deployment. The GitHub App needs read access to Actions and Checks for run counts. Organization
   billing reads need the organization's Administration (read) permission. Personal-account Actions
   spend is not readable through an App, so the posture report lists it as unreadable.
4. **Meter repositories.** `scripts/policy-admin.py meter OWNER/NAME --vercel <project id> [--vercel-team <team id>]
   [--railway-project <id> --railway-service <id>] --apply` for each governed repository. `meter` replaces the
   providers with the ones named; to add only an action, keeping the metered block, use
   `scripts/policy-admin.py protect OWNER/NAME database.migrate --apply`. Dry runs print the protected-action and
   provider changes, and `--apply` refuses when the signed content would not change.
5. **Callers.** `scripts/policy-admin.py caller <id> --kind coordinator --repo OWNER/* --apply` for each
   coordinator, and `--kind lane` for each lane. Until then the shared bearer counts as a lane.
6. **Posture.** `scripts/posture-report.py --refresh` and fix the high findings.
7. **Hooks.** Release the bootstrap's thin-client hooks (tracked in the bootstrap repository).

Railway on file storage answers every metered action with `BUDGET_LEDGER_UNAVAILABLE`, pointing
clients at the PostgreSQL endpoint. Set `ACP_STORAGE_BACKEND=postgres` and the shared database URL on
Railway to have both hosts enforce the same budgets.
