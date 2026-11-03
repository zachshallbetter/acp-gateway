# ACP recovery reconciliation

Reconciled 2026-11-02 after the owner paused other work and completed cleanup.
This record distinguishes preserved implementation from released behavior.
It does not authorize a protected effect or replace a signed ACP decision.

## Verified baseline

- ACP started clean on `main` at `3ff0b831c0073863bc072573b03549091964f393`,
  with one registered worktree. PR #36 merged the board-gate clarification.
  That commit contains neither `api/index.py` nor `vercel.json`.
- Vercel's production alias `acp-gateway.vercel.app` still selects
  `dpl_F9anHAxXoa8XvsTtgaLLKHDaGtnU`, a CLI deployment reporting source
  `7815fc7c1284cb5dea3e11d9460c80df123a1be9`. The deployment is READY;
  fresh public `/health` and `/ready` reads returned HTTP 200, and readiness
  reported PostgreSQL. These reads do not prove authorization, database parity,
  backup recoverability, or Titan availability.
- Bootstrap remains on `codex/issue-16-outage-safe-bootstrap` at `bfef2e8`
  with staged, unstaged, and untracked work. Preserve it during reconciliation.
- CUDA's primary checkout remains on `site-release-branding` at `c0b3bd8`
  with local ACP integration changes. Its clean publication worktree is on
  `site-content-live` at `405e692`, one commit ahead of its recorded origin/main.
  Earlier references to publication commit `4dff8d8` are historical.

## Preserved ACP candidates

| Candidate | Disposition | Evidence required before completion |
| --- | --- | --- |
| `fix/issue-11-vercel-gate-deploy` at `63b631e` | Minimal Vercel/PostgreSQL runtime candidate based on current main; retain | Exact deployed schema compatibility, runtime package and live route verification |
| `fix/issue-34-database-migrate-context` at `82d7590`, PR #35 | Migration request validation and exact revision binding; retain | Review with current main/runtime, request/capability refusal tests, authorized release |
| `feat/acp-shared-state-failover` at `bff9fb7` | Preserved broad candidate; extract by ticket rather than merge wholesale | Separate review of console, roles, activation, idempotency, migrations 0003–0007, and runtime behavior |
| `archive/stash-2026-09-23*` | Retain historical recovery references | Prove unique work is incorporated before removal |
| `fix/fail-incomplete-project-snapshots`, `fix/include-archived-project-items` | Retain pending ancestry/diff review | Establish equivalence to merged fixes before pruning |

The broad candidate forks from `1275ddb`, before the gate clarification.
Merging it indiscriminately risks replacing newer fixes and requiring five
additional database migrations merely to restore the runtime.

## Ticket dispositions

| Work | Disposition |
| --- | --- |
| #9, #30–#33 | Keep infrastructure umbrella and distinct parity, transport/credentials, local operator, and restore/drill deliverables. Historical Railway-source instructions need revision; Railway is offline, not a required recovery source. |
| #10 | Keep product umbrella, separate from immediate runtime recovery. |
| #11 | Keep open. PR #36 implements only gate-state clarification; full explanations and mutation contracts remain separate acceptance work. |
| #12–#15 | Keep console/roles, reviewed policy activation, exceptions, and Checks/webhooks separate. Each crosses a different authority boundary. |
| #16 | Keep closed for recorded local onboarding/client work. Its closure comment explicitly excludes live endpoint readiness. Closure is not proof that the bootstrap candidate was released. |
| #19, #28, #29 | Keep #19 as integration umbrella; #28 owns mutation execution/reconciliation, #29 owns policy-activation integration. Do not duplicate those implementations in the parent. |
| #20–#27 | Keep closed local fleet-migration records. #20's closure explicitly separates live enrollment/failover. CUDA #23 records local validation and historical live auth, not publication of its current candidate. |
| #34, PR #35 | Keep pending review/release. Request-schema support does not authorize or perform an archive database migration. |
| #17–#18 | Keep self-hosted release and end-to-end acceptance as downstream gates. Do not block basic runtime recovery on the entire product release. |

Remote issue states and closure comments were read; no issue, board field, or PR
was changed during this reconciliation. No new duplicate epic is needed.

## Recovery order

1. Prepare one focused runtime candidate from `63b631e` plus PR #35's changes.
   Preserve the mainline gate fix; include only migrations 0001–0002. This is
   local branch `fix/issue-30-runtime-reconciliation`, not a deployed release.
2. Verify the candidate against an isolated database and the actual Preview
   environment. Require exact migration checksums, audit initialization,
   structured storage refusals, route preservation, gate fields, and exact
   migration scope in decisions/capabilities. Never infer Preview correctness
   from Production's health response or from a successful build.
3. Obtain exact authorization for the final source/ref and each protected
   release effect. Deploy to the existing project, verify routes and contracts,
   then promote only the verified artifact. Preserve the known-good deployment
   until rollback has been verified. No push or promotion is part of this record.
4. Complete #11's remaining decision/action contract and #28's executor.
   Boardless issue operations must remain independent of a Ready board item;
   project-item changes require the exact board. Local E0/E1 work continues
   without granting remote mutation authority. Unknown outcomes require
   reconciliation before retry.
5. Reconcile bootstrap's existing local candidate, release it through its own
   workflow, then verify each consumer's adoption and enrollment separately.
   A closed local migration ticket is not evidence of a released client.
6. Complete #30–#33: actual shared-state parity, Titan HTTPS and distinct
   credentials, bounded eligible failover, local operator access, restore and
   failure drills. A second application host sharing Neon does not provide
   database-region resilience. Do not advertise failover before its live proof.
7. Deliver console/roles, policy activation, exceptions, Checks, and open release
   in their existing tickets. Each needs its own review and acceptance evidence.

## Cleanup boundaries

Preserve evidence, unmerged branches, and consumer modifications. Remove a
file only after identifying its replacement and checking references. Retire
obsolete build output only after identifying the deployment's source and a
working rollback. Credentials and database records are not cleanup targets.
Do not force-remove worktrees; ignored files and symlinks can contain the only
copy of local configuration or project assets.

Historical test reports remain historical. Fresh verification results belong
to the exact recovered candidate; skipped database checks remain unverified.

## Verification of this local candidate

- `.venv/bin/python test_gateway_policy.py`: 42 passed.
- `.venv/bin/python test_gateway_board_gate.py`: 16 passed.
- `.venv/bin/python test_vercel_adapter.py`: 8 passed, including structured
  storage-unavailable responses and route restoration.
- `git diff --check HEAD`: passed.
- The first attempts with system `python3` failed during import because that
  interpreter lacks `certifi`; those attempts did not execute tests. The
  existing repository environment supplied the dependencies for the passes above.
- No database connection, schema change, authenticated production request,
  push, merge, or deployment was performed. Database-backed concurrency,
  Preview route checks, and production contract verification remain outstanding.
