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
- Bootstrap's local work is committed on `feat/issue-16-outage-safe-bootstrap`
  (renamed from the never-pushed `codex/issue-16-outage-safe-bootstrap`), four
  or more commits ahead of `bfef2e8`. The earlier Codex worktree candidate is on
  `feat/acp-client-failover` at `8cd9259`. Neither is on GitHub.
- CUDA's primary checkout is on `main` at `850ccad`. The publication commit
  `405e692` is on `docs/site-product-pages` with no upstream; the ACP
  integration changes are on `chore/acp-endpoint-registry` at `789a4c8`.
  `site-content-live` was deleted. Earlier references to `4dff8d8` are historical.
- `7815fc7` exists on no GitHub ref (#37). Locally it is reachable from
  `feat/acp-shared-state-failover` and the tag `deploy/production-7815fc7`.

## Production incident, 2026-11-03

- 01:59Z: `dpl_Gi91Xh9iQPfaLJXy2LKAbJAbMETJ`, a dashboard redeploy of `main`
  at `3ff0b83`, took the production alias. `main` has no `api/index.py` or
  `vercel.json`, so `/health`, `/ready` and `/notice` returned Vercel 404 and
  every ACP-bound repository failed closed. The git deployment of the same
  commit at 08:44 (`dpl_92BpFtsPSnoGb1LRDbbcbbPscsG8`) is equally unusable.
- ~02:10Z: under the owner's instruction to recover autonomously, the alias was
  rolled back to `dpl_F9anHAxXoa8XvsTtgaLLKHDaGtnU`. `/health` and `/ready`
  returned 200 with PostgreSQL and a consumer `notice` returned governed and
  NORMAL. Vercel set `autoAssignCustomDomains=false`, so production builds of
  `main` no longer take the alias until one is promoted. ACP could not decide
  its own recovery while down; the transition is recorded as a deviation in
  `records/deviations.jsonl` and still has to be reported to ACP.
- Until the runtime lands on `main`, `main` is not deployable. Do not promote a
  production build of `main`, and do not re-enable domain auto-assignment.

## Preview is not a release gate

Decided by the owner on 2026-11-03. Preview needed its own keys, policy and a
clean database just to imitate production, and its database had already been
migrated to `0007` by the broad candidate's Preview deployments. Releases are
instead verified on the **unpromoted production deployment**: with
`autoAssignCustomDomains=false`, a production build of `main` gets its own URL
with production's real configuration and database while the alias stays on the
known-good deployment.

`scripts/vercel-build.py` runs as Vercel's `buildCommand` with the deployment's
own database URL, never printed:

- **Production** builds check the database read-only. Pending or conflicting
  migrations fail the build, so a release the production database does not
  match cannot be built or promoted. Production migrations remain a separate
  ACP-authorized `scripts/migrate-db.py` run.
- **Preview** builds report the schema state as a warning and never write or
  fail because of it.
- A commit without `api/index.py` and `vercel.json` refuses to build.

Preview still holds the variables provisioned on 2026-11-03 (production's
GitHub App and flags by widened target; Preview-only signing keys and a policy
re-signed under `acp-preview-policy-hmac-sha256`). They are unused by the
release process and can be removed. Preview's `ACP_DATABASE_URL` points at a
database migrated to `0007` by `feat/acp-shared-state-failover`; keep it for
that candidate.

`scripts/migrate-db.py --check` is read-only and remains the way to inspect any
database by hand (exit 0 current, 3 pending, 1 conflict).

## Credential and client findings

- The production `ACP_GATEWAY_TOKEN` was rotated 2026-10-30 06:52Z. The
  machine Keychain item `ACP Gateway Production / ACP_GATEWAY_TOKEN`, which the
  endpoint registry names, still holds the pre-rotation token (fingerprints
  differ; values were never printed). Repositories that carry the token in
  `.env.local` authenticate; repositories that rely on the Keychain get 401.
- Vercel `sensitive` variables (signing keys, GitHub App key, database URLs,
  Preview token) are write-only and read back empty by design. Empty display is
  not evidence of a missing value.
- The client's 2s readiness limit rejected a healthy endpoint answering in
  1.3-1.6s warm; fixed in bootstrap `f7448b8`. Rejected credentials and a
  missing gateway URL are now explained (`833a1b1`). See #38.
- `formal-project-bootstrap` has no ACP policy: a push request returned
  `DENY / POLICY_NOT_FOUND` (`8b97b0d35ef82656`).

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
2. Verify the candidate against an isolated database (done locally) and then
   on the unpromoted production deployment of `main`. Require exact migration
   checksums (enforced by the production build), audit initialization,
   structured storage refusals, route preservation, gate fields, and exact
   migration scope in decisions/capabilities. Never infer correctness from the
   live alias's health response or from a successful build.
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
