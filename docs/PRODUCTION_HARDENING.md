# Production hardening transition

The gateway supports an explicit fail-closed production profile. The transition is intentionally staged because enabling a signing key rejects any currently unsigned policy, and enabling a persistent state file changes restart behavior. `python3 scripts/harden-railway.py` performs a read-only preflight; applying requires both `--apply --confirm-production` and an attached Railway volume.

1. Generate policy and capability keys in the approved secret manager. Do not place them in the repository, shell history, logs, or command arguments.
2. Create and attach a Railway volume to `acp-gateway`, mounted at `/data`. Use `railway volume list --json` to verify the volume and `railway volume add --service acp-gateway --mount-path /data --json` only when the exact service and environment have been confirmed.
3. Configure these Railway variables using `railway variable set KEY --stdin` so secret values do not appear in process arguments:

   - `ACP_POLICY_SIGNING_KEY`
   - `ACP_CAPABILITY_SIGNING_KEY`
   - `ACP_SECURITY_STATE_FILE=/data/security-state.json`
   - `ACP_AUDIT_LOG=/data/audit.jsonl`
   - `ACP_AUDIT_HASH_CHAIN=1`
   - `ACP_REQUIRE_PRODUCTION_CONTROLS=1`

4. Before enabling the strict flag, make sure every active policy is signed: `scripts/register-policy.py --local FILE --sign-all` re-signs a copy for review, and `scripts/policy-admin.py` stores signed versions. Confirm the returned registry summary and deployment health.
5. Run `python3 scripts/validate-deployment.py --url "$ACP_GATEWAY_URL" --require-security`. The command prints only sanitized control status.
6. Verify restart continuity: record the authenticated app-status and security summary, redeploy/restart once, then confirm the persisted containment and audit-chain state remains available.

Both production hosts run this profile: on 2026-11-15 `validate-deployment.py --require-security` reported policy signing, capability signing, persisted security state, the audit log and its hash chain on Railway and on Vercel. Step 6 stays a check to repeat after any storage change. Do not set `ACP_REQUIRE_PRODUCTION_CONTROLS=1` on a new host before signing every live policy and attaching durable storage.

Both hosts run the same start-up configuration check (`gateway.boot_check`): the Railway server refuses to start when it fails, and the Vercel adapter answers every route but `/health` with `503 MISCONFIGURED` and logs the setting it names.

## Builds and releases

- Vercel builds only `main` from git (`vercel.json` `git.deploymentEnabled`); other branches start no preview build. `main` moves only by a release (`scripts/release.py`), so production builds happen on release. Railway has no GitHub source: it deploys only when `release.py` runs `railway up`.
- A release that stops after the merge prints the commands that return both hosts to the deployments they ran before it (`vercel rollback <previous deployment> --scope <team>`, and the Railway deployment to redeploy), next to the fix-forward route. Migrations are additive, so the previous release runs on the migrated schema.
