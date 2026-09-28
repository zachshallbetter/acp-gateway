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

4. Before enabling the strict flag, use `scripts/register-policy.py --sign-all --apply` to replace every active policy with a signed version. Confirm the returned registry summary and deployment health.
5. Run `python3 scripts/validate-deployment.py --url "$ACP_GATEWAY_URL" --require-security`. The command prints only sanitized control status.
6. Verify restart continuity: record the authenticated app-status and security summary, redeploy/restart once, then confirm the persisted containment and audit-chain state remains available.

The current Railway deployment is not in this profile until all six steps are completed. Do not set `ACP_REQUIRE_PRODUCTION_CONTROLS=1` before signing every live policy and attaching durable storage.
