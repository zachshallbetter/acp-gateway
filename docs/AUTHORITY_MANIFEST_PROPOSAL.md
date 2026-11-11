# Authority requirements: proposed manifest and staging-deployment vertical slice

Status: **design proposal**, not a shipped protocol, API, or authorization grant.
Date: 2026-11-11. Working name: **Authority Manifest** (more precisely, an *authority requirements manifest*).
Companion: [Latchkey integration boundary](https://github.com/zachshallbetter/latchkey/blob/docs/authority-manifest-staging-slice/docs/authority-manifest-integration.md).

## Thesis

Software should describe what it **needs to do** without possessing every credential that could do it. The declaration of a requirement does not confer permission. Distinguish:

1. **Requirements**: untrusted or reviewable statements of desired resources/operations.
2. **Authorization**: independent decision based on actor, owner, server-side policy, current trusted context and request.
3. **Enforcement**: the adapter/provider must be able to constrain the *actual* operation to the approved request.
4. **Evidence**: retain request, decision, bound execution attempt, provider response and observations as distinct events.

The product is not a replacement vault, policy store, or agent platform. It is a contract describing requirements for other components to evaluate. No code in this PR implements the format.

## Illustrative format (NOT a stable schema)

A checked-in project manifest is **input**, never an authority source:

```yaml
apiVersion: authority.example/v0
project: shop
requirements:
  - id: database-read
    resource: database
    operation: read
    scope: shop-staging
    environment: staging
  - id: deploy-staging
    resource: deployment
    operation: deploy
    project: shop
    environment: staging
  - id: provider-inference
    resource: ai-provider
    operation: inference
    provider: openai
```

A separate **per-invocation request** (authenticated outside the manifest) binds the actual target:

```json
{
  "requirement": "deploy-staging",
  "repository": "owner/shop",
  "revision": "73a1...FULL_IMMUTABLE_COMMIT_SHA",
  "target": {"provider": "example-deployer", "project": "shop", "environment": "staging"},
  "actor": "agent-session-identity",
  "request_id": "unique-random-id"
}
```

The illustrative strings above do not define provider support or an authenticated actor scheme. In particular, the mutable branch name, human-readable "revision 73", and a repository-provided claim are not sufficient proof of target or caller identity.

### Trust boundaries

- Manifest is **untrusted project data**. Git diffs and review can inform policy but cannot grant access.
- Owner/signer-approved policy is outside the repository and never silently modified by a manifest change. Existing ACP server-side policy remains authoritative.
- Required authority, approved authority, **enforceable authority**, and effective provider privilege must be evaluated separately.
- Required permission is not necessarily equivalent to a vault credential: one key may cover many requested operations.
- Treat unknown mapping or unsupported provider-level constraints as **not proven enforceable**. Reject or require visibly broader authorization; never silently widen.
- No execution token is placed in the manifest, logs, or agent output.
- The exact approved request must bind actor identity, repository/trust state, immutable revision, target provider/account/project/environment, operation, parameters, expiry and anti-replay identifier.
- Decide how the adapter learns the decision securely. A caller-supplied `ALLOW` string or unverified decision JSON does not suffice.
- Provider success is an **observation**. It is not proof that all intended consequences occurred or that no out-of-band side effects did.
- Approving a manifest change and approving one operation are different decisions.

## Initial vertical slice: Shop staging deployment

**Precondition:** An owner-approved server-side ACP policy allows narrowly defined staging deployments. A Latchkey-managed credential, with a stable identifier, exists for the deployment provider. A provider-specific adapter can verify project, environment and revision and can constrain operation adequately. If these conditions cannot be met, the demo must return a refusal instead of simulating enforcement.

1. Agent reads manifest to find `deploy-staging`; no credential values appear.
2. Latchkey offers a **metadata-only** inventory/match of candidate credentials and states known availability, not authorization.
3. Agent proposes immutable commit and exact staging target with authenticated identity.
4. ACP Gateway authenticates requester, evaluates **server-side** policy and trust, and produces a bound, limited-life decision (or `DENY`, `AUTH_REQUIRED`, `REVERIFY_REQUIRED`, `QUARANTINE`).
5. Execution adapter validates the bound decision and independently verifies target/revision, checks that it can enforce the restriction, executes once with a credential it holds or obtains by an authorized Latchkey path, and does not return the credential to agent.
6. Evidence captures request, requirement digest, decision/policy version, verified revision/target, enforceability result, attempt, provider outcome, and independent observations where possible.
7. Present **Requested / Allowed / Submitted / Observed** as separate statuses, including partial/unknown outcomes.

### Explicit negative cases

- Manifest asks for production administration although only staging is allowed: **blocked**.
- A malicious dependency or agent edits the manifest to request more authority: **no automatic grant**; new review and server-side policy evaluation required.
- Target changes after approval: **deny**, not "best effort".
- Authorized commit SHA changes or can't be verified: **deny/reverify**.
- Duplicate request/replay: **reject** unless explicit idempotent replay protocol is implemented.
- Caller injects someone else's approval: **reject**.
- A deployment credential can reach production but adapter cannot guarantee staging restriction: **deny or request explicit broader authorization**; no security claims based on prompt instructions.
- Latchkey reveals a raw deployment token to an arbitrary agent process: fails **mediated execution** acceptance even if retrieval was approved.
- Provider returns success but independent deployment health is unknown: record **submitted/succeeded at API, outcome unverified**.
- ACP unreachable or trustworthy audit sink unavailable where required: follow fail-closed policy.

### Acceptance demonstration

```
Shop / Staging                     (conceptual UI)
Database read        matching credential, scope known   AVAILABLE, not yet authorized
Deploy SHA 73a1...   exact staging target               AUTH REQUIRED -> ALLOW -> VERIFIED
Production admin     exceeds manifest and policy       BLOCKED
```

The demo must be inspectable: show the manifest diff, ACP decision/reason, which party held the credential, enforcement verdict, and evidence with redacted IDs. No simulated "secure" badge or fabricated provider proof.

## Component ownership

| Component | Responsibility | Does not grant |
| --- | --- | --- |
| Project manifest | Proposes operations and resources | Any permission |
| Latchkey | Credential identity, storage, metadata match, access broker, supported mediated use | Project authorization solely because a reference exists |
| ACP Gateway | Independently authenticates, evaluates server policy/trust, issues bounded decision, logs policy evidence | Provider-side restriction without adapter cooperation |
| Execution adapter | Validates decision and executable target; performs constrained provider call | Permission to expand the approved scope |
| Evidence record | Records decision, attempt and observations with clear provenance | Proof of all downstream effects |

### Compatibility with ACP Gateway today

ACP presently exposes `POST /internal/authorize` with server-side policy decisions and reason codes. That **does not imply** this document's manifest parsing, context-bound decision artifact, nonce/replay controls, signed handoff, deployment adapter or end-to-end execution evidence exists. Do not reinterpret existing `ALLOW` as a reusable bearer token.

A subsequent implementation issue must first inspect the API's existing request/response, authenticated actor model, durable audit controls and decision lifetime. Prefer new versioned interfaces over silently broadening an existing action's semantics.

## Implementation sequence (tickets, not commitments)

- [ ] Define and version the requirement schema, including normalization and canonical digest; reject ambiguous aliases.
- [ ] Threat model manifest edits, provenance, cross-repo confusion, replay, injection, confused-deputy paths, broker compromise and provider side effects.
- [ ] Build read-only requirements parser + comparison with current policy; no writes, keys, or execution.
- [ ] Specify Latchkey metadata match contract; require positive authorization for every credential use.
- [ ] Specify ACP decision binding, expiry, replay defense, signatures or authenticated channel, and reasons for impossible constraints.
- [ ] Implement a **single** staging provider adapter with an explicit enforceability proof/check and no fallback to broad raw-token handoff.
- [ ] Implement evidence envelope (request, decision, execution, observation), immutable identifiers and privacy-aware retention.
- [ ] Add tests for all positive and negative cases above; independently test production-target block.
- [ ] Film one real demonstration with redacted traces, not concept mock data disguised as implementation.

## Editorial continuation

Next essay: **The Authority a Project Carries**

Subtitle: *What changes when software can declare the permissions it needs, rather than inherit the privileges of whoever runs it?*

Opening example: an agent can install packages, build, and test a repository, but reaches a staging deployment and asks for a broadly privileged token. Its dependency manifests are precise; the authority it actually needs is not.

Argument: software dependency vs authority dependency; requested permission isn't granted permission; declarations can be hostile; authorize independently; match capabilities to enforceable actions; track what was requested, decided, submitted and observed. Build the narrative around **one staging deployment** rather than cataloging theoretical agent threats.

Do **not** present a hypothetical manifest as an existing standard or treat this design document as deployed behavior.

Third essay: **The Difference Between Permission and Proof**, about the verification gap between decision, enforcement and observed outcomes.
