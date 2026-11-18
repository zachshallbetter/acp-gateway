# Security policy

acp-gateway decides whether agents may take protected actions, so a flaw in it can let an agent do
something its owner did not authorize. Reports are welcome.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

<!-- OWNER: replace this line with the private reporting route (for example an email address or
     GitHub private vulnerability reporting). Until it is filled in there is no private route. -->
**Private reporting route: not yet published.**

Include the commit you tested, the request or configuration that shows the problem, and what you
expected ACP to decide. Test only against a deployment you run yourself, with dummy repositories and
tokens; do not send traffic to someone else's gateway.

## Scope

In scope: `gateway.py`, `metering.py`, `providers.py`, `posture.py`, `postgres_store.py`, the
migrations, `api/index.py`, and the operator scripts under `scripts/`.

The vendored `.agents/skills/github-projects` scripts are in scope where they act on ACP's decisions.

## Supported versions

Only the latest commit on `main` receives fixes.
