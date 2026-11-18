# Security policy

acp-gateway decides whether agents may take protected actions, so a flaw in it can let an agent do
something its owner did not authorize. Reports are welcome.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Report it privately through GitHub: open the repository's [Security advisories](https://github.com/zachshallbetter/acp-gateway/security/advisories/new)
page and choose **Report a vulnerability**.

This is a solo-maintained project: responses are best-effort, with no guaranteed response time.

Include the commit you tested, the request or configuration that shows the problem, and what you
expected ACP to decide. Test only against a deployment you run yourself, with dummy repositories and
tokens; do not send traffic to someone else's gateway.

## Scope

In scope: `gateway.py`, `metering.py`, `providers.py`, `posture.py`, `postgres_store.py`, the
migrations, `api/index.py`, and the operator scripts under `scripts/`.

The vendored `.agents/skills/github-projects` scripts are in scope where they act on ACP's decisions.

## Supported versions

Only the latest commit on `main` receives fixes.
