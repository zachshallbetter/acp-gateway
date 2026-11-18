# Contributing to acp-gateway

Thanks for your interest. ACP is a policy decision service, so a change is judged on whether every
decision it can produce stays correct, not only on whether the happy path works.

## Setup

Python 3.12 with the pinned dependencies:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Run the gateway locally as the README's "Running it" and "Self-hosting" sections describe, with dummy
tokens and a scratch policy file. Never use real credentials in development.

## Tests

Run every file listed in the README's "Tests" section, for example:

```sh
.venv/bin/python test_gateway.py
.venv/bin/python test_gateway_metering.py
.venv/bin/python test_providers.py
```

They mock GitHub, Vercel and Railway; no network or real credentials are needed. The PostgreSQL
checks (`test_postgres_store.py`, `test_migrate_db.py`, `test_vercel_build.py`) need
`ACP_TEST_DATABASE_URL` pointing at a loopback database whose name ends in `_test`.

## Conventions

- **Conventional commits:** `feat(metering): ...`, `fix(providers): ...`, `docs: ...`.
- **Fail closed.** Missing or unreadable evidence is never permission; an unknown value is an error.
- **Reason codes are a contract.** A new refusal gets a reason code and a remedy the agent can act on,
  and the README's reason-code list and docs/METERED_ACTIONS.md change with it.
- **One canonical resolver per concept.** Extend the existing helper rather than adding a parallel one.
- **Migrations are additive** and marked `-- acp-migration: additive`; anything else is a separate,
  reviewed release step.
- **Documentation follows behavior:** the README and docs/ change in the same pull request as the code.

## Pull requests

Open one against `main` using the template. Keep each pull request to one change, with the tests that
show it. Security issues go through [SECURITY.md](SECURITY.md), never a public pull request or issue.
