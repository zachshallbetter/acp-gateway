# acp-gateway

A small, dependency-free read-side gateway that lets agents read a GitHub
Projects (ProjectsV2) board without ever holding a GitHub App private key
themselves. One Python stdlib file (`gateway.py`), no framework, no
third-party packages — the whole surface fits in a few hundred lines on
purpose.

Originally built inside `Infinite-Verse` (`docs/ACP_GATEWAY_DEPLOYMENT.md`),
moved out here 2026-08-26 to be reused across every project that wants this
pattern, not just that one ecosystem.

## What it does

- Holds the GitHub App credentials (`ACP_GITHUB_APP_ID`,
  `ACP_GITHUB_INSTALLATION_ID`, `ACP_GITHUB_PRIVATE_KEY`) as the *only* place
  they live. They never reach an agent or leave this process.
- Mints a short-lived installation token per request (RS256-signed JWT,
  exchanged via the GitHub Apps API) — nothing is minted client-side or cached
  beyond the request.
- Exposes one useful authenticated read: `GET /internal/project-context?owner=&project=`
  — a live ProjectsV2 GraphQL snapshot (fields + up to 100 items) for an
  **allowlisted** project number (edit `project_context`'s range check per
  deployment; the shipped default is `2 <= project <= 7`, tuned for the repo
  this was extracted from — change it for a new project).
- `GET /health` (unauthenticated, for platform health checks) and
  `GET /internal/app-status` / `GET /internal/app-probe` (authenticated,
  for verifying the App credentials are configured and can actually mint a
  token) round out the surface.

## What it deliberately does not do

- No webhook receiving, no event queue. This is pull-only. (A companion
  webhook receiver is a separate service by design — see "Boundary" below.)
- No board writes. Claiming an item, setting a field, or mutating Project
  state happens through the agent's own scoped credentials, never through this
  gateway.
- No caching beyond process lifetime. Every `/internal/project-context` call
  mints a fresh installation token and issues a fresh GraphQL query.

## Boundary

This gateway must not be merged with or replaced by a webhook/event-receiving
service. If you also run a GitHub App webhook receiver (deliveries, queues,
a coordinator bridge), keep it as its own deployment — different failure
modes, different scaling shape, different credential exposure.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `ACP_GATEWAY_TOKEN` | yes | Bearer token every caller must present. Startup fails without it. |
| `ACP_GITHUB_APP_ID` | for App reads | The GitHub App's numeric ID. |
| `ACP_GITHUB_INSTALLATION_ID` | for App reads | The installation ID for the target org/repo. |
| `ACP_GITHUB_PRIVATE_KEY` | for App reads | The App's PEM private key, as a literal env value (not a file path). |
| `PORT` | no | Defaults to `8080`. |

`configured()` is `False` (and `/internal/app-status`, `/internal/app-probe`
report it) until all three App variables are set — `/health` still returns
`200` either way, so a deploy without App credentials still passes a basic
liveness check while clearly reporting it can't do App-authenticated reads
yet.

## Running it

```bash
docker build -t acp-gateway .
docker run -p 8080:8080 \
  -e ACP_GATEWAY_TOKEN=... \
  -e ACP_GITHUB_APP_ID=... \
  -e ACP_GITHUB_INSTALLATION_ID=... \
  -e ACP_GITHUB_PRIVATE_KEY="$(cat path/to/private-key.pem)" \
  acp-gateway
```

Or directly: `python3 gateway.py` with the same environment variables set.

Deploy to Railway (or any container host) as its own service/project — do not
attach it to a project that also hosts a webhook receiver or the product
services it reads Project state for.

## Tests

```bash
python3 test_gateway.py
```

Self-contained — mocks the GitHub calls, no network or real credentials
needed.

## Using it from an agent

```bash
curl -H "Authorization: Bearer $ACP_GATEWAY_TOKEN" \
  "https://<your-deployment>/internal/project-context?owner=<org>&project=<number>"
```

The response is `{"snapshot": {...}, "snapshot_source": "github-app", "allowed": true}`
— `snapshot` is the raw ProjectsV2 `id`/`title`/`number`/`fields`/`items`
payload from GitHub's GraphQL API.
