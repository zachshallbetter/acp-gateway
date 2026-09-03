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
  `ACP_GITHUB_PRIVATE_KEY`) as the *only* place they live. They never reach an
  agent or leave this process.
- Mints a short-lived installation token per request (RS256-signed JWT,
  exchanged via the GitHub Apps API) — nothing is minted client-side or cached
  beyond the request.
- **Serves every account the App is installed on.** The gateway asks the App
  for its own installations and picks the right one per `owner`, so adding an
  org — or your personal account — is an App install, not an env edit and a
  redeploy. Organization-owned and user-owned boards work the same way. Pin an
  owner explicitly with `ACP_GITHUB_INSTALLATIONS` if you ever need to.
- Exposes the reads an agent needs to find its way without being told:
  `GET /internal/installations` (which accounts are readable),
  `GET /internal/projects?owner=` (which boards that account has, each with the
  number to ask for, and whether the allowlist admits it), and
  `GET /internal/project-context?owner=&project=` — a live ProjectsV2 GraphQL
  snapshot (fields + **every** item, paged) for an allowlisted board.

  The snapshot reports its own completeness — `items_fetched`, `items_total`,
  `pages`, and an explicit `truncated` flag. Never infer completeness from the
  item count alone: a count equal to the page size is a cap, not a total.
- **Explains every refusal.** A caller that omits an owner, names an account
  the App is not installed on, or asks for a board outside the allowlist gets
  back a stable `error` code, a `detail`, a `remedy`, and the data needed to
  retry (`owners_available`, the board list endpoint, the allowlist value) —
  instead of an opaque 400 or 502. See "Error contract" below.
- `GET /health` (unauthenticated, for platform health checks) and
  `GET /internal/app-status` / `GET /internal/app-probe` (authenticated, for
  verifying the App credentials are configured and can actually mint a token)
  round out the surface.

## What it deliberately does not do

- No webhook receiving, no event queue. This is pull-only. (A companion
  webhook receiver is a separate service by design — see "Boundary" below.)
- No board writes. Claiming an item, setting a field, or mutating Project
  state happens through the agent's own scoped credentials, never through this
  gateway.
- No board caching. Every `/internal/project-context` call mints a fresh
  installation token and issues a fresh GraphQL query. The only in-process
  caches are the App JWT (until it nears expiry) and the installation list
  (`INSTALLATION_TTL`, 5 minutes; `?refresh=1` bypasses it) — neither holds
  board state.

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
| `ACP_GITHUB_PRIVATE_KEY` | for App reads | The App's PEM private key, as a literal env value (not a file path). |
| `ACP_PROJECT_ALLOWLIST` | no | Which boards may be read; see below. Defaults to `2-7`, the range that used to be hardcoded. |
| `ACP_GITHUB_INSTALLATIONS` | no | `owner:id,owner:id` — pin an owner to an installation, skipping discovery. Only needed to override. |
| `ACP_GITHUB_INSTALLATION_ID` | no | Legacy single installation. Used as a fallback if the installation list can't be fetched, or when a call names no owner. |
| `PORT` | no | Defaults to `8080`. |

`configured()` is `False` (and `/internal/app-status`, `/internal/app-probe`
report it) until the App ID and private key are set — `/health` still returns
`200` either way, so a deploy without App credentials still passes a basic
liveness check while clearly reporting it can't do App-authenticated reads yet.
The installation ID is deliberately no longer part of that: installations are
discovered per owner.

### The allowlist

`ACP_PROJECT_ALLOWLIST` is a comma list of numbers and ranges, optionally
qualified by owner. It is configuration, not a code edit:

```
2-9,11                                  # those numbers, for any owner
zachshallbetter:*                       # every board of that user
zachshallbetter:*,Anime-Universe:2-9,11 # per-owner; a qualification carries
                                        # across commas until the next one
*                                       # every board of every installed owner
```

Unqualified entries are the default bucket, used for any owner with no rule of
its own — so put them first. A malformed entry fails at startup rather than
silently allowing nothing.

## Error contract

Every non-2xx response is JSON with a stable `error` code, a human `detail`,
usually a `remedy`, and whatever context makes the retry possible. A client
should read the body on failure (with `curl`, that means `--fail-with-body`,
not `-f`, which throws it away).

| `error` | Status | Means / what to do |
|---|---|---|
| `UNAUTHORIZED` | 401 | Send `Authorization: Bearer <ACP_GATEWAY_TOKEN>`. |
| `OWNER_REQUIRED` | 400 | Add `?owner=`. Body carries `owners_available`. |
| `PROJECT_REQUIRED` | 400 | `?project=` must be a board number; body points at `/internal/projects?owner=`. |
| `PROJECT_NOT_ALLOWED` | 403 | Board is outside `ACP_PROJECT_ALLOWLIST`; body carries the current value and the entry to add. |
| `OWNER_NOT_INSTALLED` | 404 | Install the App on that account (body carries the install URL and `owners_available`). No redeploy follows. |
| `PROJECTS_PERMISSION_MISSING` | 403 | The installation exists but has no Projects read; body carries its `permissions`. |
| `PROJECT_NOT_FOUND` | 404 | No such board for that owner; body points at the board listing. |
| `OWNER_NOT_VISIBLE` | 404 | The login didn't resolve to a user or org. |
| `APP_NOT_CONFIGURED` | 503 | Gateway has no App credentials. |
| `INSTALLATION_LOOKUP_FAILED` / `UPSTREAM_FAILURE` | 502 | GitHub side; retry, then check `/internal/app-probe`. |

## Running it

```bash
docker build -t acp-gateway .
docker run -p 8080:8080 \
  -e ACP_GATEWAY_TOKEN=... \
  -e ACP_GITHUB_APP_ID=... \
  -e ACP_GITHUB_PRIVATE_KEY="$(cat path/to/private-key.pem)" \
  -e ACP_PROJECT_ALLOWLIST='<owner>:*' \
  acp-gateway
```

Or directly: `python3 gateway.py` with the same environment variables set.

Deploy to Railway (or any container host) as its own service/project — do not
attach it to a project that also hosts a webhook receiver or the product
services it reads Project state for.

## Tests

```bash
python3 test_gateway.py
python3 test_gateway_access.py
python3 test_gateway_owners.py
```

Self-contained — mocks the GitHub calls, no network or real credentials
needed.

## Using it from an agent

```bash
auth=(-H "Authorization: Bearer $ACP_GATEWAY_TOKEN")

# Which accounts can this gateway read?
curl --fail-with-body -sS "${auth[@]}" "$ACP_GATEWAY_URL/internal/installations"

# Which boards does one of them have?
curl --fail-with-body -sS "${auth[@]}" "$ACP_GATEWAY_URL/internal/projects?owner=<login>"

# Read one board.
curl --fail-with-body -sS "${auth[@]}" \
  "$ACP_GATEWAY_URL/internal/project-context?owner=<login>&project=<number>"
```

The snapshot response is `{"snapshot": {...}, "snapshot_source": "github-app",
"allowed": true, "owner": ..., "owner_type": ..., "items_fetched": ...,
"items_total": ..., "truncated": ..., "pages": ...}` — `snapshot` is the raw
ProjectsV2 `id`/`title`/`number`/`fields`/`items` payload from GitHub's GraphQL
API.

A client that needs an owner or board number it doesn't have should ask the
gateway rather than guess: the two discovery endpoints above answer it, and any
refusal already names what's missing. Surface the error body to the operator
verbatim — it is written to be actionable.
