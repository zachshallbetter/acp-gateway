# The GitHub App: ACP Agent Control Plane

<img src="../github-app/logo.png" alt="ACP Agent Control Plane" width="96" align="right">

The gateway reads GitHub through one GitHub App. Agents never hold its key; they
hold a gateway bearer token, and the gateway mints short-lived installation tokens
on their behalf.

| | |
|---|---|
| Name | **ACP Agent Control Plane** (`acp-agent-control-plane`) |
| Why not plain *Agent Control Plane* | `agent-control-plane` is an existing GitHub account, and an App's slug cannot collide with an account |
| Formerly | `anime-universe-agent-control-plane` — named for an org that no longer holds any repositories (renamed 2026-09-23) |
| App ID | 4555426 (unchanged by the rename) |
| Owner | `zachshallbetter` |
| Visibility | private — only its owner installs it |
| Definition | [`github-app/manifest.json`](../github-app/manifest.json) (GitHub App manifest format) |
| Icon | [`github-app/logo.svg`](../github-app/logo.svg) (source), [`github-app/logo.png`](../github-app/logo.png) (512×512, what GitHub takes) |
| Webhook | none — the gateway has no webhook endpoint |

The manifest is the source of truth. `gateway.APP_PERMISSIONS` is the same set
(`test_github_app.py` keeps them equal), and `GET /internal/installations` reports,
per installation, `permissions_missing` and `permissions_excess` against it — so a
grant that drifts from the definition is visible without opening GitHub.

## What it may do, and why

Every permission is **read**. The gateway never writes to GitHub: board writes
(claims, field updates, new items) use the worker's own `gh` credentials.

| Permission | Level | Needed for | Where |
|---|---|---|---|
| `metadata` | read | `GET /repos/{owner}/{name}` — the repository identity ACP verifies a claim against | `github_evidence()` |
| `contents` | read | the registered notice file, `git/ref` for a protected ref, and `compare` for fast-forward — the ref-state evidence behind every `git.protected_ref.update` decision | `github_evidence()` |
| `issues` | read | issue items on a board (title, state, labels, assignees) | `PROJECT_QUERY` |
| `pull_requests` | read | pull-request items and their review state on a board | `PROJECT_QUERY` |
| `organization_projects` | read | ProjectsV2 boards owned by an organization | `project_context()`, `project_list()` |

Calls that need no permission: `GET /app`, `GET /app/installations` and
`POST /app/installations/{id}/access_tokens` use the App's own JWT; `GET /user/{id}`
is public.

Deliberately **not** requested:

- `repository_projects` — that is Projects *classic*, which ProjectsV2 does not use.
- `repository_hooks`, and every webhook event — nothing here receives deliveries. A
  webhook receiver (the `github-projects` skill ships one for its coordinator) should
  be its own App with its own least-privilege grant, not this one.
- any `write` or `admin` level.

## Personal boards

No GitHub App can read a user's ProjectsV2 boards: Projects exists as an App
permission only at the organization level. A user owner is served by a classic
personal access token with `read:project`, set as `ACP_GITHUB_TOKEN_<OWNER>` on the
deployment (`ACP_GITHUB_TOKEN_ZACHSHALLBETTER` today). The App is still installed on
the user account for repository evidence — `metadata` and `contents` — which is why
`organization_projects` is not "missing" on a user installation.

## Installations

| Account | Type | Serves |
|---|---|---|
| `zachshallbetter` | User | repository evidence for personal repositories (boards via the PAT above) |
| `Anime-Universe` | Organization | nothing now — the org holds no repositories or boards; uninstall when convenient |
| `AcmeProductCo` | Organization | **not installed yet** — needed for Infinite-Verse and Infinite-Studio evidence and their org boards |

Install from `https://github.com/apps/acp-agent-control-plane/installations/new` (the
gateway derives this link from the App's own record, so it follows a rename).

## Configuration

| Variable | |
|---|---|
| `ACP_GITHUB_APP_ID` | the App's numeric ID |
| `ACP_GITHUB_PRIVATE_KEY` | the App's private key (PEM). A secret: never printed, logged or committed |
| `ACP_GITHUB_INSTALLATION_ID` | optional fallback; installations are discovered from `/app/installations` |

Verify with `GET /internal/app-probe?owner=<login>` (mints a token and shows its
permissions) and `GET /internal/installations?refresh=1` (shows drift).

## Bringing the existing App in line

The App was created by hand, so its settings have drifted from this definition.
GitHub has no API for editing an App's settings; do it at
`https://github.com/settings/apps/<current-slug>`:

1. **General** → name `Agent Control Plane`, description and homepage from
   `manifest.json`, logo `github-app/logo.png`. Webhook: uncheck **Active**.
2. **Permissions & events** → set exactly the table above; set `repository_hooks` and
   Projects (classic) to *No access*; subscribe to no events.
3. Each installation must **accept** the new permissions (GitHub emails the owner and
   shows a banner on the installation). Until it does, the old grant stands.
4. `GET /internal/installations?refresh=1` — every installation should report empty
   `permissions_missing` and `permissions_excess`.

Renaming changes the slug and the install URL. Existing installations and the App
ID are unaffected, so the deployment needs no change.

## Creating it from the manifest

For a new deployment, GitHub's
[manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)
creates the App from `manifest.json` in one step: POST the manifest to
`https://github.com/settings/apps/new`, then exchange the returned code at
`POST /app-manifests/{code}/conversions` for the App ID and private key. Upload
`logo.png` afterwards — the manifest has no logo field.

## Rotating the private key

Rotate whenever the key may have been exposed — including being printed to a
terminal or transcript — and otherwise on a schedule.

1. App settings → **Private keys** → *Generate a private key* (the old one keeps
   working until you delete it).
2. `railway variables --service acp-gateway --environment production --set "ACP_GITHUB_PRIVATE_KEY=$(cat <new-key>.pem)"` — this redeploys.
3. `GET /internal/app-probe` must return `installation_token: minted`.
4. Delete the old key in App settings, then delete the downloaded `.pem`.

Never read the Railway variables with line-oriented tools (`cut`, `grep` on the
plain listing): the PEM is multi-line and its body prints. Use `--json` and select
key names only.
