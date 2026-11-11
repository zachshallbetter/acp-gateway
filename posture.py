"""Build posture: every governed repository's Vercel, Railway and Actions behaviour, ranked findings.

A finding names the risky setting, why it costs money, and the exact change that
fixes it. Billing, spend caps, build machines and concurrency are the owner's
to change; ACP reports them and applies nothing.
"""
from __future__ import annotations

import html

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

PRODUCTION_ONLY_IGNORE = 'if [ "$VERCEL_ENV" = "production" ]; then exit 1; else exit 0; fi'


def _finding(severity, code, repository, subject, problem, fix, owner_only):
    return {"severity": severity, "code": code, "repository": repository, "subject": subject,
            "problem": problem, "fix": fix, "who": "owner" if owner_only else "agent"}


def findings(snapshot, ledger_rows=None, day=None):
    """Ranked findings for one repository snapshot (see providers.posture_snapshot)."""
    repo = snapshot["repository"]
    out = []
    ledger_rows = ledger_rows or []

    def recorded(provider):
        return sum(1 for r in ledger_rows if r.get("counted") and r.get("provider") == provider
                   and f"{r.get('resource_owner')}/{r.get('resource_name')}" == repo.lower())

    for project in snapshot.get("vercel") or []:
        name = project["name"]
        config = project.get("vercel_json") or {}
        git = config.get("git") if isinstance(config.get("git"), dict) else {}
        branch_rules = git.get("deploymentEnabled")
        ignore = project.get("ignore_command") or config.get("ignoreCommand")
        if project["create_deployments"] == "enabled" and not ignore and not isinstance(branch_rules, (dict, bool)):
            out.append(_finding(
                "high", "VERCEL_DEPLOYS_EVERY_PUSH", repo, f"vercel:{name}",
                "Every push to every branch starts a Vercel build (no Ignored Build Step, no branch rules).",
                f"Add to vercel.json: \"ignoreCommand\": \"{PRODUCTION_ONLY_IGNORE}\" so only production builds; "
                "previews then run only on request (vercel deploy) under an ACP hosted_build decision.",
                owner_only=False))
        if project.get("build_machine_selection") == "elastic" or \
                project.get("build_machine_type") in ("turbo", "enhanced", "14cpu-28gb"):
            out.append(_finding(
                "high", "VERCEL_LARGE_OR_ELASTIC_MACHINE", repo, f"vercel:{name}",
                f"Builds run on {project.get('build_machine_type') or 'an'} machine with "
                f"{project.get('build_machine_selection') or 'unset'} selection, which can scale to large, "
                "costly machines.",
                "Vercel dashboard: Project Settings > Build and Deployment > Build Machine: choose Standard and "
                "turn off elastic selection.", owner_only=True))
        if project.get("elastic_concurrency"):
            out.append(_finding(
                "medium", "VERCEL_ELASTIC_CONCURRENCY", repo, f"vercel:{name}",
                "Elastic build concurrency is on, so many builds can run and bill at once.",
                "Vercel dashboard: Project Settings > Build and Deployment: turn off elastic concurrency.",
                owner_only=True))
        today = (project.get("deployments_per_day") or {}).get(day) if day else None
        if today is not None and today > recorded("vercel"):
            out.append(_finding(
                "high", "UNRECORDED_BUILDS", repo, f"vercel:{name}",
                f"{today} Vercel deployments today, {recorded('vercel')} authorized by ACP: builds are starting "
                "without a hosted_build decision.",
                "Install the bootstrap hooks that ask ACP before pushing (thin-client release), and check the "
                "deployments list for the source that bypassed them.", owner_only=False))
        out.append(_finding(
            "medium", "VERCEL_SPEND_CAP_UNVERIFIED", repo, f"vercel:{name}",
            "Vercel's API does not expose Spend Management, so ACP cannot confirm a cap exists.",
            "Vercel dashboard: Team Settings > Billing > Spend Management: set a monthly amount and turn on "
            "pausing production deployments when it is reached.", owner_only=True))

    railway = snapshot.get("railway")
    if railway:
        for trigger in railway.get("triggers") or []:
            out.append(_finding(
                "medium", "RAILWAY_DEPLOYS_ON_PUSH", repo, f"railway:{railway['name']}",
                f"Railway deploys every push to {trigger['branch']} of {trigger['repository']}.",
                "Keep it only if this branch is production. Otherwise Railway dashboard: Service > Settings > "
                "Source: disconnect the branch, and deploy with railway up under an ACP hosted_build decision.",
                owner_only=True))
        limit = railway.get("usage_limit")
        if limit is not None and limit.get("hard_limit") is None:
            out.append(_finding(
                "high", "RAILWAY_NO_HARD_LIMIT", repo, f"railway:{railway['name']}",
                "The Railway workspace has no hard usage limit, so spend is unbounded.",
                "Railway dashboard: Workspace Settings > Usage: set a hard limit (services stop at it) above "
                "the soft limit.", owner_only=True))
        today = (railway.get("deployments_per_day") or {}).get(day) if day else None
        if today is not None and today > recorded("railway"):
            out.append(_finding(
                "high", "UNRECORDED_BUILDS", repo, f"railway:{railway['name']}",
                f"{today} Railway deployments today, {recorded('railway')} authorized by ACP.",
                "Route deploys through an ACP hosted_build decision and check the deployment list for the source.",
                owner_only=False))

    actions = snapshot.get("github_actions") or {}
    for workflow in actions.get("workflows") or []:
        path = workflow["path"]
        if workflow.get("parse_error"):
            out.append(_finding("medium", "GHA_WORKFLOW_UNPARSEABLE", repo, path,
                                "The workflow is not valid YAML, so ACP assumes it runs on every push.",
                                f"Fix the YAML in {path}.", owner_only=False))
            continue
        push = (workflow.get("triggers") or {}).get("push", "absent")
        if push != "absent" and not (isinstance(push, dict) and (push.get("branches") or push.get("branches-ignore")
                                                                 or push.get("tags"))):
            out.append(_finding(
                "high", "GHA_PUSH_ANY_BRANCH", repo, path,
                "Runs on pushes to every branch.",
                f"In {path}: run on pull_request plus `push: branches: [main]`, and add `paths:` filters so "
                "docs-only changes do not run.", owner_only=False))
        if workflow.get("jobs_without_timeout"):
            out.append(_finding(
                "high", "GHA_NO_TIMEOUT", repo, path,
                f"Job(s) {', '.join(workflow['jobs_without_timeout'])} have no timeout (GitHub's default is "
                "6 hours per job).",
                f"In {path}: add `timeout-minutes: 15` (or the job's real ceiling) to each listed job.",
                owner_only=False))
        if not workflow.get("has_concurrency"):
            out.append(_finding(
                "medium", "GHA_NO_CONCURRENCY", repo, path,
                "No concurrency group, so superseded runs keep running.",
                f"In {path}, top level: `concurrency: {{group: ${{{{ github.workflow }}}}-${{{{ github.ref }}}}, "
                "cancel-in-progress: true}`.", owner_only=False))
        if workflow.get("matrix_jobs"):
            out.append(_finding(
                "low", "GHA_MATRIX", repo, path,
                f"Job(s) {', '.join(workflow['matrix_jobs'])} use a matrix, multiplying minutes per run.",
                f"In {path}: keep the matrix only where it is required; run the full matrix on release, a "
                "single cell on pull requests.", owner_only=False))
    spend = actions.get("spend") or {}
    if not spend.get("readable"):
        out.append(_finding(
            "medium", "GHA_SPEND_UNREADABLE", repo, "github_actions",
            "ACP cannot read this account's Actions spend or budget through the GitHub App.",
            "GitHub: Settings > Billing and licensing > Budgets and alerts: create an Actions budget with "
            "\"Stop usage when budget limit is reached\" on, for every account and organization.",
            owner_only=True))

    for error in snapshot.get("errors") or []:
        out.append(_finding("high" if error["kind"] == "DIVERGED" else "medium",
                            "PROVIDER_" + error["kind"], repo, error["provider"],
                            f"{error['provider']} evidence failed: {error['detail']}. Paid builds that depend on "
                            "it are refused until it is readable.",
                            "Owner: check the provider credential by name (ACP_VERCEL_TOKEN, ACP_RAILWAY_TOKEN, "
                            "the GitHub App installation) and the project ids in the policy's metered.providers.",
                            owner_only=True))
    return sorted(out, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"], f["subject"]))


# Settings that belong to an account, not a repository: report each once, naming every repository.
ACCOUNT_CODES = frozenset({"VERCEL_SPEND_CAP_UNVERIFIED", "GHA_SPEND_UNREADABLE", "RAILWAY_NO_HARD_LIMIT"})


def _collapse_account_findings(found):
    kept, merged = [], {}
    for finding in found:
        if finding["code"] not in ACCOUNT_CODES:
            kept.append(finding)
            continue
        key = (finding["code"], finding["repository"].split("/")[0] if finding["code"] == "GHA_SPEND_UNREADABLE"
               else "account")
        if key in merged:
            merged[key]["repositories"].append(finding["repository"])
        else:
            merged[key] = {**finding, "repositories": [finding["repository"]]}
    for finding in merged.values():
        finding["repository"] = ", ".join(sorted(set(finding.pop("repositories"))))
        kept.append(finding)
    return kept


def report(snapshots, ledger_rows, day, budget):
    """The posture report: all findings ranked, per-repository behaviour, today's budget use."""
    repositories, all_findings = [], []
    for snapshot in snapshots:
        found = findings(snapshot, ledger_rows, day)
        all_findings.extend(found)
        repositories.append({"repository": snapshot["repository"], "fetched_at": snapshot.get("fetched_at"),
                             "vercel": [{k: p.get(k) for k in ("name", "create_deployments", "ignore_command",
                                                                "build_machine_type", "build_machine_selection",
                                                                "elastic_concurrency", "deployments_per_day")}
                                        for p in snapshot.get("vercel") or []],
                             "railway": None if not snapshot.get("railway") else {
                                 k: snapshot["railway"].get(k) for k in ("name", "triggers", "deployments_per_day",
                                                                         "usage_limit")},
                             "github_actions": {"runs_per_day": (snapshot.get("github_actions") or {}).get("runs_per_day"),
                                                "check_runs": (snapshot.get("github_actions") or {}).get("check_runs"),
                                                "workflows": [w["path"] for w in (snapshot.get("github_actions") or {})
                                                              .get("workflows") or []]},
                             "findings": len(found)})
    all_findings = _collapse_account_findings(all_findings)
    all_findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"], f["repository"], f["subject"]))
    counted = [r for r in ledger_rows if r.get("counted")]
    usage = {}
    for row in counted:
        usage.setdefault(row["action"], {}).setdefault(row["provider"], 0)
        usage[row["action"]][row["provider"]] += 1
    return {"day": day, "budget": budget, "usage_today": usage, "findings": all_findings,
            "repositories": repositories}


def render_html(body):
    """One self-contained page for the owner. Text only: every value is escaped."""
    e = lambda value: html.escape("" if value is None else str(value))
    rows = "".join(
        f"<tr class='{e(f['severity'])}'><td>{e(f['severity'])}</td><td>{e(f['repository'])}</td>"
        f"<td>{e(f['subject'])}</td><td>{e(f['problem'])}</td><td><code>{e(f['fix'])}</code></td>"
        f"<td>{e(f['who'])}</td></tr>" for f in body["findings"])
    repos = "".join(
        f"<li><b>{e(r['repository'])}</b>: {e(r['findings'])} finding(s); Vercel "
        f"{e(', '.join(p['name'] for p in r['vercel']) or 'none')}; Railway "
        f"{e((r['railway'] or {}).get('name') or 'none')}; Actions runs/day {e(r['github_actions']['runs_per_day'])}</li>"
        for r in body["repositories"])
    usage = "".join(f"<li>{e(action)}: {e(counts)}</li>" for action, counts in body["usage_today"].items()) \
        or "<li>nothing counted yet today</li>"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>ACP build posture</title>
<style>
:root{{--bg:#fff;--fg:#1a1a1a;--muted:#666;--line:#ddd;--high:#b3261e;--medium:#8a5a00;--low:#3b5b2a}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141414;--fg:#eee;--muted:#aaa;--line:#333;--high:#ff8a80;--medium:#ffcc80;--low:#a5d6a7}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0;padding:24px 16px;max-width:1200px}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
.high td:first-child{{color:var(--high);font-weight:600}}.medium td:first-child{{color:var(--medium)}}.low td:first-child{{color:var(--low)}}
code{{white-space:pre-wrap;word-break:break-word}}.wrap{{overflow-x:auto}}p.m{{color:var(--muted)}}
</style></head><body>
<h1>ACP build posture</h1><p class="m">Day {e(body['day'])} (UTC). Budget policy {e((body.get('budget') or {}).get('budget_policy_id'))}
v{e((body.get('budget') or {}).get('version'))}. Nothing here has been applied.</p>
<h2>Findings, most severe first</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Repository</th>
<th>Where</th><th>Problem</th><th>Exact fix</th><th>Who</th></tr></thead><tbody>{rows}</tbody></table></div>
<h2>Today's budget use</h2><ul>{usage}</ul><h2>Repositories</h2><ul>{repos}</ul></body></html>"""
