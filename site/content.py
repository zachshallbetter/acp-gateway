"""Everything the build says about the site, its pages and its documents.

Descriptions are written for a search result or a share card (about 150 characters).
Excerpts are the two or three sentences a reader sees before deciding to open a page.
"""
import os
from pathlib import Path

# This checkout supplies the gateway documents; the other sources are sibling checkouts under PROJECTS_DIR.
GATEWAY = Path(__file__).resolve().parent.parent
HOME = Path(os.environ.get("PROJECTS_DIR", Path.home() / "Projects"))

SITE = {
    "name": "Agent Control Plane",
    "short_name": "ACP",
    # Placeholder until the site has an address. Rebuild with SITE_URL=https://… python3 build.py
    "url": "https://acp.example/",
    "locale": "en_US",
    "lang": "en",
    "description": "ACP is an authorization service for AI agents. Before an agent pushes, deploys or migrates, ACP checks the facts itself and approves one exact action.",
    "compiled": "2026-11-03",
    "theme_light": "#e9eee9",
    "theme_dark": "#0b1310",
    "repo": "https://github.com/zachshallbetter/acp-gateway",
}

AUTHOR = {
    "name": "Zach Shallbetter",
    "url": "https://zachshallbetter.com",
    "github": "https://github.com/zachshallbetter",
    "orcid": "https://orcid.org/0009-0004-9548-2856",
}

LICENSES = {
    "MIT": ("MIT License", "https://opensource.org/license/mit"),
    "Apache-2.0": ("Apache License 2.0", "https://www.apache.org/licenses/LICENSE-2.0"),
    "CC-BY-4.0": ("Creative Commons Attribution 4.0", "https://creativecommons.org/licenses/by/4.0/"),
    None: ("No license declared in the source repository", None),
}

# Where each document comes from. `web` is the public GitHub base for links; None means the repository is private.
# `ref` pins the text to a tag; without one the build reads the checkout as it is.
REPOS = {
    "acp-gateway": {"dir": GATEWAY, "label": "zachshallbetter/acp-gateway", "web": "https://github.com/zachshallbetter/acp-gateway/blob/main/", "license": None},
    "fpb": {"dir": HOME / "_formal-project-bootstrap", "label": "zachshallbetter/formal-project-bootstrap @ v0.7.3", "web": "https://github.com/zachshallbetter/formal-project-bootstrap/blob/v0.7.3/", "ref": "v0.7.3", "license": "MIT"},
    "acpr": {"dir": HOME / "_tools/agent-control-plane", "label": "zachshallbetter/agent-control-plane", "web": "https://github.com/zachshallbetter/agent-control-plane/blob/main/", "license": "Apache-2.0"},
    "protocols": {"dir": HOME / "_protocols", "label": "zachshallbetter/protocols (private)", "web": None, "license": "MIT"},
    "iepe": {"dir": HOME / "_protocols/intent-evidence-project-engine", "label": "zachshallbetter/IEPE", "web": "https://github.com/zachshallbetter/IEPE/blob/main/", "license": "Apache-2.0"},
    "pdp": {"dir": HOME / "_protocols/polymorphic-decision-protocol", "label": "zachshallbetter/polymorphic-decision-protocol", "web": "https://github.com/zachshallbetter/polymorphic-decision-protocol/blob/main/", "license": "MIT"},
    "research": {"dir": HOME / "_research", "label": "Chroma Systems Research (unpublished repository)", "web": None, "license": "CC-BY-4.0"},
}

GROUPS = [
    ("ACP", "ShieldCheck", "The gateway, the client and the contracts that bind them."),
    ("Bootstrap doctrine", "FolderTree", "The rules every bootstrapped project runs under."),
    ("Admission tool", "ClipboardCheck", "The earlier, separate tool that admits and qualifies agent work."),
    ("Protocols", "FileText", "Formal protocols that ground what ACP does."),
    ("Research", "BookMarked", "Papers behind the ideas."),
]

# type: TechArticle for specifications and guides, ScholarlyArticle for the paper.
DOCS = [
    {"id": "gateway", "title": "acp-gateway specification", "group": "ACP", "status": "Production", "repo": "acp-gateway", "path": "README.md",
     "description": "How the ACP gateway decides protected actions: signed policies, its own GitHub reads, eight decision codes, containment, audit and errors.",
     "excerpt": "The full specification of the service that answers when an agent asks to push, merge or deploy. It covers policy authority, repository trust, containment and recovery, protected artifacts, telemetry, the board read and every setting.",
     "keywords": ["policy decision point", "AI agent authorization", "GitHub", "containment", "audit log"]},
    {"id": "gateway-github-app", "title": "The GitHub App", "group": "ACP", "repo": "acp-gateway", "path": "docs/GITHUB_APP.md",
     "description": "The read-only GitHub App behind ACP: each permission it asks for and why, installations, personal boards, configuration and key rotation.",
     "excerpt": "Agents never hold the App’s private key. They hold a gateway token, and the gateway mints short-lived installation tokens for them. This page lists every permission the App asks for, with the reason for each.",
     "keywords": ["GitHub App", "permissions", "installation token", "key rotation"]},
    {"id": "client", "title": "ACP client and integration", "group": "ACP", "status": "0.7.3", "repo": "fpb", "path": ".agents/acp/README.md",
     "description": "How a project binds ACP: quick start, effect classes, what agents do with each decision, owner overrides, failing closed and onboarding.",
     "excerpt": "In a bootstrapped project, ACP is the one instrument that authorizes a protected effect. Everything else an agent produces only observes, remembers or pressures. This guide covers setup, daily use and what agents never do.",
     "keywords": ["ACP client", "integration", "effect classes", "fail closed", "onboarding"]},
    {"id": "authorize-skill", "title": "Authorize a protected effect", "group": "ACP", "repo": "fpb", "path": ".agents/skills/authorize-protected-effect/SKILL.md",
     "description": "The skill an agent follows before any governed effect: find the action, ask the provider for a decision, and act only on an exact ALLOW.",
     "excerpt": "A short procedure agents load when a project binds an authorization provider. It sets out the requirements, the order of calls, and what to do with every decision that isn’t an ALLOW.",
     "keywords": ["agent skill", "authorization", "protected effect"]},
    {"id": "protected-effects", "title": "Protected-effects map", "group": "ACP", "repo": "fpb", "path": ".agents/bootstrap/templates/contracts/acp-protected-effects.yaml", "file": "protected-effects.txt", "code": "yaml",
     "description": "The contract that maps each operation an agent performs, from a local test to a production deploy, to its effect class and ACP action.",
     "excerpt": "Before an agent can ask ACP for a decision, it has to know which action names its operation. This YAML file is that lookup. It maps and never grants: editing it to unprotect an effect is itself refused.",
     "keywords": ["effect classes", "YAML contract", "ACP actions"],
     "intro": "This contract ships with every bootstrapped project. Each operation an agent can perform is listed with its effect class (E0 to E4), whether it is governed, and the ACP action to request."},
    {"id": "fpb-authority-model", "title": "Authority model", "group": "Bootstrap doctrine", "repo": "fpb", "path": ".agents/bootstrap/docs/AUTHORITY_MODEL.md",
     "description": "Why capability, permission, evidence, qualification and promotion are different things, and why only one bound instrument may authorize.",
     "excerpt": "Authority is the right to cause a protected effect under scope. Tool access, expertise, confidence and peer agreement don’t create it. The model also defines effect classes, human deviations and what happens on failure.",
     "keywords": ["authority model", "instrument stratification", "effect classes", "deviation"]},
    {"id": "fpb-work-graph", "title": "Work graph", "group": "Bootstrap doctrine", "repo": "fpb", "path": ".agents/bootstrap/docs/WORK_GRAPH.md",
     "description": "The states a work item moves through, the Ready predicate, claims and blockers, and how local work continues while ACP is unavailable.",
     "excerpt": "Work moves from Backlog to Verified. Providers may rename the columns but not what they mean. An item is Ready only when its scope, exclusions, dependencies, acceptance, evidence and budget are all defined.",
     "keywords": ["work graph", "Ready predicate", "claims", "blockers"]},
    {"id": "fpb-multi-agent-coordination", "title": "Multi-agent coordination", "group": "Bootstrap doctrine", "repo": "fpb", "path": ".agents/bootstrap/docs/MULTI_AGENT_COORDINATION.md",
     "description": "How several agents share one project: disjoint ownership, isolated workspaces, messages as evidence, handoffs and no authority by coalition.",
     "excerpt": "Several workers on one project are partial observers, not independent authorities. Each owns a claim, a scope and an isolated workspace, and agreement among agents never adds up to permission.",
     "keywords": ["multi-agent", "coordination", "handoff", "isolation"]},
    {"id": "fpb-negative-knowledge", "title": "Negative knowledge", "group": "Bootstrap doctrine", "repo": "fpb", "path": ".agents/bootstrap/docs/NEGATIVE_KNOWLEDGE.md",
     "description": "How a project keeps useful failures in a ledger so later agents don’t rediscover them, and what each negative result has to record.",
     "excerpt": "A failed attempt is evidence too. This page sets out what a negative result records, from its scope and revision to the new evidence that would justify reopening it, and names the common drafting failures.",
     "keywords": ["negative results", "evidence ledger", "failure classes"]},
    {"id": "acpr", "title": "Agent Control Plane (admission tool)", "group": "Admission tool", "status": "0.1.0", "repo": "acpr", "path": "README.md",
     "description": "A provider-neutral tool that admits agent work through issue packets, claims, evidence, qualification and human approval.",
     "excerpt": "An earlier, separate tool that shares the name. It decides whether a piece of agent work is admissible and qualified, with decisions from INVALID to QUALIFIED. It isn’t yet connected to the gateway’s decisions.",
     "keywords": ["admission control", "issue packet", "qualification", "GitHub Projects"]},
    {"id": "acpr-operating-model", "title": "Operating model", "group": "Admission tool", "repo": "acpr", "path": "docs/OPERATING_MODEL.md",
     "description": "The admission tool’s operating model: the issue packet as the authorization boundary, its decisions and invariants, and why silence isn’t approval.",
     "excerpt": "An issue packet declares everything a worker may do. Admission is the reusable decision over that packet. Projects still enforce locally, and a person must read and acknowledge the final delivery record.",
     "keywords": ["operating model", "issue packet", "invariants"]},
    {"id": "acpr-rate-limits", "title": "Provider access and rate limits", "group": "Admission tool", "repo": "acpr", "path": "docs/RATE_LIMITS.md",
     "description": "How the admission tool reads GitHub Projects within rate limits, and what agents may and may not do while access is degraded.",
     "excerpt": "A doctor run makes at most one read for the chosen Project and never retries a failure. While access is degraded, agents keep planning and testing locally. Claims, branches and deploys wait for fresh authority.",
     "keywords": ["rate limits", "degraded mode", "GitHub Projects"]},
    {"id": "icp", "title": "Interaction Contract Protocol", "group": "Protocols", "status": "Normative Candidate 0.1.0", "repo": "protocols", "path": "interaction-contract-protocol/INTERACTION_CONTRACT_PROTOCOL_v0.1.0.md",
     "description": "A versioned protocol for declaring and governing consequential interactions among people, software, agents and institutions.",
     "excerpt": "ICP binds schemas, API descriptions, problem details, state machines and policy engines into one declared interaction lifecycle. It is the closest formal match to ACP: a mandatory execution boundary, single-use verification, receipts and fail-closed authority.",
     "keywords": ["interaction contract", "protocol", "execution boundary", "receipts"]},
    {"id": "iepe", "title": "Intent and Evidence Project Engine", "group": "Protocols", "status": "Normative Candidate 0.2.0", "repo": "iepe", "path": "docs/PROTOCOL.md",
     "description": "A governed process that turns project intent into authorized work, evaluates results against declared evidence and promotes only what qualifies.",
     "excerpt": "IEPE puts intent above implementation and tickets above conversation. It keeps coordination, execution, evaluation and promotion apart, and defines issue readiness, the worker contract and how blockers are classified.",
     "keywords": ["project engine", "intent", "evidence", "promotion"]},
    {"id": "eqp", "title": "Evidence Qualification Protocol", "group": "Protocols", "status": "Normative Candidate 0.1.0", "repo": "protocols", "path": "evidence-qualification-protocol/01-EQP-SPECIFICATION.md",
     "description": "A protocol for deciding what a body of evidence justifies claiming about a candidate, under a declared profile and context.",
     "excerpt": "EQP doesn’t replace test frameworks or release systems. It binds their evidence into one explicit qualification decision, under the rule that a candidate gets the weakest claim its evidence justifies.",
     "keywords": ["evidence qualification", "claims", "qualification profile"]},
    {"id": "esp", "title": "External State Protocol", "group": "Protocols", "status": "Normative Candidate 0.3.0", "repo": "protocols", "path": "external-state-protocol/ESP-v0.3.0-External-State-Protocol-Definition.md",
     "description": "A protocol for governed progress toward a goal that depends on outside actors: commitments, gray conditions, relationships and the last undo.",
     "excerpt": "ESP keeps unresolved conditions gray, qualifies evidence independently and models relationships apart from transactions. It exposes the last reversible state before any consequential commitment.",
     "keywords": ["external state", "commitments", "last undo", "relationships"]},
    {"id": "hcml-authority", "title": "Mutual Interaction and Authority Protocol", "group": "Protocols", "status": "Research corpus 2.0", "repo": "protocols",
     "path": "human-computer-mutual-legibility/Human-Computer-Mutual-Legibility-Research-Corpus-v2/04-mutual-interaction-authority-protocol.md", "strip_until": "**Working status**",
     "description": "How people and computational systems exchange intent, evidence, correction and control, with the roles and correction classes each side owns.",
     "excerpt": "A working research specification from August 2026. It sets out what a person and a machine each owe the other during consequential delegation, and keeps implemented mechanisms apart from hypotheses it hasn’t tested.",
     "keywords": ["human-computer interaction", "authority", "correction", "delegation"]},
    {"id": "pdp", "title": "Polymorphic Decision Protocol", "group": "Protocols", "status": "Normative Candidate 1.3.1", "repo": "pdp", "path": "README.md",
     "description": "A procedure for high-uncertainty decisions made with panels of AI systems, in which the person owns the weights, the stakes and the exit.",
     "excerpt": "PDP discounts consensus by where each model’s inputs came from and tests model confidence under controlled pressure. Its paper is a public preprint and hasn’t been peer reviewed.",
     "keywords": ["decision protocol", "AI panels", "consensus", "human ownership"]},
    {"id": "commitment-assurance", "title": "Distance from Gray", "group": "Research", "status": "v1.0.0, staged", "repo": "research", "path": "commitment-assurance/manuscript/paper.md", "type": "ScholarlyArticle",
     "full_title": "Distance from Gray: Formal Assurance States, Commitment Clocks, and Epistemic Verification Gates",
     "bibliography": "commitment-assurance/manuscript/references.bib", "published": "2026-10-24", "affiliation": "Chroma Systems Research",
     "description": "A formal model of assurance at irreversible commitments: each property is satisfied, violated or gray, judged only on evidence from before the commit.",
     "excerpt": "Distance from Gray scores every required property against evidence available at commitment time and sends anything still gray to escalation. Worked cases from PostgreSQL commits and Rust merges show that a fully resolved change can still correctly fail.",
     "keywords": ["formal methods", "software assurance", "epistemic verification", "commitment clocks", "verification gates"]},
]

# Relative links inside the documents that point at another document in this library.
LINKS = {
    "GITHUB_APP.md": "gateway-github-app", "AUTHORITY_MODEL.md": "fpb-authority-model", "WORK_GRAPH.md": "fpb-work-graph",
    "MULTI_AGENT_COORDINATION.md": "fpb-multi-agent-coordination", "NEGATIVE_KNOWLEDGE.md": "fpb-negative-knowledge",
    "RATE_LIMITS.md": "acpr-rate-limits", "OPERATING_MODEL.md": "acpr-operating-model", "ACP_INTEGRATION.md": "client",
    "acp-protected-effects.yaml": "protected-effects", "SKILL.md": "authorize-skill",
}

# The site's own pages. `kind` picks the schema.org type.
PAGES = [
    {"file": "index.html", "title": "Agent Control Plane", "nav": "Overview", "icon": "Map", "kind": "home", "priority": "1.0",
     "description": SITE["description"],
     "excerpt": "Agents can write code, but some actions can’t be taken back. ACP answers before each one: for that action, at that commit, for about a minute, and only on facts it checked itself.",
     "image_alt": "Agent Control Plane: an agent asks, the gateway checks GitHub for itself, and approves one exact push."},
    {"file": "install.html", "title": "Install ACP", "nav": "Install", "icon": "Download", "kind": "howto", "priority": "0.9",
     "description": "Install ACP in a new or existing project: what you need, setup, connecting to a gateway, registering a policy, daily use, upgrades and removal.",
     "excerpt": "ACP arrives with formal-project-bootstrap. Install the bootstrap, connect your machine to a gateway, and have the repository’s owner register a policy once.",
     "image_alt": "Install ACP: requirements, five setup steps, then push, upgrade and uninstall."},
    {"file": "coverage.html", "title": "ACP Coverage", "nav": "Coverage", "icon": "Layers", "kind": "article", "priority": "0.8",
     "description": "The thirteen things ACP does, where each is specified and built, the protocols behind them, the eight decision codes and what’s still open.",
     "excerpt": "Each capability is grouped by when it acts in a change and linked to the exact section that specifies it. Gaps are named, with the issue that tracks each one.",
     "image_alt": "ACP Coverage: thirteen capabilities, eight decision codes and the protocols behind them."},
    {"file": "docs.html", "title": "ACP Docs", "nav": "Docs", "icon": "BookOpen", "kind": "collection", "priority": "0.8",
     "description": "Every source document behind ACP, each on its own page: the gateway specification, the client guide, bootstrap doctrine, protocols and research.",
     "excerpt": "Nineteen documents in five groups, each with its source, license, last update and reading time. Every one is also available as plain Markdown.",
     "image_alt": "ACP Docs: nineteen source documents in five groups."},
    {"file": "credits.html", "title": "Credits and Sources", "nav": "Credits", "icon": "Users", "kind": "about", "priority": "0.4",
     "description": "Who made this site, where each document comes from and under which license, the typefaces it uses and the work it draws on.",
     "excerpt": "Every document here is reproduced from its source repository under that repository’s license. This page lists each one, with the fonts, the original icons and the outside work the site cites.",
     "image_alt": "Credits and Sources for the Agent Control Plane site."},
]
