#!/usr/bin/env python3
"""client-releases.py -- record the machinery files of every formal-project-bootstrap release.

    python3 scripts/client-releases.py --bootstrap ~/Projects/_formal-project-bootstrap [--write]

Reads each release tag (vX.Y.Z) of a bootstrap checkout and lists the sha256 of
every file a release installs as machinery: scripts/, schemas/, .agents/skills/,
docs/ and NEW_AGENT_PROMPT.md (before 0.7), and .agents/acp/, .agents/bootstrap/
and .agents/skills/ (0.7 onward). Project-owned files (AGENTS.md, .agents/project/,
.agents/records/, the intent, profile, bindings, rules, contracts) are left out, so a change to them still
needs an exact artifact grant. With --write it replaces client_releases.json,
which the gateway reads to accept a pinned client file that a release ships.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent.parent
TARGET = HERE / "client_releases.json"
MACHINERY = re.compile(r"\A(scripts/[^/]+\.py|schemas/[^/]+\.json|docs/[^/]+\.md|\.agents/skills/.+|NEW_AGENT_PROMPT\.md"
                       r"|\.agents/acp/.+|\.agents/bootstrap/(?!templates/).+)\Z")
TAG = re.compile(r"\Av(\d+)\.(\d+)\.(\d+)\Z")


def git(bootstrap: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(bootstrap), *args], capture_output=True, check=True).stdout


def release_files(bootstrap: Path, tag: str) -> dict[str, str]:
    files = {}
    for line in git(bootstrap, "ls-tree", "-r", "-z", tag).decode().split("\0"):
        if not line:
            continue
        meta, _, path = line.partition("\t")
        mode, kind, blob = meta.split()
        if kind != "blob" or mode not in ("100644", "100755") or not MACHINERY.match(path):
            continue
        files[path] = hashlib.sha256(git(bootstrap, "cat-file", "blob", blob)).hexdigest()
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bootstrap", required=True, help="formal-project-bootstrap checkout with its tags")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    bootstrap = Path(args.bootstrap).expanduser().resolve()
    tags = sorted((t for t in git(bootstrap, "tag", "--list", "v*").decode().split() if TAG.match(t)),
                  key=lambda t: tuple(int(n) for n in TAG.match(t).groups()))
    releases = {tag[1:]: release_files(bootstrap, tag) for tag in tags}
    document = {"format": 1, "source": "formal-project-bootstrap release tags", "releases": releases}
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    for version, files in releases.items():
        print(f"{version}: {len(files)} machinery files")
    if args.write:
        TARGET.write_text(text, encoding="utf-8")
        print(f"wrote {TARGET.name}")
    else:
        print("dry run: pass --write to replace client_releases.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
