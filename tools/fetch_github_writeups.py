#!/usr/bin/env python3
"""Clone curated public GitHub pentest writeup / methodology repos.

Output:
  data/writeups/github/<org>-<repo>/     shallow clones (git --depth 1)

Usage:
  python3 fetch_github_writeups.py [repo1 repo2 ...]
"""
import argparse
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GH_DIR = os.path.join(BASE, "data", "writeups", "github")
RAW = os.path.join(BASE, "data", "raw")

# Curated list of well-known public repos relevant for pentest AI (methodology,
# payloads, cheat sheets, vulnerability writeups). Edit freely.
DEFAULT_REPOS = [
    "swisskyrepo/PayloadsAllTheThings",
    "HackTricks-wiki/hacktricks",
    "enaqx/awesome-pentest",
    "Hack-with-Github/Awesome-Hacking",
    "0x90n/InfoSec-Black-Friday",
    "ivan-sincek/penetration-testing-cheat-sheet",
    "JohnHammond/ctf-katana",
]


def clone(repo, dest):
    if os.path.exists(os.path.join(dest, ".git")):
        print(f"[skip] {repo} already cloned")
        return True
    if os.path.exists(dest):
        print(f"[skip] {repo} dest exists (non-git)")
        return True
    r = subprocess.run(
        ["git", "clone", "--depth", "1", "-q", f"https://github.com/{repo}.git", dest],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"[err]  {repo}: {r.stderr.strip()[:160]}", file=sys.stderr)
        return False
    print(f"[ok]   {repo}")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repos", nargs="*", help="extra repos to clone (org/name)")
    ap.add_argument("--list", action="store_true", help="print default repo list and exit")
    args = ap.parse_args()
    os.makedirs(GH_DIR, exist_ok=True)
    os.makedirs(RAW, exist_ok=True)

    repos = list(DEFAULT_REPOS) + args.repos
    if args.list:
        for r in repos:
            print(r)
        return

    ok = fail = 0
    for repo in repos:
        org, _, name = repo.partition("/")
        dest = os.path.join(GH_DIR, f"{org}-{name}")
        if clone(repo, dest):
            ok += 1
        else:
            fail += 1

    manifest = os.path.join(GH_DIR, "_repos.json")
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump({"repos": repos, "ok": ok, "failed": fail}, fh, indent=2)
    print(f"done. cloned {ok}, failed {fail}. manifest: {manifest}")


if __name__ == "__main__":
    main()
