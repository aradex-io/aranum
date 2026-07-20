---
service: git
title: Git daemon
ports: 9418
aliases: git-daemon, git-protocol
---

# Git daemon — quick wins

**When you see it:** 9418/tcp open and `git ls-remote git://H/` returns 40-hex ref lines → an
**anonymous git daemon**. Anonymous read = full source disclosure and, via history, leaked secrets.

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
GIT_TERMINAL_PROMPT=0 git ls-remote git://H/          # ref advertisement (repo path visible)
git ls-remote git://H/REPO                            # if a repo path is exported
# no git binary — raw upload-pack ref advertisement:
printf '0032git-upload-pack /\x00host=H\x00' | nc -w5 H 9418
```

## Quick wins

### Anonymous repo listing
```sh
GIT_TERMINAL_PROMPT=0 git ls-remote git://H/
```
*Why:* the daemon advertises refs (`HEAD`, branches, tags as 40-hex SHAs) without auth — confirms
unauth read and gives you the exported repo path to clone.

### Clone + mine history for secrets
```sh
git clone git://H/REPO && cd REPO
gitleaks detect --source . --no-git=false             # or: trufflehog filesystem .
git log -p | grep -iE 'password|api[_-]?key|secret|token'
```
*Why:* the daemon exposes the entire history, not just the current tree — deleted creds, old configs,
and API keys live in past commits. `gitleaks`/`trufflehog` walk every commit for you.

## aranum helpers
- `aranumtoolkit/network/enum-git.sh` — dispatcher (`git ls-remote git://H/` ref advertisement, or a raw `git-upload-pack` request over `nc` when git isn't installed).

## Gotchas
- The daemon only serves repos it was told to export (`git daemon --export-all` or a per-repo `git-daemon-export-ok` file). `ls-remote git://H/` with no path may need the exact repo name.
- 9418 is read-only unless `receive-pack` was explicitly enabled (rare) — this is a disclosure finding, not a write.
- No refs returned ≠ nothing there; try known repo names (`app`, `web`, the org name) as the path.

## Sources
- HackTricks `9418-pentesting-git`; git-daemon(1) / gitprotocol-pack docs; gitleaks / trufflehog; aranum `enum-git.sh` header.
