# Secret Time Machine

**Find every secret ever committed to a git repository, not just the ones still in your code, and see exactly how long each one was exposed.**

Most secret scanners check the current files. But deleting a leaked key only adds a *new* commit. The old commit still holds the key, and anyone with a clone can get it back with `git show <sha>`. Secret Time Machine replays the entire history of every branch and tag. For each secret it reconstructs a lifetime:

- **who** added it, in which commit, file and line
- **when** it was removed, if ever
- **whether it's still live**: in `HEAD`, only on another branch or tag, or only in history
- **whether it was pushed**: the commit is reachable from a remote-tracking branch
- **how long it was exposed**

It then renders the results as an interactive timeline you can open in any browser.

```
$ stm . --html report.html

Secret Time Machine · acme-shop
Scanned 13 commits across 3 refs by 5 authors.

  LIVE       critical Stripe live key  sk_live_Ty…63
             billing.py:3
             added 2025-12-14 by Dana Kowalski in 2f1c9a0e · exposed 11 months · pushed

  OTHER REF  critical OpenAI API key  sk-proj-NP…yj
             search.py:3
             added 2026-05-26 by Eve Laurent in 71c77ad0, still on experiment/ai-search · exposed 5 months

  IN HISTORY high     AWS access key ID  AKIA…0E
             config.py:5
             added 2025-05-17 by Bob Okafor in 60c18160, removed in 7dc4a25c · exposed 23 days · pushed

8 secrets: 3 live in HEAD, 1 on other refs, 4 deleted but recoverable from history.
```

## The report

A sample report from the demo repo is in [`docs/index.html`](docs/index.html). Turn on GitHub Pages for the `docs/` folder to get a live demo link.

`--html` writes one self-contained HTML file with no external requests:

- **Exposure timeline**: one bar per secret, running from the commit that added it to the commit that removed it (or to *now*, pulsing, if it's still live). A dashed tail after a removed bar marks the stretch where the secret was "gone" from the code but still recoverable.
- **Filters**: status, severity, free-text search over files, authors and commit messages, and sorting by urgency or exposure.
- **Per-secret detail**: the full add/remove history, the refs that contain it, whether it was pushed, and a remediation checklist with copy-ready `git filter-repo` commands.
- Light and dark themes, works at phone width.

**Secret values are always masked** (`AKIA…0E`, `postgres://shop:****@db…`). Neither the report nor the JSON output ever contains a full secret, so you can attach either one to a ticket.

## Install & use

Requires Python 3.9+ and git. No third-party dependencies.

```bash
pip install .
stm /path/to/repo --html report.html --open
```

| Flag | Meaning |
|---|---|
| `--html FILE` | write the interactive timeline report |
| `--json FILE` | write machine-readable results (`-` for stdout) |
| `--exclude GLOB` | skip matching files (repeatable) |
| `--fail-on live\|any` | exit `1` if a secret is live in HEAD / exists anywhere (for CI) |
| `--open` | open the HTML report when done |

Add `stm:ignore` to a line to suppress it (e.g. test fixtures).

### Try it on a demo repo

```bash
python examples/make_demo_repo.py demo-repo
stm demo-repo --html report.html --open
```

This builds a small "acme-shop" repo with 18 months of backdated commits by five authors. The history includes an AWS key that was fixed after 23 days, an SSH deploy key deleted two days after it was committed, a Stripe key that's still live, a leaked database URL that was later moved to a secrets manager, and an OpenAI key that exists only on an unpushed feature branch. The "secrets" are random strings generated at run time.

### In CI

[`.github/workflows/secret-scan.yml`](.github/workflows/secret-scan.yml) runs the tests, scans the repo with `--fail-on live`, and uploads the report as a build artifact. Note `fetch-depth: 0`. Without it, CI only sees one commit.

## How it works

```
git log --all --topo-order --reverse -p -U0
        │  one streamed pass over every commit on every ref, oldest first
        ▼
  diff parser ──► each added/removed line ──► rule engine (regex + entropy + placeholder filters)
        │                                            │
        ▼                                            ▼
  commit metadata                         fingerprint = sha256(rule + value)
                                                     │
                                                     ▼
                                   Finding: ordered add/remove events
                                                     │
          ┌──────────────────────────────────────────┼──────────────────────────────┐
          ▼                                          ▼                              ▼
 present at HEAD / any ref tip?        for-each-ref --contains <intro>     exposure = intro → removal
 (ls-tree + cat-file, cached)          → reachable refs, pushed?           (or → now if still live)
```

Design decisions:

- **Streaming `-U0` diffs.** Context lines would be re-scanned in every commit that touches a file. With zero context, each line is scanned only in the commit that adds or removes it. The parser tracks hunk line counts, so a content line such as `+++ foo` is never mistaken for a diff header.
- **Identity by value, not by location.** The same key pasted into two files is one finding with two files. Moving a key between files doesn't make it look like a new leak.
- **Liveness comes from snapshots, not from counting diffs.** Counting adds and removes across branches and merges is unreliable. Instead the scanner checks whether each ref's tip tree still contains the value, with trees and blobs cached so every blob is read at most once.
- **Merge commits are skipped.** `git log -p` shows no diff for merges, so each line is credited to the commit that actually wrote it.
- **Specific rules beat the generic one.** A `token = "ghp_…"` line is reported once, as a GitHub token. The catch-all "hard-coded secret" rule only fires on spans no vendor rule claimed, and only when the value passes entropy, character-class and placeholder checks (`your-api-key-here`, `${VAR}`, `{pw}` and similar are ignored).

### Detected secret types

AWS access keys and secret keys · GitHub and GitLab tokens · Anthropic and OpenAI API keys · Stripe live keys · Slack tokens and webhooks · Discord webhooks · Google API keys · SendGrid · Twilio · npm and PyPI tokens · private keys (RSA/EC/DSA/OpenSSH/PGP) · JWTs · database URLs with embedded passwords · generic high-entropy `password=` / `api_key:` assignments.

Rules live in [`stm/rules.py`](stm/rules.py). Each rule is a regex plus its severity and specific rotation advice.

### Limitations

- Private keys span many lines. They are identified by their header and file path, so the same key committed in two different files shows up as two findings.
- Only text that git can diff is scanned. Binary files and files over git's diff limits are skipped.
- "Pushed" means the commit is on a remote-tracking ref you have fetched. If you never fetched, the scanner can't know about pushes.

## Development

```bash
python -m unittest discover -s tests -v
```

The tests build real git repos with backdated commits. They check rule matching and masking, secret lifecycles (removed, live, branch-only, duplicated across files), the full demo story, that the HTML report never contains a raw secret, and CLI exit codes. The tool also scans its own repository clean.
