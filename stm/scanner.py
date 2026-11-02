"""Walk every commit reachable from any ref and reconstruct each secret's lifetime."""
from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .rules import SEVERITIES, Hit, Rule, find_secrets

COMMIT_MARK = "\x1eSTM\x1f"
LOG_FORMAT = "%x1eSTM%x1f%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s"
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
IGNORE_MARKER = "stm:ignore"
DEFAULT_EXCLUDES = ("*.min.js", "*.map", "*.lock", "package-lock.json", "pnpm-lock.yaml", "*.svg")
MAX_LINE = 20_000
MAX_REFS = 100
MAX_CONTAINS_LOOKUPS = 300
STATUS_ORDER = {"live": 0, "branch": 1, "removed": 2}


class GitError(RuntimeError):
    pass


def git(root: str, *args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", root, "-c", "core.quotepath=false", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if check and proc.returncode != 0:
        raise GitError(proc.stderr.strip() or f"git {args[0]} failed")
    return proc.stdout


@dataclass
class Commit:
    sha: str
    parents: list[str]
    author: str
    email: str
    timestamp: int
    subject: str


@dataclass
class Event:
    kind: str  # "added" | "removed"
    sha: str
    path: str
    line: int


@dataclass
class Finding:
    fingerprint: str
    rule: Rule
    masked: str
    value: str
    events: list[Event] = field(default_factory=list)


def _strip_prefix(path: str, prefix: str) -> str:
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return path[len(prefix):] if path.startswith(prefix) else path


def iter_history(root: str) -> Iterator[tuple]:
    """Yield ("commit", Commit) and ("line", Commit, path, kind, lineno, text) in parent-first order.

    Merge commits produce no diff here, so a line is attributed to the commit that actually wrote it.
    """
    cmd = ["git", "-C", root, "-c", "core.quotepath=false", "log", "--all", "--topo-order", "--reverse",
           "-p", "-U0", "--no-color", "--no-renames", "--no-ext-diff", "--no-textconv",
           f"--format={LOG_FORMAT}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    commit: Commit | None = None
    path = ""
    old_left = new_left = old_no = new_no = 0
    assert proc.stdout is not None
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").rstrip("\n").rstrip("\r")
        if old_left or new_left:
            if line.startswith("+") and new_left:
                yield ("line", commit, path, "added", new_no, line[1:])
                new_no += 1
                new_left -= 1
                continue
            if line.startswith("-") and old_left:
                yield ("line", commit, path, "removed", old_no, line[1:])
                old_no += 1
                old_left -= 1
                continue
            if line.startswith("\\"):
                continue
            old_left = new_left = 0
        if line.startswith(COMMIT_MARK):
            sha, parents, author, email, ts, subject = line[len(COMMIT_MARK):].split("\x1f", 5)
            commit = Commit(sha, parents.split(), author, email, int(ts), subject)
            path = ""
            yield ("commit", commit)
        elif line.startswith("--- ") and line[4:] != "/dev/null":
            path = _strip_prefix(line[4:], "a/")
        elif line.startswith("+++ ") and line[4:] != "/dev/null":
            path = _strip_prefix(line[4:], "b/")
        elif m := HUNK_RE.match(line):
            old_no, new_no = int(m[1]), int(m[3])
            old_left = int(m[2]) if m[2] is not None else 1
            new_left = int(m[4]) if m[4] is not None else 1
    stderr = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
    if proc.wait() != 0:
        raise GitError(stderr.strip() or "git log failed")


class _Excluder:
    def __init__(self, patterns: tuple[str, ...]):
        self.patterns = patterns
        self.cache: dict[str, bool] = {}

    def __call__(self, path: str) -> bool:
        if path not in self.cache:
            base = os.path.basename(path)
            self.cache[path] = any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p) for p in self.patterns)
        return self.cache[path]


class _Snapshots:
    """Answers "does the file at this commit still contain the secret?" with cached trees and blobs."""

    def __init__(self, root: str):
        self.root = root
        self.trees: dict[str, dict[str, str]] = {}
        self.blobs: dict[str, str] = {}

    def _tree(self, sha: str) -> dict[str, str]:
        if sha not in self.trees:
            out = git(self.root, "ls-tree", "-r", "-z", sha, check=False)
            tree = {}
            for entry in out.split("\0"):
                meta, _, p = entry.partition("\t")
                parts = meta.split()
                if len(parts) == 3 and parts[1] == "blob":
                    tree[p] = parts[2]
            self.trees[sha] = tree
        return self.trees[sha]

    def contains(self, sha: str, path: str, value: str) -> bool:
        blob = self._tree(sha).get(path)
        if not blob:
            return False
        if blob not in self.blobs:
            self.blobs[blob] = git(self.root, "cat-file", "blob", blob, check=False)
        return value in self.blobs[blob]


def _list_refs(root: str) -> list[tuple[str, str, str]]:
    out = git(root, "for-each-ref", "--format=%(refname)%00%(refname:short)%00%(objectname)%00%(*objectname)",
              "refs/heads", "refs/remotes", "refs/tags", check=False)
    refs = []
    for row in out.splitlines():
        full, short, obj, peeled = (row.split("\0") + ["", "", "", ""])[:4]
        if full.endswith("/HEAD"):
            continue
        refs.append((full, short, peeled or obj))
    return refs[:MAX_REFS]


def _fingerprint(hit: Hit, path: str) -> str:
    key = f"{hit.rule.id}\0{hit.value}" + (f"\0{path}" if hit.rule.keyed_by_path else "")
    return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]


def _event_dict(e: Event, commits: dict[str, Commit]) -> dict:
    c = commits[e.sha]
    return {"kind": e.kind, "sha": e.sha, "short": e.sha[:8], "ts": c.timestamp, "author": c.author,
            "subject": c.subject, "path": e.path, "line": e.line}


def _summarize(f: Finding, commits: dict[str, Commit], snaps: _Snapshots, head: str | None,
               refs: list[tuple[str, str, str]], now: int, root: str, lookup_contains: bool) -> dict:
    ts = lambda e: commits[e.sha].timestamp  # noqa: E731
    files = sorted({e.path for e in f.events})
    adds = [e for e in f.events if e.kind == "added"] or f.events
    intro = min(adds, key=ts)
    start = ts(intro)

    def present_at(sha: str) -> bool:
        return any(snaps.contains(sha, p, f.value) for p in files)

    in_head = bool(head) and present_at(head)
    live_refs = [short for _, short, sha in refs if present_at(sha)]
    status = "live" if in_head else "branch" if live_refs else "removed"

    removal = None
    if status == "removed":
        later = [e for e in f.events if e.kind == "removed" and ts(e) >= start]
        removal = max(later, key=ts) if later else None
        end = ts(removal) if removal else max(ts(e) for e in f.events)
    else:
        end = now

    reachable: list[str] = []
    if lookup_contains:
        out = git(root, "for-each-ref", "--contains", intro.sha, "--format=%(refname)",
                  "refs/heads", "refs/remotes", "refs/tags", check=False)
        reachable = [r for r in out.splitlines() if not r.endswith("/HEAD")]
    short_names = {full: short for full, short, _ in refs}

    events = sorted(f.events, key=lambda e: (ts(e), e.kind != "added"))
    return {
        "id": f.fingerprint,
        "rule_id": f.rule.id,
        "rule": f.rule.name,
        "severity": f.rule.severity,
        "advice": f.rule.advice,
        "masked": f.masked,
        "keyed_by_path": f.rule.keyed_by_path,
        "status": status,
        "files": files,
        "introduced": _event_dict(intro, commits),
        "removed": _event_dict(removal, commits) if removal else None,
        "start": start,
        "end": end,
        "exposure_seconds": max(0, end - start),
        "live_refs": live_refs,
        "reachable_from": [short_names.get(r, r) for r in reachable],
        "pushed": any(r.startswith("refs/remotes/") for r in reachable),
        "events": [_event_dict(e, commits) for e in events],
    }


def scan(repo: str = ".", excludes: tuple[str, ...] = (),
         on_progress: Callable[[int], None] | None = None) -> dict:
    root = git(repo, "rev-parse", "--show-toplevel").strip()
    now = int(time.time())
    head = git(root, "rev-parse", "--verify", "-q", "HEAD", check=False).strip() or None
    refs = _list_refs(root)
    commits: dict[str, Commit] = {}
    findings: dict[str, Finding] = {}
    excluded = _Excluder(DEFAULT_EXCLUDES + tuple(excludes))

    if head or refs:
        for item in iter_history(root):
            if item[0] == "commit":
                commits[item[1].sha] = item[1]
                if on_progress and len(commits) % 250 == 0:
                    on_progress(len(commits))
                continue
            _, commit, path, kind, lineno, text = item
            if len(text) < 8 or IGNORE_MARKER in text or excluded(path):
                continue
            for hit in find_secrets(text[:MAX_LINE]):
                fp = _fingerprint(hit, path)
                finding = findings.get(fp)
                if finding is None:
                    finding = findings[fp] = Finding(fp, hit.rule, hit.masked, hit.value)
                finding.events.append(Event(kind, commit.sha, path, lineno))

    snaps = _Snapshots(root)
    lookup = len(findings) <= MAX_CONTAINS_LOOKUPS
    results = [_summarize(f, commits, snaps, head, refs, now, root, lookup) for f in findings.values()]
    results.sort(key=lambda r: (STATUS_ORDER[r["status"]], SEVERITIES.index(r["severity"]), r["start"]))

    stamps = [c.timestamp for c in commits.values()]
    return {
        "tool": "secret-time-machine",
        "version": 1,
        "repo": os.path.basename(root.rstrip("/\\")),
        "head": head,
        "scanned_at": now,
        "commit_count": len(commits),
        "author_count": len({c.email.lower() for c in commits.values()}),
        "ref_count": len(refs),
        "first_commit_ts": min(stamps) if stamps else now,
        "last_commit_ts": max(stamps) if stamps else now,
        "findings": results,
    }
