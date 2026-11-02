"""Command-line entry point: `stm [repo] [--html report.html] [--json out.json] [--fail-on live]`."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import webbrowser
from pathlib import Path

from . import __version__
from .report import render_html
from .scanner import GitError, scan

STATUS_LABEL = {"live": "LIVE", "branch": "OTHER REF", "removed": "IN HISTORY"}
STATUS_COLOR = {"live": "31;1", "branch": "33;1", "removed": "36"}
SEV_COLOR = {"critical": "31", "high": "35", "medium": "33", "low": "37"}


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        if enabled and os.name == "nt":
            os.system("")  # switches the Windows console into ANSI mode

    def __call__(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text


def human_duration(seconds: int) -> str:
    days = seconds / 86400
    if seconds < 3600:
        return f"{max(1, seconds // 60)} min"
    if days < 2:
        return f"{round(seconds / 3600)} hours"
    if days < 90:
        return f"{round(days)} days"
    if days < 730:
        return f"{round(days / 30.44)} months"
    return f"{days / 365.25:.1f} years"


def print_summary(result: dict, paint: Painter, out=sys.stdout) -> None:
    findings = result["findings"]
    counts = {s: sum(f["status"] == s for f in findings) for s in STATUS_LABEL}
    print(paint(f"\nSecret Time Machine · {result['repo']}", "1"), file=out)
    print(f"Scanned {result['commit_count']:,} commits across {result['ref_count']} refs "
          f"by {result['author_count']} authors.\n", file=out)
    if not findings:
        print(paint("✓ No secrets found anywhere in history.", "32;1"), file=out)
        return
    for f in findings:
        intro = f["introduced"]
        when = time.strftime("%Y-%m-%d", time.localtime(intro["ts"]))
        status = paint(f"{STATUS_LABEL[f['status']]:<10}", STATUS_COLOR[f["status"]])
        sev = paint(f"{f['severity']:<8}", SEV_COLOR[f["severity"]])
        print(f"  {status} {sev} {f['rule']}  {paint(f['masked'], '1')}", file=out)
        extra = f" +{len(f['files']) - 1} more" if len(f["files"]) > 1 else ""
        print(f"             {intro['path']}:{intro['line']}{extra}", file=out)
        tail = ""
        if f["removed"]:
            tail = f", removed in {f['removed']['short']}"
        elif f["status"] == "branch":
            tail = f", still on {', '.join(f['live_refs'][:3])}"
        pushed = paint(" · pushed", "31") if f["pushed"] else ""
        print(paint(f"             added {when} by {intro['author']} in {intro['short']}{tail}"
                    f" · exposed {human_duration(f['exposure_seconds'])}", "2") + pushed + "\n", file=out)
    print(paint(f"{len(findings)} secrets: {counts['live']} live in HEAD, {counts['branch']} on other refs, "
                f"{counts['removed']} deleted but recoverable from history.", "1"), file=out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stm",
        description="Find secrets anywhere in a git repository's history and see how long each one was exposed.",
    )
    parser.add_argument("repo", nargs="?", default=".", help="path to a git repository (default: current directory)")
    parser.add_argument("--html", metavar="FILE", help="write an interactive HTML timeline report")
    parser.add_argument("--json", metavar="FILE", help="write machine-readable results ('-' for stdout)")
    parser.add_argument("--exclude", metavar="GLOB", action="append", default=[],
                        help="skip files matching this glob (repeatable)")
    parser.add_argument("--fail-on", choices=("none", "live", "any"), default="none",
                        help="exit 1 if secrets are live in HEAD ('live') or exist anywhere in history ('any')")
    parser.add_argument("--open", action="store_true", help="open the HTML report when done")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    json_to_stdout = args.json == "-"
    out = sys.stderr if json_to_stdout else sys.stdout
    paint = Painter(not args.no_color and out.isatty() and "NO_COLOR" not in os.environ)
    progress = None
    if sys.stderr.isatty():
        def progress(n: int) -> None:
            print(f"\r  scanning… {n:,} commits", end="", file=sys.stderr, flush=True)

    try:
        result = scan(args.repo, tuple(args.exclude), on_progress=progress)
    except GitError as exc:
        print(f"stm: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print("stm: git was not found on PATH", file=sys.stderr)
        return 2
    if progress:
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

    print_summary(result, paint, out)

    if args.json:
        text = json.dumps(result, indent=2, ensure_ascii=False)
        if json_to_stdout:
            print(text)
        else:
            Path(args.json).write_text(text, encoding="utf-8")
            print(f"\nJSON written to {args.json}", file=out)
    if args.html:
        path = Path(args.html).resolve()
        path.write_text(render_html(result), encoding="utf-8")
        print(f"\nReport written to {path}", file=out)
        if args.open:
            webbrowser.open(path.as_uri())

    statuses = {f["status"] for f in result["findings"]}
    if args.fail_on == "any" and statuses or args.fail_on == "live" and "live" in statuses:
        return 1
    return 0
