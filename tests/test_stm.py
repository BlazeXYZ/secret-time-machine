"""Tests build real git repos with backdated commits. Fake secrets are assembled at run time
so this file never matches the scanner (or GitHub push protection) itself."""
from __future__ import annotations

import json
import random
import string
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from make_demo_repo import DemoRepo, build  # noqa: E402
from stm.cli import main  # noqa: E402
from stm.report import render_html  # noqa: E402
from stm.rules import find_secrets  # noqa: E402
from stm.scanner import scan  # noqa: E402

RNG = random.Random(42)
ALNUM = string.ascii_letters + string.digits
DAY = 86400


def junk(alphabet: str, n: int) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def aws_id() -> str:
    return "AK" + "IA" + junk(string.ascii_uppercase + string.digits, 16)


def gh_token() -> str:
    return "gh" + "p_" + junk(ALNUM, 36)


class RuleTests(unittest.TestCase):
    def rule_ids(self, line: str) -> list[str]:
        return [h.rule.id for h in find_secrets(line)]

    def test_specific_rules(self):
        cases = {
            "aws-access-key": f'key = "{aws_id()}"',
            "github-token": f"export GITHUB_TOKEN={gh_token()}",
            "stripe-live-key": "stripe.api_key = '" + "sk_" + "live_" + junk(ALNUM, 24) + "'",
            "slack-webhook": "url: https://hooks.slack.com/services/T" + junk(ALNUM, 8) + "/B" + junk(ALNUM, 8) + "/" + junk(ALNUM, 24),
            "google-api-key": "AI" + "za" + junk(ALNUM, 35),
            "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "openai-key": "sk-" + "proj-" + junk(ALNUM, 24) + "T3Blbk" + "FJ" + junk(ALNUM, 24),
            "npm-token": "//registry.npmjs.org/:_authToken=" + "npm" + "_" + junk(ALNUM, 36),
            "jwt": "Bearer " + "ey" + "J" + junk(ALNUM, 20) + ".ey" + "J" + junk(ALNUM, 20) + "." + junk(ALNUM, 20),
        }
        for rule_id, line in cases.items():
            with self.subTest(rule_id):
                self.assertIn(rule_id, self.rule_ids(line))

    def test_specific_rule_wins_over_generic(self):
        self.assertEqual(self.rule_ids(f'token = "{gh_token()}"'), ["github-token"])

    def test_connection_string_masks_only_password(self):
        pw = junk(ALNUM, 14)
        [hit] = find_secrets(f"url = postgres://shop:{pw}@db.internal:5432/prod")
        self.assertEqual(hit.rule.id, "connection-string")
        self.assertNotIn(pw, hit.masked)
        self.assertIn("db.internal", hit.masked)

    def test_placeholders_and_low_entropy_are_ignored(self):
        for line in ('API_KEY="your-api-key-here"', 'password = "aaaaaaaaaaaa"',
                     "DATABASE_URL=postgres://user:password@localhost/db", 'token = "${GITHUB_TOKEN}"',
                     'tokenizer = "bert-base-uncased"'):
            with self.subTest(line):
                self.assertEqual(find_secrets(line), [])

    def test_generic_rule_catches_high_entropy_assignment(self):
        self.assertEqual(self.rule_ids('DB_PASSWORD: "' + junk(ALNUM, 18) + '"'), ["generic-secret"])

    def test_masking_never_reveals_full_value(self):
        key = aws_id()
        [hit] = find_secrets(key)
        self.assertNotEqual(hit.masked, key)
        self.assertTrue(hit.masked.startswith("AKIA"))


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = DemoRepo(Path(self.tmp.name) / "r")
        self.repo.path.mkdir()
        self.repo.git("init", "-q", "-b", "main")
        self.t0 = int(time.time()) - 100 * DAY

    def tearDown(self):
        self.tmp.cleanup()

    def test_lifecycle(self):
        removed_key, live_token, branch_key = aws_id(), gh_token(), aws_id()
        self.repo.write("a.py", f'KEY = "{removed_key}"\n')
        self.repo.commit("alice", "add key", self.t0)
        self.repo.write("a.py", "KEY = None\n")
        self.repo.commit("bob", "remove key", self.t0 + 10 * DAY)
        self.repo.write("b.sh", f"GITHUB_TOKEN={live_token}\n")
        self.repo.write("c.py", f'IGNORED = "{aws_id()}"  # stm:ignore\n')
        self.repo.commit("chen", "add token", self.t0 + 20 * DAY)
        self.repo.git("checkout", "-q", "-b", "side")
        self.repo.write("d.py", f'K = "{branch_key}"\n')
        self.repo.commit("dana", "side branch key", self.t0 + 30 * DAY)
        self.repo.git("checkout", "-q", "main")

        result = scan(str(self.repo.path))
        self.assertEqual(result["commit_count"], 4)
        by_status = {f["status"]: f for f in result["findings"]}
        self.assertEqual(len(result["findings"]), 3)

        removed = by_status["removed"]
        self.assertEqual(removed["introduced"]["author"], "Alice Moreno")
        self.assertEqual(removed["removed"]["subject"], "remove key")
        self.assertEqual(removed["exposure_seconds"], 10 * DAY)

        live = by_status["live"]
        self.assertEqual(live["rule_id"], "github-token")
        self.assertEqual(live["files"], ["b.sh"])
        self.assertIn("main", live["reachable_from"])

        branch = by_status["branch"]
        self.assertEqual(branch["live_refs"], ["side"])
        self.assertFalse(branch["pushed"])

    def test_same_secret_in_two_files_is_one_finding(self):
        key = aws_id()
        self.repo.write("a.py", f"A = '{key}'\n")
        self.repo.write("b.py", f"B = '{key}'\n")
        self.repo.commit("alice", "dup", self.t0)
        [finding] = scan(str(self.repo.path))["findings"]
        self.assertEqual(finding["files"], ["a.py", "b.py"])

    def test_empty_repo(self):
        result = scan(str(self.repo.path))
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["commit_count"], 0)


class DemoAndReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.path = build(Path(cls.tmp.name) / "demo")
        cls.result = scan(str(cls.path))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_demo_story(self):
        rules = {(f["rule_id"], f["status"]) for f in self.result["findings"]}
        self.assertEqual(rules, {
            ("aws-access-key", "removed"), ("aws-secret-key", "removed"), ("private-key", "removed"),
            ("connection-string", "removed"), ("slack-webhook", "live"), ("stripe-live-key", "live"),
            ("github-token", "live"), ("openai-key", "branch"),
        })
        pushed = {f["rule_id"]: f["pushed"] for f in self.result["findings"]}
        self.assertTrue(pushed["stripe-live-key"])
        self.assertFalse(pushed["openai-key"])

    def test_report_never_contains_raw_values(self):
        html = render_html(self.result)
        raw = subprocess.run(["git", "log", "--all", "-p"], cwd=self.path, capture_output=True, text=True).stdout
        for f in self.result["findings"]:
            self.assertIn(json.dumps(f["masked"], ensure_ascii=False)[1:-1].replace("<", "\\u003c"), html)
        for hit in (h for line in raw.splitlines() for h in find_secrets(line)):
            if not hit.rule.keyed_by_path:
                self.assertNotIn(hit.value, html)
        # A committed report must not trip the scanner (or GitHub push protection) itself.
        self.assertEqual([h.rule.id for line in html.splitlines() for h in find_secrets(line)], [])

    def test_cli_exit_codes(self):
        self.assertEqual(main([str(self.path), "--fail-on", "live", "--no-color", "--json", str(Path(self.tmp.name) / "o.json")]), 1)
        self.assertEqual(main([str(self.path), "--no-color", "--exclude", "*"]), 0)


if __name__ == "__main__":
    unittest.main()
