"""Build a throwaway repo with a realistic, backdated leak history for demos and screenshots.

    python examples/make_demo_repo.py demo-repo
    python -m stm demo-repo --html report.html --open

Every "secret" is random junk shaped like a real credential, generated at run time,
so this file itself contains nothing a scanner (or GitHub push protection) would flag.
"""
from __future__ import annotations

import argparse
import os
import random
import shutil
import stat
import string
import subprocess
import sys
import time
from pathlib import Path

UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
B64 = ALNUM + "+/"

AUTHORS = {
    "alice": ("Alice Moreno", "alice@acme.dev"),
    "bob": ("Bob Okafor", "bob@acme.dev"),
    "chen": ("Chen Wei", "chen@acme.dev"),
    "dana": ("Dana Kowalski", "dana@acme.dev"),
    "eve": ("Eve Laurent", "eve@acme.dev"),
}


class DemoRepo:
    def __init__(self, path: Path):
        self.path = path

    def git(self, *args: str, env: dict | None = None) -> None:
        subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args],
                       cwd=self.path, check=True, capture_output=True, env=env)

    def write(self, rel: str, text: str) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")

    def delete(self, rel: str) -> None:
        (self.path / rel).unlink()

    def commit(self, who: str, message: str, when: int) -> None:
        name, email = AUTHORS[who]
        stamp = f"{when} +0000"
        env = {**os.environ, "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_AUTHOR_DATE": stamp,
               "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email, "GIT_COMMITTER_DATE": stamp}
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message, env=env)


def _rmtree(path: Path) -> None:
    # git marks object files read-only, which makes a plain rmtree fail on Windows.
    def make_writable(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable)
    else:
        shutil.rmtree(path, onerror=make_writable)


def build(dest: Path, seed: int = 7) -> Path:
    rng = random.Random(seed)
    r = lambda alphabet, n: "".join(rng.choice(alphabet) for _ in range(n))  # noqa: E731

    if dest.exists():
        _rmtree(dest)
    origin = dest.with_name(dest.name + "-origin.git")
    if origin.exists():
        _rmtree(origin)
    dest.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    repo = DemoRepo(dest)
    repo.git("init", "-q", "-b", "main")
    repo.git("remote", "add", "origin", str(origin))

    day = 86400
    t = int(time.time()) - 540 * day
    aws_id = "AK" + "IA" + r(UPPER_DIGITS, 16)
    aws_secret = r(B64, 40)
    slack = f"https://hooks.slack.com/services/T{r(UPPER_DIGITS, 8)}/B{r(UPPER_DIGITS, 8)}/{r(ALNUM, 24)}"
    stripe = "sk_" + "live_" + r(ALNUM, 24)
    gh = "gh" + "p_" + r(ALNUM, 36)
    db_pw = r(ALNUM, 14)
    openai = "sk-" + "proj-" + r(ALNUM, 24) + "T3Blbk" + "FJ" + r(ALNUM, 24)
    pem = "\n".join(["-----BEGIN " + "OPENSSH PRIVATE KEY-----", *(r(B64, 64) for _ in range(6)),
                     "-----END OPENSSH PRIVATE KEY-----"])

    repo.write("README.md", "# acme-shop\n\nTiny storefront API.\n")
    repo.write("app.py", "from config import settings\n\n\ndef main():\n    print('acme-shop up')\n")
    repo.write("config.py", "settings = {\n    'region': 'eu-west-1',\n}\n")
    repo.commit("alice", "Initial commit", t)

    t += 6 * day
    repo.write("config.py", "settings = {\n    'region': 'eu-west-1',\n}\n\n"
                            f'AWS_ACCESS_KEY_ID = "{aws_id}"\nAWS_SECRET_ACCESS_KEY = "{aws_secret}"\n')
    repo.write("uploads.py", "import boto3\nfrom config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n")
    repo.commit("bob", "Add S3 uploads for product images", t)

    t += 23 * day
    repo.write("config.py", "import os\n\nsettings = {\n    'region': 'eu-west-1',\n}\n\n"
                            "AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']\n"
                            "AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']\n")
    repo.commit("alice", "Read AWS credentials from the environment", t)

    t += 41 * day
    repo.write("notify.py", f'import requests\n\nWEBHOOK = "{slack}"\n\n\ndef alert(msg):\n'
                            "    requests.post(WEBHOOK, json={'text': msg})\n")
    repo.commit("chen", "Post failed orders to #alerts", t)

    t += 33 * day
    repo.write("deploy/id_ci", pem + "\n")
    repo.write("deploy/deploy.sh", "#!/bin/sh\nssh -i deploy/id_ci deploy@shop.acme.dev ./release\n")
    repo.commit("bob", "CI deploy over ssh", t)

    t += 2 * day
    repo.delete("deploy/id_ci")
    repo.commit("bob", "Oops, remove deploy key", t)

    t += 64 * day
    repo.write("billing.py", f'import stripe\n\nstripe.api_key = "{stripe}"\n')
    repo.commit("dana", "Stripe checkout", t)

    t += 29 * day
    repo.write(".env.example", 'API_KEY="your-api-key-here"\nDATABASE_URL="postgres://user:password@localhost/shop"\n')
    repo.write("tests/test_auth.py", f'FIXTURE_TOKEN = "{r(ALNUM, 20)}"  # stm:ignore (test fixture)\n')
    repo.commit("alice", "Document env vars and add auth tests", t)

    t += 47 * day
    repo.write("settings.yaml", f"database_url: postgres://shop:{db_pw}@db.internal:5432/prod\n")
    repo.commit("chen", "Point at the production database", t)

    t += 45 * day
    repo.write("settings.yaml", "database_url: ${DATABASE_URL}\n")
    repo.commit("chen", "Use the secrets manager for the DB URL", t)

    t += 38 * day
    repo.write("scripts/release.sh", f'#!/bin/sh\nGITHUB_TOKEN={gh} gh release create "$1"\n')
    repo.commit("dana", "Release script", t)

    repo.git("push", "-q", "origin", "main")
    repo.git("fetch", "-q", "origin")

    t += 52 * day
    repo.git("checkout", "-q", "-b", "experiment/ai-search")
    repo.write("search.py", f'from openai import OpenAI\n\nclient = OpenAI(api_key="{openai}")\n')
    repo.commit("eve", "Spike: semantic product search", t)
    repo.git("checkout", "-q", "main")

    t += 60 * day
    repo.write("app.py", "from config import settings\nfrom notify import alert\n\n\ndef main():\n"
                         "    print('acme-shop up')\n")
    repo.commit("alice", "Wire alerts into startup", min(t, int(time.time()) - day))
    return dest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("dest", nargs="?", default="demo-repo")
    args = parser.parse_args()
    path = build(Path(args.dest).resolve())
    print(f"Demo repo created at {path}", file=sys.stderr)
