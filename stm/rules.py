"""Detection rules: what a leaked credential looks like on a single line of text."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low")

# Values containing any of these are almost always documentation, not real secrets.
PLACEHOLDER_HINTS = (
    "example", "sample", "xxxx", "changeme", "change_me", "placeholder", "dummy",
    "redacted", "password", "your_", "your-", "yourkey", "insert", "replace", "<", ">", "${",
    "{{", "%(", "process.env", "os.environ", "getenv", "****", "...",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if value.startswith(("{", "$", "%", "/")) or "://" in value:
        return True  # template variables ({pw}, $PW, %s) and paths/URLs, not literal secrets
    return any(h in lowered for h in PLACEHOLDER_HINTS) or len(set(lowered)) <= 2


def char_classes(value: str) -> int:
    return sum(any(test(c) for c in value) for test in (str.islower, str.isupper, str.isdigit))


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    pattern: re.Pattern[str]
    advice: str
    group: int = 1                 # capture group holding the secret
    vet_group: int | None = None   # group to vet for placeholders/entropy (defaults to `group`)
    min_entropy: float = 0.0
    vet_placeholders: bool = False
    min_char_classes: int = 0
    keyed_by_path: bool = False    # identity is match + file (PEM bodies span many lines)
    generic: bool = False          # loose rule; yields to any specific rule on the same span


@dataclass(frozen=True)
class Hit:
    rule: Rule
    value: str    # raw secret: used for fingerprinting and HEAD checks, never written out
    masked: str


def _rule(id: str, name: str, severity: str, pattern: str, advice: str, flags: int = 0, **kw) -> Rule:
    return Rule(id, name, severity, re.compile(pattern, flags), advice, **kw)


RULES: tuple[Rule, ...] = (
    _rule("private-key", "Private key", "critical",
          r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?)-----",
          "Generate a new key pair, trust the new public key wherever the old one was used "
          "(servers, deploy keys, CI), then revoke the old one.",
          group=0, keyed_by_path=True),
    _rule("aws-access-key", "AWS access key ID", "high",
          r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b",
          "Deactivate and delete the key in AWS IAM (Users > Security credentials), "
          "then check CloudTrail for activity you don't recognise."),
    _rule("aws-secret-key", "AWS secret access key", "critical",
          r"aws.{0,20}?(?:secret|private).{0,20}?['\"\s:=]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
          "Delete the access key pair in AWS IAM and create a new one; review CloudTrail.",
          flags=re.IGNORECASE, min_entropy=3.5),
    _rule("github-token", "GitHub token", "critical",
          r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b",
          "Revoke it at github.com/settings/tokens and review the account's security log."),
    _rule("github-pat", "GitHub fine-grained token", "critical",
          r"\b(github_pat_[A-Za-z0-9_]{60,255})\b",
          "Revoke it at github.com/settings/tokens and review the account's security log."),
    _rule("gitlab-token", "GitLab token", "critical",
          r"\b(glpat-[A-Za-z0-9_\-]{20,})",
          "Revoke it in GitLab under Preferences > Access tokens."),
    _rule("anthropic-key", "Anthropic API key", "critical",
          r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})",
          "Delete the key in the Claude Console (API keys) and create a new one."),
    _rule("openai-key", "OpenAI API key", "critical",
          r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{48})(?![A-Za-z0-9_\-])",
          "Revoke it on the OpenAI platform's API keys page and check usage for unexpected spend."),
    _rule("stripe-live-key", "Stripe live key", "critical",
          r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b",
          "Roll the key in the Stripe Dashboard (Developers > API keys)."),
    _rule("slack-token", "Slack token", "high",
          r"\b(xox[abposr]-[A-Za-z0-9-]{10,})",
          "Revoke the token in your Slack app's settings and reinstall the app."),
    _rule("slack-webhook", "Slack webhook", "medium",
          r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)",
          "Delete the webhook in the Slack app's Incoming Webhooks settings and create a new one."),
    _rule("discord-webhook", "Discord webhook", "medium",
          r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)",
          "Delete the webhook in the Discord channel's Integrations settings."),
    _rule("google-api-key", "Google API key", "high",
          r"\b(AIza[0-9A-Za-z_\-]{35})(?![0-9A-Za-z_\-])",
          "Regenerate the key in Google Cloud Console (APIs & Services > Credentials) "
          "and restrict the new one."),
    _rule("sendgrid-key", "SendGrid API key", "high",
          r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])",
          "Delete the key in SendGrid (Settings > API Keys) and create a new one."),
    _rule("twilio-key", "Twilio API key", "high",
          r"\b(SK[0-9a-f]{32})\b",
          "Delete the key in the Twilio Console (API keys & tokens)."),
    _rule("npm-token", "npm token", "high",
          r"\b(npm_[A-Za-z0-9]{36})\b",
          "Revoke it with `npm token revoke` or on npmjs.com (Access Tokens)."),
    _rule("pypi-token", "PyPI token", "high",
          r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})",
          "Remove the token on pypi.org (Account settings > API tokens)."),
    _rule("jwt", "JSON Web Token", "medium",
          r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})",
          "If the token is long-lived, revoke the session or rotate the signing secret."),
    _rule("connection-string", "Database URL with password", "high",
          r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:@/'\"]+:([^\s@/'\"]{3,})@[^\s'\"]+)",
          "Change the database user's password and update every service that connects with it.",
          vet_group=2, vet_placeholders=True),
    _rule("generic-secret", "Hard-coded secret", "medium",
          r"(?:api[_-]?key|apikey|secret|token|passw(?:or)?d|pwd|credential)[A-Za-z0-9_\-]{0,20}[\"']?\s*(?:=>|:=|[:=])\s*[\"']([^\"'\s]{8,200})[\"']",
          "Find out what this value unlocks, rotate it there, and load it from an "
          "environment variable or secrets manager instead.",
          flags=re.IGNORECASE, min_entropy=3.3, vet_placeholders=True, min_char_classes=2, generic=True),
)


def mask_value(value: str) -> str:
    if value.startswith("http"):
        # Keep the host and first path segment only: later segments (workspace IDs, tokens)
        # would let the masked value match the rule again.
        scheme, _, rest = value.partition("://")
        host, _, path = rest.partition("/")
        return f"{scheme}://{host}/{path.split('/')[0]}/…"
    if len(value) <= 8:
        return value[:2] + "…"
    keep = min(8, max(4, len(value) // 6))
    # Keep a vendor prefix like "sk_live_" or "ghp_" whole so the reader can tell what it is.
    prefix_end = max(value.rfind("_", 0, 12), value.rfind("-", 0, 12))
    if prefix_end >= 0:
        keep = max(keep, prefix_end + 3)
    return value[:keep] + "…" + value[-2:]


def _mask(rule: Rule, m: re.Match[str]) -> str:
    value = m.group(rule.group)
    if rule.keyed_by_path:
        return m.group(1)  # "RSA PRIVATE KEY", without the PEM armor the rule matches on
    if rule.vet_group:
        # Only the embedded password is secret; keep the host so the finding is recognisable.
        base = m.start(rule.group)
        start, end = m.span(rule.vet_group)
        return value[: start - base] + "****" + value[end - base:]
    return mask_value(value)


def find_secrets(line: str) -> list[Hit]:
    hits: list[Hit] = []
    taken: list[tuple[int, int]] = []
    for rule in RULES:
        for m in rule.pattern.finditer(line):
            start, end = m.span(rule.group)
            if rule.generic and any(s < end and start < e for s, e in taken):
                continue
            vetted = m.group(rule.vet_group or rule.group)
            if rule.vet_placeholders and looks_like_placeholder(vetted):
                continue
            if rule.min_entropy and shannon_entropy(vetted) < rule.min_entropy:
                continue
            if rule.min_char_classes and char_classes(vetted) < rule.min_char_classes:
                continue
            taken.append((start, end))
            hits.append(Hit(rule, m.group(rule.group), _mask(rule, m)))
    return hits
