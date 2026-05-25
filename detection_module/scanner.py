import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class Match:
    service: str
    rule_id: str
    value: str
    start: int
    end: int
    length: int
    prefix: str
    format: str

RULES = [
    {
        "service": "AWS",
        "rule_id": "aws_access_key_id",
        "regex": re.compile(r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        "prefix": ["A3T", "AKIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASIA"],
        "format": "20-char access key id",
    },
    {
        "service": "GitHub",
        "rule_id": "github_pat",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9_]{20,80})(?![A-Za-z0-9_])"),
        "prefix": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        "format": "GitHub token",
    },
    {
        "service": "GitLab",
        "rule_id": "gitlab_token",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(glpat-[A-Za-z0-9_-]{20,80})(?![A-Za-z0-9_])"),
        "prefix": ["glpat-"],
        "format": "GitLab PAT",
    },
    {
        "service": "Slack",
        "rule_id": "slack_token",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(xox[baprs]-[A-Za-z0-9-]{10,200})(?![A-Za-z0-9_])"),
        "prefix": ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"],
        "format": "Slack token",
    },
    {
        "service": "Stripe",
        "rule_id": "stripe_secret_key",
        "regex": re.compile(r"(?i)(?<![A-Za-z0-9_])(sk_(?:live|test)_[A-Za-z0-9]{16,80})(?![A-Za-z0-9_])"),
        "prefix": ["sk_live_", "sk_test_"],
        "format": "Stripe secret key",
    },
    {
        "service": "Google",
        "rule_id": "google_api_key",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_])"),
        "prefix": ["AIza"],
        "format": "Google API key",
    },
    {
        "service": "Azure",
        "rule_id": "azure_storage_key",
        "regex": re.compile(r"(?<![A-Za-z0-9_])([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9_])"),
        "prefix": ["base64"],
        "format": "Azure-like base64 key",
    },
    {
        "service": "OpenAI",
        "rule_id": "openai_api_key",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(sk-[A-Za-z0-9]{20,200})(?![A-Za-z0-9_])"),
        "prefix": ["sk-"],
        "format": "OpenAI API key",
    },
    {
        "service": "Twilio",
        "rule_id": "twilio_token",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(SK[0-9a-fA-F]{32})(?![A-Za-z0-9_])"),
        "prefix": ["SK"],
        "format": "Twilio secret key",
    },
    {
        "service": "Heroku",
        "rule_id": "heroku_api_key",
        "regex": re.compile(r"(?<![A-Za-z0-9_])(heroku[a-z0-9]{24,48})(?![A-Za-z0-9_])", re.I),
        "prefix": ["heroku"],
        "format": "Heroku API key",
    },
]

def scan_line(code: str) -> List[Dict[str, Any]]:
    matches = []
    for rule in RULES:
        for m in rule["regex"].finditer(code):
            val = m.group(1) if m.lastindex else m.group(0)
            prefix = next((p for p in rule["prefix"] if val.startswith(p) or val.lower().startswith(p.lower())), "")
            matches.append(asdict(Match(
                service=rule["service"],
                rule_id=rule["rule_id"],
                value=val,
                start=m.start(1) if m.lastindex else m.start(),
                end=m.end(1) if m.lastindex else m.end(),
                length=len(val),
                prefix=prefix,
                format=rule["format"],
            )))
    return matches

def scan_text(code: str) -> List[Dict[str, Any]]:
    return scan_line(code)

def count_matches(code: str) -> int:
    return len(scan_line(code))