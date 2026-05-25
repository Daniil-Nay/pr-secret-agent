from __future__ import annotations

import math
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


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
    detector: str
    severity: str


@dataclass
class Signature:
    rule_id: str
    service: str
    pattern: str
    fmt: str = "regex signature"
    severity: str = "high"
    confidence: str = "high"
    min_entropy: float = 0.0
    strict: bool = True
    prefixes: tuple = ()
    _rx: Optional[re.Pattern] = field(default=None, repr=False)
    _group: int = field(default=0, repr=False)


def _compile(sig: Signature) -> Signature:
    sig._rx = re.compile(sig.pattern)
    sig._group = 1 if sig._rx.groups else 0
    return sig


_BUILTIN: List[Signature] = [
    Signature("aws_access_key_id", "AWS",
              r"(?<![A-Z0-9])((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])",
              "AWS access key id", prefixes=("AKIA", "ASIA", "A3T", "AGPA", "AIDA", "AROA")),
    Signature("aws_secret", "AWS Secret Access Key",
              r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS secret"),
    Signature("github_pat", "GitHub",
              r"(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9_]{20,80})(?![A-Za-z0-9_])",
              "GitHub token", prefixes=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    Signature("github_finegrained", "GitHub Fine-grained PAT",
              r"\b(github_pat_[A-Za-z0-9_]{82})\b", "GitHub fine-grained PAT", prefixes=("github_pat_",)),
    Signature("gitlab_token", "GitLab",
              r"(?<![A-Za-z0-9_])(glpat-[A-Za-z0-9_-]{20,80})(?![A-Za-z0-9_])",
              "GitLab PAT", prefixes=("glpat-",)),
    Signature("slack_token", "Slack",
              r"(?<![A-Za-z0-9_])(xox[baprs]-[A-Za-z0-9-]{10,200})(?![A-Za-z0-9_])",
              "Slack token", prefixes=("xoxb-", "xoxp-")),
    Signature("stripe_secret_key", "Stripe",
              r"(?i)(?<![A-Za-z0-9_])(sk_(?:live|test)_[A-Za-z0-9]{16,80})(?![A-Za-z0-9_])",
              "Stripe secret key", prefixes=("sk_live_", "sk_test_")),
    Signature("google_api_key", "Google",
              r"(?<![A-Za-z0-9_])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_])", "Google API key", prefixes=("AIza",)),
    Signature("gcp_oauth", "Google OAuth", r"\b(GOCSPX-[A-Za-z0-9_\-]{24,28})\b", "Google OAuth secret", prefixes=("GOCSPX-",)),
    Signature("openai_api_key", "OpenAI",
              r"(?<![A-Za-z0-9_])(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9]{20,200})(?![A-Za-z0-9_])",
              "OpenAI API key", prefixes=("sk-",)),
    Signature("anthropic_key", "Anthropic", r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b", "Anthropic API key", prefixes=("sk-ant-",)),
    Signature("slack_webhook", "Slack Webhook",
              r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9]{16,})", "Slack webhook"),
    Signature("telegram_bot", "Telegram", r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b", "Telegram bot token"),
    Signature("sendgrid_key", "SendGrid", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "SendGrid API key", prefixes=("SG.",)),
    Signature("twilio_sid", "Twilio Account SID", r"(?<![A-Za-z0-9])(AC[0-9a-f]{32})(?![A-Za-z0-9])", "Twilio Account SID", prefixes=("AC",)),
    Signature("mailgun_key", "Mailgun", r"\b(key-[0-9a-f]{32})\b", "Mailgun API key", prefixes=("key-",)),
    Signature("npm_token", "npm", r"\b(npm_[A-Za-z0-9]{36})\b", "npm token", prefixes=("npm_",)),
    Signature("pypi_token", "PyPI", r"\b(pypi-[A-Za-z0-9_\-]{16,})\b", "PyPI token", prefixes=("pypi-",)),
    Signature("shopify_token", "Shopify", r"\b(shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32})\b", "Shopify token", prefixes=("shpat_",)),
    Signature("jwt", "JSON Web Token",
              r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,})\b", "JWT", prefixes=("eyJ",)),
    Signature("private_key", "Private Key Block",
              r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)", "PEM private key"),
    Signature("db_url_creds", "Credentials in URL",
              r"(?i)\b([a-z][a-z0-9+.\-]*://[^:/\s@]+:[^@/\s]{3,}@[^\s/'\"]+)", "URL with credentials"),
    Signature("linear_api", "Linear", r"\b(lin_api_[0-9A-Za-z]{40})\b", "Linear API key", prefixes=("lin_api_",)),
    Signature("notion_secret", "Notion", r"\b(secret_[A-Za-z0-9]{43})\b", "Notion token", prefixes=("secret_",)),
    Signature("postman_api", "Postman", r"\b(PMAK-[a-zA-Z0-9]{24}-[a-zA-Z0-9]{34})\b", "Postman API key", prefixes=("PMAK-",)),
    Signature("doppler_token", "Doppler", r"\b(dp\.pt\.[a-zA-Z0-9]{43})\b", "Doppler token", prefixes=("dp.pt.",)),
    Signature("discord_bot", "Discord", r"\b([MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27})\b", "Discord bot token"),
    Signature("square_token", "Square", r"\b(sq0atp-[0-9A-Za-z_\-]{22})\b", "Square token", prefixes=("sq0atp-",)),
    Signature("mailchimp_key", "Mailchimp", r"\b([0-9a-f]{32}-us[0-9]{1,2})\b", "Mailchimp key"),
]


ENT_MIN_LEN = 32
ENT_THRESHOLD = 4.6

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|my[_-]?|xxx+|example|sample|changeme|placeholder|redacted"
    r"|dummy|fake|test[_-]?key|<[^>]*>|\.\.\.|\bfoo\b|\bbar\b|\bsomething\b|0{6,}|1234567)")
_TEMPLATED_RE = re.compile(r"\{\{.*\}\}|\$\{.*\}|<[^>]*>|%\([^)]*\)s|\$[A-Z][A-Z0-9_]+")
_UUID_RE = re.compile(r"(?i)\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_ALPHA_RE = re.compile(r"[A-Za-z]")
_DIGIT_RE = re.compile(r"[0-9]")
_STOPWORDS = {
    "password", "passwd", "secret", "token", "example", "sample", "test", "testing",
    "changeme", "default", "dummy", "fake", "none", "null", "true", "false", "something",
    "your", "admin", "user", "username", "placeholder", "redacted", "todo", "undefined",
    "root", "string", "value", "xxxxxxxx", "secretkey", "mysecret", "yourtoken",
}
_SEQ = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"]

_CTX_RE = re.compile(
    r"(?i)[A-Za-z0-9_.\-]{0,40}"
    r"(?:secret|passwd|password|pass|pwd|api[_-]?key|apikey|access[_-]?key|client[_-]?secret"
    r"|private[_-]?key|auth[_-]?token|token|credential|otp|salt|nonce|signing|session[_-]?key|bearer)"
    r"[A-Za-z0-9_.\-]{0,25}\s*[:=]\s*"
    r"(?:\"([^\"\r\n]{4,150})\"|'([^'\r\n]{4,150})'|([^\s,;)#'\"]{6,150}))")

_DBURL_DENY = re.compile(r"(?i)(example\.(com|org|net)|localhost|127\.0\.0\.1|contoso\.com|john\.doe|letmein|password123|user:pass)")
_CODEREF_RE = re.compile(r"(?i)\A(os\.|sys\.|process\.|System\.|config|settings|getenv|environ|Configuration|require\(|import\b|new\b|self\.|this\.)")
_NOISE_RULE = re.compile(r"(?i)(arn|amazonaws|hostname|\bhost\b|endpoint|\binternal\b|gateway|\belb\b|\bec2\b|\bregion\b|bucket|cred.?file|password_in_url|\buri\b)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in {ch: s.count(ch) for ch in set(s)}.values())


def _is_sequential(t: str) -> bool:
    if len(set(t)) <= 2:
        return True
    low = t.lower()
    return any(low in src or low in src[::-1] for src in _SEQ)


def _is_hash_like(t: str) -> bool:
    return (_HEX_RE.match(t) and len(t) in (32, 40, 64)) or t.isdigit()


def _mixed(t: str) -> bool:
    return bool(_ALPHA_RE.search(t) and _DIGIT_RE.search(t))


def _is_allowlisted(t: str) -> bool:
    return bool(t.lower() in _STOPWORDS or _PLACEHOLDER_RE.search(t)
                or _TEMPLATED_RE.search(t) or _UUID_RE.match(t) or _is_sequential(t))


def _is_placeholderish(t: str) -> bool:
    return bool(t.lower() in _STOPWORDS or _PLACEHOLDER_RE.search(t) or _TEMPLATED_RE.search(t))


def _valid_ctx_value(v: Optional[str], quoted: bool) -> Optional[str]:
    if v is None:
        return None
    v = v.strip()
    if len(v) < 6 or " " in v:
        return None
    if _is_placeholderish(v):
        return None
    if v.startswith(("/", "./", "../", "http", "www.")) or "://" in v:
        return None
    if re.search(r"[\[\](){}<>$`\\]", v) or _CODEREF_RE.match(v):
        return None
    if not quoted and ("_" in v or "::" in v or re.search(r"[A-Za-z]\.[A-Za-z]", v)):
        return None
    return v


def _mask(t: str) -> str:
    return "*" * len(t) if len(t) <= 8 else f"{t[:4]}...{t[-2:]}"


def _prefix(v: str, prefixes: tuple) -> str:
    for p in prefixes:
        if v.lower().startswith(p.lower()):
            return p
    return v[:4]


def _overlaps(s: int, e: int, spans: List) -> bool:
    return any(a < e and s < b for a, b in spans)


_SIGNATURES: List[Signature] = [_compile(s) for s in _BUILTIN]


def _findings(code: str) -> List[Match]:
    out: List[Match] = []
    covered: List = []

    for sig in _SIGNATURES:
        for m in sig._rx.finditer(code):
            gi = sig._group
            if gi and m.group(gi) is None:
                gi = 0
            value = m.group(gi)
            s, e = m.span(gi)
            if _overlaps(s, e, covered):
                continue
            if sig.rule_id == "db_url_creds" and _DBURL_DENY.search(value):
                continue
            if not sig.strict and _is_allowlisted(value):
                continue
            if sig.min_entropy and shannon_entropy(value) < sig.min_entropy:
                continue
            out.append(Match(sig.service, sig.rule_id, _mask(value), s, e, len(value),
                             _prefix(value, sig.prefixes), sig.fmt, "signature", sig.severity))
            covered.append((s, e))

    for m in _CTX_RE.finditer(code):
        gi = 1 if m.group(1) is not None else 2 if m.group(2) is not None else 3
        s, e = m.span(gi)
        if _overlaps(s, e, covered):
            continue
        v = _valid_ctx_value(m.group(gi), gi != 3)
        if not v:
            continue
        out.append(Match("Secret assignment", "generic_assignment", _mask(v), s, e,
                         len(v), v[:4], "secret in assignment", "signature", "medium"))
        covered.append((s, e))

    for tm in _TOKEN_RE.finditer(code):
        token, (s, e) = tm.group(0), tm.span()
        if _overlaps(s, e, covered) or len(token) < ENT_MIN_LEN or "/" in token:
            continue
        if _is_allowlisted(token) or _is_hash_like(token) or not _mixed(token):
            continue
        if shannon_entropy(token) >= ENT_THRESHOLD:
            out.append(Match("High-entropy string", "high_entropy", _mask(token), s, e,
                             len(token), token[:4], "high-entropy string", "entropy", "medium"))
            covered.append((s, e))

    out.sort(key=lambda f: f.start)
    return out


def scan_line(code: str) -> List[Dict[str, Any]]:
    return [asdict(f) for f in _findings(code)]


def scan_text(code: str) -> List[Dict[str, Any]]:
    return scan_line(code)


def count_matches(code: str) -> int:
    return len(_findings(code))


count = count_matches


def load_rules_from_yaml(path) -> List[Signature]:
    import yaml
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    items = raw.get("patterns", raw) if isinstance(raw, dict) else raw
    out: List[Signature] = []
    for it in items or []:
        p = it.get("pattern", it) if isinstance(it, dict) else {}
        name, regex = p.get("name"), p.get("regex")
        if not name or not regex:
            continue
        rule_id = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
        if _NOISE_RULE.search(name) or _NOISE_RULE.search(rule_id):
            continue
        conf = str(p.get("confidence", "low")).lower()
        try:
            sig = _compile(Signature(rule_id=rule_id, service=name, pattern=regex, fmt="Secrets Patterns DB",
                                     severity="high" if conf == "high" else "medium", confidence=conf,
                                     strict=(conf == "high"), min_entropy=0.0 if conf == "high" else 3.5))
        except re.error:
            continue
        sig._group = 0
        out.append(sig)
    return out


def register(sigs: List[Signature]) -> None:
    _SIGNATURES.extend(sigs)


_HERE = Path(__file__).parent
for _name in ("rules_secrets_patterns_db.yml", "rules_extra.yml"):
    _f = _HERE / _name
    if _f.exists():
        try:
            register(load_rules_from_yaml(_f))
        except Exception as exc:
            print(f"[scanner] {_name} не подключён: {exc}", file=sys.stderr)


def _cli(argv: List[str]) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    paths, total = argv[1:], 0
    srcs = [(p, None) for p in paths] if paths else [("stdin", sys.stdin.read())]
    for path, pre in srcs:
        if pre is None:
            try:
                pre = Path(path).read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                print(f"[skip] {path}: {exc}")
                continue
        for i, line in enumerate(pre.splitlines(), 1):
            for d in scan_line(line):
                total += 1
                print(f"{path}:{i}: [{d['severity']}] {d['rule_id']} ({d['service']}) -> {d['value']} len={d['length']}")
    print(f"\nИтого секретов: {total} | активных сигнатур: {len(_SIGNATURES)}")
    return 1 if total else 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv))
