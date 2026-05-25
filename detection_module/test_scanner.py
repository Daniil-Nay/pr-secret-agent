import pytest

import scanner

POSITIVE = [
    ('AWS_KEY = "AKIA' 'IOSFODNN7EXAMPLE"', "aws_access_key_id"),
    ('token = "ghp_' 'aB3dEfGhIjKlMnOpQrStUvWxYz0123456789"', "github_pat"),
    ('GOOGLE_API_KEY=AIza' 'SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q', "google_api_key"),
    ('STRIPE_KEY = "sk_live_' '4eC39HqLyjWDarjtT1zdp7dc"', "stripe_secret_key"),
    ('slack = "xoxb-' '2488385019-2490902815302-abcdefghijklmnopqrst"', "slack_token"),
    ('DSN = "postgres://admin:' 'S3cr3tP4ss@db:5432/prod"', "db_url_creds"),
    ('-----BEGIN RSA ' 'PRIVATE KEY-----', "private_key"),
    ('password = "Wq8!' 'zPk2@mLx9Qr"', "generic_assignment"),
    ('NOTION_TOKEN = "secret_' 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"', "notion_secret"),
]

NEGATIVE = [
    'API_KEY = os.getenv("API_KEY")',
    'API_KEY = "your-api-key-here"',
    'username = "admin"',
    'etag = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"',
    'EXAMPLE_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxx"',
    'token = settings.GITHUB_TOKEN',
    'version = "1.2.3"',
    'request_id = "550e8400-e29b-41d4-a716-446655440000"',
]


@pytest.mark.parametrize("line,rule_id", POSITIVE)
def test_positive(line, rule_id):
    ms = scanner.scan_line(line)
    assert ms, f"должен найти секрет: {line}"
    assert any(m["rule_id"] == rule_id for m in ms), \
        f"ждал rule_id={rule_id}, получил {[m['rule_id'] for m in ms]}"


@pytest.mark.parametrize("line", NEGATIVE)
def test_negative(line):
    assert scanner.scan_line(line) == [], f"ложное срабатывание: {line}"


def test_empty():
    assert scanner.scan_line("") == []


def test_count_matches():
    assert scanner.count_matches('username = "admin"') == 0
    assert scanner.count_matches('AWS_KEY = "AKIA' 'IOSFODNN7EXAMPLE"') >= 1


def test_value_is_masked():
    tok = "ghp_" "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789"
    m = scanner.scan_line(f'token = "{tok}"')[0]
    assert tok not in m["value"]
    assert "..." in m["value"]


def test_dict_schema():
    line = "GOOGLE_API_KEY=" "AIza" "SyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q"
    m = scanner.scan_line(line)[0]
    for k in ("service", "rule_id", "value", "start", "end", "length", "prefix", "format"):
        assert k in m
