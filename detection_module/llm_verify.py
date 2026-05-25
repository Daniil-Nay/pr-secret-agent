import os
import subprocess
import time
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

_here = Path(__file__).resolve().parent
for _p in (_here / ".env", _here.parent / ".env"):
    if _p.exists():
        load_dotenv(_p)


def _gh_token() -> str:
    for v in ("LLM_API_KEY", "GITHUB_TOKEN", "GH_TOKEN"):
        t = os.getenv(v)
        if t:
            return t
    try:
        return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


BASE_URL = os.getenv("LLM_BASE_URL", "https://models.github.ai/inference")
MODEL = os.getenv("LLM_MODEL", "openai/gpt-4o-mini")

_SYS = (
    "Ты — детектор утечек секретов в коде. Тебе дают ОДНУ строку исходного кода. "
    "Определи, содержит ли она НАСТОЯЩИЙ захардкоженный секрет: реальный API-ключ, токен, "
    "пароль, приватный ключ или строку подключения с паролем. "
    "Это НЕ секрет, если: плейсхолдер/пример (your-key, xxxx, example, changeme), имя переменной "
    "без значения, чтение из окружения (os.getenv, process.env, Configuration[...]), ссылка на конфиг, "
    "публичный идентификатор/хеш/UUID без секретного смысла, присваивание другой переменной/константы. "
    "Ответь СТРОГО одним словом: ДА или НЕТ."
)

_client = None


def _cli():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(base_url=BASE_URL, api_key=_gh_token())
    return _client


@lru_cache(maxsize=50000)
def verify(line: str):
    for attempt in range(3):
        try:
            r = _cli().chat.completions.create(
                model=MODEL, max_tokens=4, temperature=0,
                messages=[{"role": "system", "content": _SYS},
                          {"role": "user", "content": f"Строка кода:\n{line}"}])
            ans = (r.choices[0].message.content or "").strip().upper()
            if ans.startswith(("Д", "Y", "1", "ТР")):
                return True
            if ans.startswith(("Н", "N", "0", "FA")):
                return False
            return None
        except Exception as e:
            if attempt < 2 and ("429" in str(e) or "rate" in str(e).lower()):
                time.sleep(3 + attempt * 3)
                continue
            return None
    return None


if __name__ == "__main__":
    for t in ['API_KEY = "AKIAIOSFODNN7EXAMPLE"', 'API_KEY = os.getenv("API_KEY")',
              'password = "changeme"', 'token = "ghp_aB3dEfGhIjKlMnOpQrStUvWxYz0123456789"',
              'finish_pass = finish_pass_phuff;']:
        print(verify(t), "<-", t)
