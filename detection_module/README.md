# detection_module

Детекция утечек секретов в строках кода + LLM-верификация кандидатов.

## Состав

| Файл | Назначение |
|------|------------|
| `scanner.py` | детектор: `scan_line(code) -> list[dict]`, `count_matches`, `scan_text`. Сигнатуры формата + контекстный слой + энтропия Шеннона + allowlist/фильтры |
| `rules_secrets_patterns_db.yml` | база сигнатур Secrets Patterns DB (подхватывается автоматически) |
| `rules_extra.yml` | дополнительные правила того же формата |
| `dataset.jsonl` | размеченные строки (`text` / `label` / `kind`), секреты синтетические — держится локально (паттерны ключей отклоняются push-protection), запросить у команды |
| `eval.py` | метрики на датасете: precision / recall / F1, разбивка по типам, FP/FN |
| `ml_big.py` | ML-классификатор: char/word n-граммы + числовые фичи, ансамбль LogReg + HistGradientBoosting |
| `llm_verify.py` | LLM-верификация кандидата по контексту строки (OpenAI-совместимый эндпоинт) |
| `agent.py` | tool-using агент: в цикле сам вызывает `scan_file` / `read_context` / `submit_report` |
| `creddata_to_jsonl.py` | конвертер внешнего бенчмарка Samsung/CredData в формат `eval.py` |
| `test_scanner.py` | тесты scanner.py |

## Запуск

```bash
pip install pyyaml scikit-learn scipy numpy python-dotenv openai pytest

python scanner.py path/to/file.py            # CLI-сканер по файлу
python eval.py                               # метрики на dataset.jsonl
pytest -q test_scanner.py                    # тесты
```

LLM-слой (`llm_verify.py`, `agent.py`) читает `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`
из `.env` рядом с модулем (OpenAI-совместимый эндпоинт). Без ключа не запускается.

Оценка на CredData: склонировать `github.com/Samsung/CredData`, выполнить `download_data.py`,
затем `python creddata_to_jsonl.py --root <путь> --out creddata.jsonl` и `python eval.py creddata.jsonl`.
Файл `creddata.jsonl` не коммитим (внешние данные).

## Результаты

Синтетический датасет — F1 0.96 (оценка завышена, тест на знакомых форматах).
CredData, repo-disjoint (train и test на разных репозиториях): regex+эвристика F1 0.56,
ML-ансамбль F1 0.85. Baseline detect-secrets на том же сплите — F1 0.40.

## Источники техник

Сигнатуры — на базе Secrets Patterns DB. Фильтры ложных срабатываний
(stopwords, шаблоны, UUID, энтропия) — приёмы gitleaks и detect-secrets.
Внешний бенчмарк — Samsung/CredData. Сторонние сканеры не оборачивались.
