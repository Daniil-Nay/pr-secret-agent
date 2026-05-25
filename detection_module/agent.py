import json, sys, time
from openai import OpenAI
import scanner
import llm_verify
try: sys.stdout.reconfigure(encoding="utf-8")
except Exception: pass

client = OpenAI(base_url=llm_verify.BASE_URL, api_key=llm_verify._gh_token())
MODEL = llm_verify.MODEL

SYS = (
    "Ты — pr-secret-agent, автономный агент анализа pull request на утечки секретов. "
    "Тебе дают путь к изменённому файлу. Действуй сам, шаг за шагом, вызывая инструменты:\n"
    "1) scan_file — запусти детектор, получи кандидатов;\n"
    "2) для КАЖДОГО кандидата вызови read_context, посмотри окружение и реши: это НАСТОЯЩИЙ "
    "захардкоженный секрет или ложное (плейсхолдер, чтение из окружения, тест, пример);\n"
    "3) когда разобрался со всеми — вызови submit_report с Markdown-отчётом "
    "(найденные настоящие секреты + рекомендации; ложные перечисли отдельно). "
    "Секреты в отчёте пиши в маскированном виде. Не выдумывай строки, которых не видел."
)

TOOLS = [
    {"type": "function", "function": {"name": "scan_file",
        "description": "Запустить детектор секретов по файлу. Возвращает список кандидатов (строка, тип, маскированное значение).",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "read_context",
        "description": "Прочитать строки вокруг указанной (±radius) — чтобы понять, настоящий ли секрет.",
        "parameters": {"type": "object", "properties": {"path": {"type": "string"}, "line": {"type": "integer"},
            "radius": {"type": "integer"}}, "required": ["path", "line"]}}},
    {"type": "function", "function": {"name": "submit_report",
        "description": "Финальный Markdown-отчёт. Вызови, когда проанализировал всех кандидатов.",
        "parameters": {"type": "object", "properties": {"markdown": {"type": "string"}}, "required": ["markdown"]}}},
]

def _lines(path):
    return open(path, encoding="utf-8", errors="ignore").read().splitlines()

def scan_file(path):
    out = []
    for i, line in enumerate(_lines(path), 1):
        for d in scanner.scan_line(line):
            out.append({"line": i, "rule_id": d["rule_id"], "service": d["service"], "masked": d["value"]})
    return json.dumps(out, ensure_ascii=False) if out else "[] (кандидатов нет)"

def read_context(path, line, radius=3):
    L = _lines(path); a = max(0, line-1-radius); b = min(len(L), line+radius)
    return json.dumps([{"line": j+1, "code": L[j]} for j in range(a, b)], ensure_ascii=False)

DISPATCH = {"scan_file": scan_file, "read_context": read_context}

def _chat(messages):
    for attempt in range(4):
        try:
            return client.chat.completions.create(model=MODEL, messages=messages, tools=TOOLS,
                                                  tool_choice="auto", temperature=0, max_tokens=1200)
        except Exception as e:
            if "429" in str(e) or "rate" in str(e).lower():
                time.sleep(4+attempt*4); continue
            raise

def run(path):
    messages = [{"role": "system", "content": SYS},
                {"role": "user", "content": f"Проанализируй файл на утечки секретов: {path}"}]
    report = None
    for step in range(1, 9):
        resp = _chat(messages)
        m = resp.choices[0].message
        if not m.tool_calls:
            print(f"[шаг {step}] LLM (без инструмента): {(m.content or '')[:200]}")
            report = report or m.content
            break
        messages.append({"role": "assistant", "content": m.content or "",
                         "tool_calls": [{"id": tc.id, "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments}} for tc in m.tool_calls]})
        for tc in m.tool_calls:
            name = tc.function.name
            args = json.loads(tc.function.arguments or "{}")
            print(f"[шаг {step}] LLM вызвал: {name}({json.dumps(args, ensure_ascii=False)})")
            if name == "submit_report":
                report = args.get("markdown", ""); result = "ok"
            else:
                result = DISPATCH[name](**args)
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
        if report is not None:
            break
    print("\n================ ОТЧЁТ АГЕНТА ================\n")
    print(report or "(агент не сформировал отчёт)")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "../samples/leaky_config.py"
    run(path)
