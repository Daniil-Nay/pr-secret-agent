from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import scanner

DEFAULT_DATASET = Path(__file__).parent / "dataset.jsonl"


def load_dataset(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8").strip()
    if raw.startswith("["):
        return json.loads(raw)
    rows = []
    for line in raw.splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def evaluate(rows: list[dict]) -> dict:
    tp = fp = tn = fn = 0
    false_pos: list[dict] = []
    false_neg: list[dict] = []
    recall_by_kind: Counter = Counter()
    total_by_kind: Counter = Counter()

    for row in rows:
        text = row["text"]
        gold = int(row["label"])
        kind = row.get("kind", "?")
        predicted = 1 if scanner.scan_line(text) else 0

        if gold == 1:
            total_by_kind[kind] += 1
            if predicted:
                recall_by_kind[kind] += 1

        if predicted and gold:
            tp += 1
        elif predicted and not gold:
            fp += 1
            false_pos.append(row)
        elif not predicted and gold:
            fn += 1
            false_neg.append(row)
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    accuracy = (tp + tn) / len(rows) if rows else 0.0

    return {
        "n": len(rows),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "accuracy": accuracy,
        "false_positives": false_pos,
        "false_negatives": false_neg,
        "recall_by_kind": dict(recall_by_kind),
        "total_by_kind": dict(total_by_kind),
    }


def _print_report(m: dict) -> None:
    print(f"Датасет: {m['n']} строк "
          f"(позитивов {m['tp'] + m['fn']}, негативов {m['tn'] + m['fp']})")
    print(f"TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print("-" * 48)
    print(f"Precision = {m['precision']:.3f}")
    print(f"Recall    = {m['recall']:.3f}")
    print(f"F1        = {m['f1']:.3f}")
    print(f"Accuracy  = {m['accuracy']:.3f}")

    print("-" * 48)
    print("Recall по типам секретов (найдено / всего):")
    for kind in sorted(m["total_by_kind"]):
        found = m["recall_by_kind"].get(kind, 0)
        total = m["total_by_kind"][kind]
        print(f"  {kind:20s} {found}/{total}")

    if m["false_negatives"]:
        print("-" * 48)
        print("Пропущенные секреты (FN):")
        for r in m["false_negatives"]:
            print(f"  [{r.get('kind','?')}] {r['text']}")

    if m["false_positives"]:
        print("-" * 48)
        print("Ложные срабатывания (FP):")
        for r in m["false_positives"]:
            print(f"  [{r.get('kind','?')}] {r['text']}")


def main(argv: list[str]) -> dict:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_DATASET
    if not path.exists():
        print(f"Не найден датасет: {path}")
        return {}
    rows = load_dataset(path)
    metrics = evaluate(rows)
    _print_report(metrics)
    return metrics


if __name__ == "__main__":
    main(sys.argv)
