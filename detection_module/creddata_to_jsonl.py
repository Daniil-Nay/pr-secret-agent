from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def _resolve(root: Path, file_path: str) -> Path | None:
    for cand in (root / file_path, root / "data" / file_path, Path(file_path)):
        if cand.is_file():
            return cand
    return None


def convert(root: Path, out: Path, limit: int | None = None) -> dict:
    meta_dir = root / "meta"
    if not meta_dir.is_dir():
        print(f"Нет папки meta/ в {root}. Это точно checkout CredData?", file=sys.stderr)
        return {}

    n, pos, missing = 0, 0, 0
    file_cache: dict[Path, list[str]] = {}

    with out.open("w", encoding="utf-8") as w:
        for csv_path in sorted(meta_dir.glob("*.csv")):
            with csv_path.open(encoding="utf-8", errors="ignore") as f:
                for row in csv.DictReader(f):
                    gt = (row.get("GroundTruth") or "").strip().upper()
                    label = 1 if gt == "T" else 0
                    fp = _resolve(root, row.get("FilePath", ""))
                    if fp is None:
                        missing += 1
                        continue
                    if fp not in file_cache:
                        file_cache[fp] = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
                    lines = file_cache[fp]
                    try:
                        idx = int(row["LineStart"]) - 1
                    except (KeyError, ValueError):
                        continue
                    if not (0 <= idx < len(lines)):
                        continue
                    text = lines[idx].strip()[:400]
                    if not text:
                        continue
                    kind = (row.get("Category") or "unknown").split(":")[0].strip() or "unknown"
                    repo = (row.get("RepoName") or "").strip()
                    if not repo:
                        fpp = (row.get("FilePath") or "").replace("\\", "/").split("/")
                        repo = fpp[1] if len(fpp) > 1 and fpp[0] == "data" else (fpp[0] if fpp else "?")
                    w.write(json.dumps({"text": text, "label": label, "kind": kind, "repo": repo},
                                       ensure_ascii=False) + "\n")
                    n += 1
                    pos += label
                    if limit and n >= limit:
                        _summary(n, pos, missing, out)
                        return {"n": n, "pos": pos}
    _summary(n, pos, missing, out)
    return {"n": n, "pos": pos}


def _summary(n: int, pos: int, missing: int, out: Path) -> None:
    print(f"Записано строк: {n} (позитивов {pos}, негативов {n - pos})")
    if missing:
        print(f"Пропущено (файл не найден в data/): {missing} — выполни download_data.py")
    print(f"Готово: {out}")


def main() -> None:
    ap = argparse.ArgumentParser(description="CredData -> JSONL для eval.py")
    ap.add_argument("--root", required=True, help="путь к checkout-у Samsung/CredData")
    ap.add_argument("--out", default="creddata.jsonl", help="куда писать JSONL")
    ap.add_argument("--limit", type=int, default=None, help="ограничить число строк")
    args = ap.parse_args()
    convert(Path(args.root), Path(args.out), args.limit)


if __name__ == "__main__":
    main()
