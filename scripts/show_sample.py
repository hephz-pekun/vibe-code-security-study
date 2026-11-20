#!/usr/bin/env python3
"""Show each sampled finding with the surrounding code, so you can label it quickly.

Run from the project root after creating results/validation_sample.csv:
    python scripts/show_sample.py
Then read results/validation_context.txt and add a column named verdict to
results/validation_sample.csv with one of: real, false, unsure.
"""
import csv
from pathlib import Path

root = Path.cwd()
rows = list(csv.DictReader(open(root / "results" / "validation_sample.csv", encoding="utf-8-sig")))
out = []
for i, r in enumerate(rows, 1):
    p = root / "outputs" / r["model"] / r["cond"] / f"task{int(r['task']):02d}.py"
    out.append("=" * 78)
    out.append(f"#{i}  {r['tool']}  {r['rule']}  {r['cwe']}   {r['model']}/{r['cond']}/task{int(r['task']):02d}.py  line {r['line']}")
    out.append(f"Scanner says: {r['message']}")
    out.append("-" * 78)
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        n = int(r["line"])
        for k in range(max(1, n - 4), min(len(lines), n + 4) + 1):
            out.append(f"{'>>' if k == n else '  '} {k:4d} | {lines[k - 1]}")
    except Exception as e:
        out.append(f"(could not read file: {e})")
    out.append("Verdict (real / false / unsure): ____\n")
(root / "results" / "validation_context.txt").write_text("\n".join(out), encoding="utf-8")
print(f"Wrote results\\validation_context.txt with {len(rows)} findings")