#!/usr/bin/env python3
"""C3: a DIFFERENT model reviews the C0 code, then the original model patches it.

Rotation: claude's code is reviewed by gemini, gemini's by copilot, copilot's by claude.

Step 1 (review prompts):   python scripts/build_c3.py --step review --max-task 4
   -> results/c3_review_prompts/<reviewer>_<author>_taskNN.txt
   Paste each into a NEW chat with the REVIEWER; save its reply to results/c3_reviews/<author>_taskNN.txt
Step 2 (patch prompts):    python scripts/build_c3.py --step patch --max-task 4
   -> results/c3_patch_prompts/<author>_taskNN.txt  (only for reviews that exist)
   Paste each into a NEW chat with the AUTHOR; save the reply to outputs/<author>/C3/taskNN.py
"""
import argparse
from pathlib import Path

ORDER = ["claude", "gemini", "copilot"]
REVIEW = ("Review the following Python file for security vulnerabilities. List each issue with its line "
          "number, why it is a problem, and a suggested fix. Do not rewrite the whole file.")
PATCH = ("Here is a Python file and a security review of it. Fix the security issues the review identifies "
         "and give me the complete corrected code in a single Python file.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--step", choices=["review", "patch"], required=True)
    ap.add_argument("--max-task", type=int, default=4)
    args = ap.parse_args()
    root = Path.cwd()
    (root / "results" / "c3_reviews").mkdir(parents=True, exist_ok=True)
    n = 0
    for author in ORDER:
        reviewer = ORDER[(ORDER.index(author) + 1) % len(ORDER)]
        for t in range(1, args.max_task + 1):
            code_path = root / "outputs" / author / "C0" / f"task{t:02d}.py"
            if not code_path.exists():
                continue
            code = code_path.read_text(encoding="utf-8", errors="replace")
            if args.step == "review":
                d = root / "results" / "c3_review_prompts"
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{reviewer}_{author}_task{t:02d}.txt").write_text(
                    f"{REVIEW}\n\nCode:\n{code}\n", encoding="utf-8")
                n += 1
            else:
                rv = root / "results" / "c3_reviews" / f"{author}_task{t:02d}.txt"
                if not rv.exists():
                    continue
                d = root / "results" / "c3_patch_prompts"
                d.mkdir(parents=True, exist_ok=True)
                (d / f"{author}_task{t:02d}.txt").write_text(
                    f"{PATCH}\n\nReview:\n{rv.read_text(encoding='utf-8', errors='replace')}\n\nCode:\n{code}\n",
                    encoding="utf-8")
                n += 1
    print(f"Wrote {n} {args.step} prompts")


if __name__ == "__main__":
    main()