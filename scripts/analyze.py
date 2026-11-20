#!/usr/bin/env python3
"""Scan LLM-generated code with Bandit and Semgrep and summarize by model / condition.

Run from the project root (the folder that contains outputs/):
    python scripts\\analyze.py
    python scripts\\analyze.py --semgrep-config p/python   (if "auto" fails)
    python scripts\\analyze.py --no-semgrep                (Bandit only)

Expected layout: outputs/<model>/<condition>/taskNN.py
"""
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path.cwd()
OUT = ROOT / "outputs"
RES = ROOT / "results"
SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
SEMGREP_SEV = {"INFO": "LOW", "WARNING": "MEDIUM", "ERROR": "HIGH"}
ENV = dict(os.environ, PYTHONUTF8="1")


def parse_path(p):
    """Return (model, condition, task_number) for outputs/<model>/<cond>/taskNN.py."""
    try:
        rel = Path(p).resolve().relative_to(OUT.resolve())
    except ValueError:
        return None
    if len(rel.parts) != 3:
        return None
    model, cond, fname = rel.parts
    m = re.match(r"task(\d+)\.py$", fname)
    return (model, cond, int(m.group(1))) if m else None


def run_bandit(ignore_nosec=False):
    out = RES / "bandit.json"
    cmd = [sys.executable, "-m", "bandit", "-r", str(OUT), "-f", "json", "-o", str(out), "-q"]
    if ignore_nosec:
        cmd.append("--ignore-nosec")      # count findings even where the code says "# nosec"
    subprocess.run(cmd, env=ENV)
    if not out.exists():
        print("Bandit produced no output; is it installed in this environment?")
        return None
    data = json.loads(out.read_text(encoding="utf-8"))
    rows = []
    for r in data.get("results", []):
        k = parse_path(r["filename"])
        if not k:
            continue
        cwe = (r.get("issue_cwe") or {}).get("id")
        rows.append(dict(tool="bandit", model=k[0], cond=k[1], task=k[2],
                         rule=r["test_id"], cwe=f"CWE-{cwe}" if cwe else "none",
                         severity=r["issue_severity"].upper(),
                         line=r.get("line_number", ""), message=r.get("issue_text", "")))
    return rows


def run_semgrep(config, disable_nosem=False):
    exe = shutil.which("semgrep")
    if not exe:
        print("Semgrep not found on PATH; skipping.")
        return None
    out = RES / "semgrep.json"
    if out.exists():
        out.unlink()
    cmd = [exe, "--config", config, "--json", "-o", str(out), "--quiet", str(OUT)]
    if disable_nosem:
        cmd.append("--disable-nosem")     # count findings even where the code says "# nosemgrep"
    subprocess.run(cmd, env=ENV)
    if not out.exists():
        print(f"Semgrep failed with config '{config}'. Try --semgrep-config p/python.")
        return None
    data = json.loads(out.read_text(encoding="utf-8"))
    rows = []
    for r in data.get("results", []):
        k = parse_path(r["path"])
        if not k:
            continue
        meta = r.get("extra", {}).get("metadata", {})
        cwe_raw = meta.get("cwe", "")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        m = re.search(r"CWE-\d+", str(cwe_raw))
        sev = SEMGREP_SEV.get(r.get("extra", {}).get("severity", "INFO"), "LOW")
        rows.append(dict(tool="semgrep", model=k[0], cond=k[1], task=k[2],
                         rule=r["check_id"].split(".")[-1],
                         cwe=m.group(0) if m else "none", severity=sev,
                         line=r.get("start", {}).get("line", ""),
                         message=r.get("extra", {}).get("message", "").replace("\n", " ")[:300]))
    return rows


def table(title, header, rows):
    print(f"\n=== {title} ===")
    widths = [max(len(str(x)) for x in col) for col in zip(header, *rows)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*header))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[str(x) for x in r]))


def group_stats(findings, file_keys):
    idx = set(file_keys)
    fs = [f for f in findings if (f["model"], f["cond"], f["task"]) in idx]
    n = len(idx)
    total = len(fs)
    med_files = len({(f["model"], f["cond"], f["task"]) for f in fs
                     if SEV_RANK[f["severity"]] >= 2})
    return n, total, round(total / n, 2) if n else 0, round(100 * med_files / n, 1) if n else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep-config", default="auto")
    ap.add_argument("--no-semgrep", action="store_true")
    ap.add_argument("--ignore-nosec", action="store_true",
                    help="do not let # nosec / # nosemgrep comments in the code hide findings")
    ap.add_argument("--exclude-rules", nargs="*", default=[],
                    help="rule ids to drop, e.g. B201 debug-enabled render-template-string")
    args = ap.parse_args()

    RES.mkdir(exist_ok=True)
    files = sorted({k for k in (parse_path(p) for p in OUT.rglob("task*.py")) if k})
    if not files:
        sys.exit("No files found. Run this from the folder that contains outputs/.")
    fileset = set(files)
    models = sorted({k[0] for k in files})
    conds = sorted({k[1] for k in files})
    print(f"Found {len(files)} files across models {models} and conditions {conds}")

    all_findings = []
    tools = []
    b = run_bandit(args.ignore_nosec)
    if b is not None:
        all_findings += b
        tools.append("bandit")
    if not args.no_semgrep:
        s = run_semgrep(args.semgrep_config, args.ignore_nosec)
        if s is not None:
            all_findings += s
            tools.append("semgrep")

    if args.exclude_rules:
        all_findings = [f for f in all_findings if f["rule"] not in args.exclude_rules]
        print(f"Excluding rules: {args.exclude_rules}")

    with open(RES / "findings.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["tool", "model", "cond", "task", "rule", "cwe", "severity", "line", "message"])
        w.writeheader()
        w.writerows(all_findings)

    summary_rows = []
    for tool in tools:
        tf = [f for f in all_findings if f["tool"] == tool]

        # Main comparison: tasks 1-8, C0 vs C1 only
        paired = [k for k in files if k[1] in ("C0", "C1")
                  and (k[0], "C0", k[2]) in fileset and (k[0], "C1", k[2]) in fileset]
        paired_set = set(paired)
        rows = []
        for model in models + ["ALL MODELS"]:
            for cond in ("C0", "C1"):
                keys = [k for k in paired if k[1] == cond and (model == "ALL MODELS" or k[0] == model)]
                if not keys:
                    continue
                n, total, per_file, pct = group_stats(tf, keys)
                rows.append((model, cond, n, total, per_file, pct))
                summary_rows.append((tool, "paired_tasks", model, cond, n, total, per_file, pct))
        table(f"[{tool}] Paired tasks, C0 (plain) vs C1 (security prompt)",
              ["model", "cond", "files", "findings", "per file", "% files w/ med+high"], rows)

        # Same-task comparison across conditions (only tasks present in every listed condition)
        cand = [("C0", "C1", "C2"), ("C0", "C1", "C2", "C4"), ("C0", "C1", "C2", "C3", "C4")]
        if "C4" in conds:
            cand = cand[1:]
        for cs in cand:
            if not all(c in conds for c in cs):
                continue
            trip = [k for k in files if k[1] in cs
                    and all((k[0], c, k[2]) in fileset for c in cs)]
            if not trip:
                continue
            rows = []
            for model in models + ["ALL MODELS"]:
                for cond in cs:
                    keys = [k for k in trip if k[1] == cond and (model == "ALL MODELS" or k[0] == model)]
                    if keys:
                        n, total, per_file, pct = group_stats(tf, keys)
                        rows.append((model, cond, n, total, per_file, pct))
                        summary_rows.append((tool, "same_tasks_" + "_".join(cs), model, cond, n, total, per_file, pct))
            table(f"[{tool}] SAME TASKS ONLY: " + " vs ".join(cs),
                  ["model", "cond", "files", "findings", "per file", "% files w/ med+high"], rows)

        # Per-task paired deltas
        better = same = worse = 0
        for model in models:
            for t in sorted({k[2] for k in files}):
                if (model, "C0", t) in files and (model, "C1", t) in files:
                    c0 = sum(1 for f in tf if (f["model"], f["cond"], f["task"]) == (model, "C0", t))
                    c1 = sum(1 for f in tf if (f["model"], f["cond"], f["task"]) == (model, "C1", t))
                    if c1 < c0:
                        better += 1
                    elif c1 == c0:
                        same += 1
                    else:
                        worse += 1
        print(f"\n[{tool}] Paired comparison (model x task): C1 fewer findings in {better}, "
              f"equal in {same}, more in {worse}")

        # Top CWEs by condition
        for cond in ("C0", "C1"):
            c = Counter(f["cwe"] for f in tf if f["cond"] == cond and (f["model"], f["cond"], f["task"]) in paired_set)
            table(f"[{tool}] Top CWEs, {cond}, paired tasks",
                  ["cwe", "count"], c.most_common(8) or [("none found", 0)])

        # Exploratory: every file, every condition (NOT a fair comparison, tasks differ)
        rows = []
        for model in models:
            for cond in conds:
                keys = [k for k in files if k[0] == model and k[1] == cond]
                if keys:
                    n, total, per_file, pct = group_stats(tf, keys)
                    rows.append((model, cond, n, total, per_file, pct))
        table(f"[{tool}] EXPLORATORY: all files (different tasks per condition, do not compare across conditions)",
              ["model", "cond", "files", "findings", "per file", "% files w/ med+high"], rows)

    with open(RES / "summary.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "scope", "model", "cond", "files", "findings", "per_file", "pct_files_med_high"])
        w.writerows(summary_rows)
    print(f"\nSaved results\\findings.csv and results\\summary.csv")


if __name__ == "__main__":
    main()