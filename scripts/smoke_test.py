#!/usr/bin/env python3
"""Minimal functional check: does each generated Flask app import and answer GET / ?

Needs these in the venv:
  pip install flask pillow beautifulsoup4 argon2-cffi flask-wtf flask-sqlalchemy bcrypt requests
Run from the project root:  python scripts/smoke_test.py
Each file runs in its own process, in a temporary folder, with a 30 s timeout.
NOTE: this executes the generated code. Run it only on this project.

Categories:
  ok             app imported and GET / returned a status below 500
  http_500       GET / crashed the app (status 500 or an exception while serving)
  import_error   the file failed to import (syntax error, runtime error at start-up)
  missing_dep    the file needs a package that is not installed (not counted as a fault)
  no_app         no Flask app object found (a script or helper functions, not a web app)
  timeout        the file hung
"""
import csv
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path


def child(path):
    import importlib.util
    for k in ("SECRET_KEY", "FLASK_SECRET_KEY", "APP_SECRET_KEY", "SESSION_SECRET"):
        os.environ.setdefault(k, "x" * 64)           # secure apps refuse to start without a key
    for k in ("WEATHER_API_KEY", "API_KEY", "OPENWEATHER_API_KEY", "SMTP_PASSWORD", "ENCRYPTION_KEY"):
        os.environ.setdefault(k, "dummy-" + "k" * 40)
    try:
        spec = importlib.util.spec_from_file_location("generated_app", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["generated_app"] = mod            # dataclasses and similar need this
        spec.loader.exec_module(mod)          # name is not __main__, so app.run() is skipped
    except ModuleNotFoundError as e:
        return {"result": "missing_dep", "detail": str(e)[:120]}
    except BaseException as e:
        return {"result": "import_error", "detail": repr(e)[:120]}
    app = getattr(mod, "app", None)
    if app is None:
        for v in vars(mod).values():
            if v.__class__.__name__ == "Flask":
                app = v
                break
    if app is None:
        return {"result": "no_app", "detail": ""}
    try:
        app.config["PROPAGATE_EXCEPTIONS"] = False
        status = app.test_client().get("/").status_code
        return {"result": "ok" if status < 500 else "http_500", "detail": str(status)}
    except BaseException as e:
        return {"result": "http_500", "detail": repr(e)[:120]}


def main():
    root = Path.cwd()
    files = sorted((root / "outputs").glob("*/C*/task*.py"))
    rows = []
    for f in files:
        model, cond, name = f.parent.parent.name, f.parent.name, f.name
        with tempfile.TemporaryDirectory() as tmp:
            try:
                p = subprocess.run([sys.executable, __file__, "--one", str(f)], cwd=tmp,
                                   capture_output=True, text=True, timeout=30,
                                   env=dict(os.environ, PYTHONUTF8="1"))
                last = (p.stdout.strip().splitlines() or ["{}"])[-1]
                r = json.loads(last) if last.startswith("{") else {"result": "import_error", "detail": p.stderr[-120:]}
            except subprocess.TimeoutExpired:
                r = {"result": "timeout", "detail": ""}
            except Exception as e:
                r = {"result": "import_error", "detail": repr(e)[:120]}
        rows.append((model, cond, name, r["result"], r["detail"]))
        print(f"{model:8s} {cond} {name}: {r['result']} {r['detail'][:60]}")
    (root / "results").mkdir(exist_ok=True)
    with open(root / "results" / "smoke_test.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["model", "cond", "file", "result", "detail"])
        w.writerows(rows)
    tally = defaultdict(Counter)
    for m, c, _, res, _ in rows:
        tally[(m, c)][res] += 1
    print("\nmodel    cond  files  ok  http_500  import_error  missing_dep  no_app  timeout")
    for (m, c), t in sorted(tally.items()):
        print(f"{m:8s} {c:5s} {sum(t.values()):5d}  {t['ok']:2d}  {t['http_500']:8d}  {t['import_error']:12d}  "
              f"{t['missing_dep']:11d}  {t['no_app']:6d}  {t['timeout']:7d}")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--one":
        print(json.dumps(child(sys.argv[2])))
    else:
        main()