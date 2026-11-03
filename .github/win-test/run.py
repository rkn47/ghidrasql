#!/usr/bin/env python3
"""Windows test driver: analyze one binary with the fixed and the unfixed LibGhidraHost on Ghidra 12.2,
run the fixed-vs-unfixed edit comparison, the per-sample checks and the table sweep, then report the
results as GitHub annotations.

Environment: CLI, GHIDRA_FIX, GHIDRA_UNFIX, TARGET, OUT.
"""
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
CLI, GFIX, GUNFIX = os.environ["CLI"], os.environ["GHIDRA_FIX"], os.environ["GHIDRA_UNFIX"]
TARGET, OUT = os.environ["TARGET"], pathlib.Path(os.environ["OUT"])
OUT.mkdir(parents=True, exist_ok=True)


def notice(title, msg, level="notice"):
    print(f"::{level} title={title}::{msg}", flush=True)


def get(url, timeout=5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def start(port, ghidra, label):
    proj = OUT / f"proj-{label}"
    proj.mkdir(exist_ok=True)
    log = open(OUT / f"server-{label}.log", "w")
    return subprocess.Popen([CLI, "--ghidra", ghidra, "--binary", TARGET, "--project", str(proj),
                             "--project-name", "p", "--analyze", "--http", "--port", str(port),
                             "--max-runtime", "0"], stdout=log, stderr=subprocess.STDOUT)


def wait_ready(port, proc, limit=1800):
    t0 = time.time()
    while time.time() - t0 < limit:
        if proc.poll() is not None:
            return f"exited ({proc.returncode})"
        try:
            get(f"http://127.0.0.1:{port}/health/deep")
            return "ready"
        except Exception:
            time.sleep(2)
    return "timeout"


def stop(port, proc):
    try:
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/shutdown", method="POST"), timeout=10)
    except Exception:
        pass
    try:
        proc.wait(timeout=300)
        return "clean"
    except subprocess.TimeoutExpired:
        proc.kill()
        return "killed"


def py(*args, timeout):
    return subprocess.run([sys.executable, *map(str, args)], timeout=timeout, capture_output=True, text=True)


t0 = time.time()
pf, pu = start(9301, GFIX, "fixed"), start(9302, GUNFIX, "unfixed")
sf, su = wait_ready(9301, pf), wait_ready(9302, pu)
notice("Analysis", f"{pathlib.Path(TARGET).name}: fixed={sf}, unfixed={su} after {round(time.time() - t0)}s")
failed = False
if sf == "ready" and su == "ready":
    r = py(HERE / "demo2.py", 9301, 9302, OUT / "demo", 3, timeout=3600)
    (OUT / "demo.out").write_text(r.stdout + r.stderr)
    r = py(HERE / "checks.py", 9301, OUT / "checks-fixed.json", 150, timeout=2400)
    (OUT / "checks.out").write_text(r.stdout + r.stderr)
    r = py(HERE / "sweep.py", 9301, OUT / "sweep.tsv", timeout=1800)
    (OUT / "sweep.out").write_text(r.stdout + r.stderr)
else:
    failed = True
shut = f"fixed {stop(9301, pf)}, unfixed {stop(9302, pu)}"

try:
    s = json.loads((OUT / "demo" / "summary.json").read_text())
    notice("Missing locals (unfixed -> fixed)",
           f"{s['missing_unfixed']} -> {s['missing_fixed']} over {s['scanned']} of {s['funcs']} functions")
    notice("Renames landed (unfixed -> fixed)", f"{s['edits_unfixed']} -> {s['edits_fixed']}; diff lines: {s['diff_lines']}")
    landed, tried = map(int, s["edits_fixed"].split("/"))
    failed |= s["missing_fixed"] > 0 or landed != tried
except Exception as e:
    notice("Comparison", f"no summary: {e}", "error")
    failed = True
try:
    c = json.loads((OUT / "checks-fixed.json").read_text())
    notice("Fixed-build checks", f"{c['sampled']} fns: missing={c['missing']} dup_ids={c['dup_ids']} "
           f"hash0={c['hash0_rows']} query_errors={c['query_errors']} id-stability={c['idstab'].get('status')}")
except Exception as e:
    notice("Fixed-build checks", f"no result: {e}", "error")
    failed = True
try:
    rows = [l.split("\t") for l in (OUT / "sweep.tsv").read_text().splitlines() if l]
    errs = [r[0] for r in rows if len(r) > 1 and r[1] != "ok"]
    notice("Sweep (fixed)", f"{len(rows) - len(errs)}/{len(rows)} ok; errors: {', '.join(errs) or 'none'}")
    for r in rows:
        if len(r) > 1 and r[1] != "ok" and "byte_search" not in r[0]:
            notice(f"Sweep error: {r[0]}", (r[3] if len(r) > 3 else "")[:600] or "(no detail)")
except Exception as e:
    notice("Sweep (fixed)", f"no result: {e}", "error")
    failed = True
for label in ("fixed", "unfixed"):
    log = (OUT / f"server-{label}.log").read_text(errors="replace")
    exc = [l.strip() for l in log.splitlines() if "Exception" in l and "GCC Exception" not in l]
    notice(f"Server log ({label})", f"{len(exc)} exception lines; shutdown {shut}" + (f"; first: {exc[0][:200]}" if exc else ""))
sys.exit(1 if failed else 0)
