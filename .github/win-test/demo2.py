#!/usr/bin/env python3
"""Fixed vs. unfixed local_id handling on one binary: locals coverage + the same SQL edits + pseudocode diff.

Usage: demo2.py FIXED_PORT UNFIXED_PORT OUT_DIR [N_FUNCS]

1. Scan an even spread of up to MAX_SCAN functions (time-boxed) on BOTH builds: declared locals vs decomp_lvars.
2. Pick the N functions where the unfixed build loses the most locals (ties: most HASH-keyed temporaries).
3. On each build: rename every HASH-keyed local listed by decomp_lvars to r_<name> by local_id, then to
   r2_<name> using the ORIGINAL local_id; record what each UPDATE actually renamed; save pseudocode.
4. Write summary.json, pseudocode.diff and pseudocode-diff.html.
"""
import difflib
import json
import os
import re
import sys
import time
import urllib.request

fixed_port, unfixed_port, out = sys.argv[1], sys.argv[2], sys.argv[3]
N = int(sys.argv[4]) if len(sys.argv) > 4 else 3
MAX_SCAN, BUDGET = 400, 600
os.makedirs(out, exist_ok=True)


def q(port, sql):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/query", data=sql.encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            res = json.loads(r.read().decode())["results"][0]
    except Exception as e:
        return [], f"transport: {e}"
    return res.get("rows") or [], res.get("error")


DECL = re.compile(r"^\s{2}[A-Za-z_][\w \*]*?[\s\*]\**([A-Za-z_]\w*)(\s*\[[^\]]*\])*;\s*(//.*)?$")


def pseudocode(port, addr):
    rows, _ = q(port, f"SELECT text FROM pseudocode WHERE func_addr = {addr}")
    return "\n".join(str(r[0]) for r in rows)


def declared(text):
    names = []
    for line in (text.split("{", 1)[1] if "{" in text else "").splitlines():
        if not line.strip():
            if names:
                break
            continue
        m = DECL.match(line)
        if not m:
            break
        names.append(m.group(1))
    return names


def coverage(port, addr):
    lv, _ = q(port, f"SELECT local_id, name FROM decomp_lvars WHERE func_addr = {addr}")
    have = {str(r[1]) for r in lv}
    missing = [d for d in declared(pseudocode(port, addr)) if d not in have]
    hashes = sum(1 for r in lv if str(r[0]).startswith("local:HASH:"))
    return missing, hashes


summary = {"funcs": 0, "scanned": 0, "truncated": False,
           "missing_unfixed": 0, "missing_fixed": 0, "funcs_missing_unfixed": 0, "funcs_missing_fixed": 0}
funcs, err = q(unfixed_port, "SELECT addr, name FROM funcs ORDER BY addr")
summary["funcs"] = len(funcs)
step = max(1, len(funcs) // MAX_SCAN)
t0 = time.time()
scored = []
for addr, name in funcs[::step][:MAX_SCAN]:
    if time.time() - t0 > BUDGET:
        summary["truncated"] = True
        break
    addr = int(addr)
    mu, hu = coverage(unfixed_port, addr)
    mf, _ = coverage(fixed_port, addr)
    summary["scanned"] += 1
    summary["missing_unfixed"] += len(mu)
    summary["missing_fixed"] += len(mf)
    summary["funcs_missing_unfixed"] += bool(mu)
    summary["funcs_missing_fixed"] += bool(mf)
    if mu or hu:
        scored.append((len(mu), hu, addr, str(name), mu))
scored.sort(reverse=True)
chosen = scored[:N]
summary["chosen"] = [{"addr": f"0x{a:X}", "name": n, "missing_unfixed": m, "hash_locals_unfixed": h}
                     for _, h, a, n, m in chosen]


def safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:60]


def run(port, label):
    log, landed, attempted = [], 0, 0
    for _, _h, addr, name, _m in chosen:
        lv, _ = q(port, f"SELECT local_id, name FROM decomp_lvars WHERE func_addr = {addr}")
        temps = [(str(i), str(n)) for i, n in lv if str(i).startswith("local:HASH:")]
        log.append(f"== {name} @ 0x{addr:X}: decomp_lvars lists {len(lv)} locals, {len(temps)} HASH-keyed")
        for prefix in ("r_", "r2_"):
            for lid, orig in temps:
                _, err = q(port, f"UPDATE decomp_lvars SET name = '{prefix}{orig}' WHERE func_addr = {addr} AND local_id = '{lid}'")
                now, _ = q(port, f"SELECT name FROM decomp_lvars WHERE func_addr = {addr} AND local_id = '{lid}'")
                got = str(now[0][0]) if now else "(id no longer listed)"
                ok = got == f"{prefix}{orig}"
                attempted += 1
                landed += ok
                log.append(f"   {prefix:3} {lid:34} {orig:12} -> {got:22} {'ok' if ok else 'MISMATCH'}"
                           + (f"  error: {err[:120]}" if err else ""))
        open(f"{out}/{label}-{safe(name)}.c", "w").write(pseudocode(port, addr) + "\n")
    open(f"{out}/{label}-edits.log", "w").write("\n".join(log) + "\n")
    return landed, attempted


summary["edits_unfixed"] = "%d/%d" % run(unfixed_port, "unfixed")
summary["edits_fixed"] = "%d/%d" % run(fixed_port, "fixed")

html_parts, udiff = [], []
for _, _h, addr, name, _m in chosen:
    a = open(f"{out}/unfixed-{safe(name)}.c").read().splitlines()
    b = open(f"{out}/fixed-{safe(name)}.c").read().splitlines()
    udiff += list(difflib.unified_diff(a, b, f"unfixed/{name}.c", f"fixed/{name}.c", lineterm="", n=2))
    html_parts.append(f"<h2>{name} @ 0x{addr:X}</h2>" +
                      difflib.HtmlDiff(wrapcolumn=90).make_table(a, b, "without the fix", "with the fix",
                                                                 context=True, numlines=3))
open(f"{out}/pseudocode.diff", "w").write("\n".join(udiff) + "\n")
summary["diff_lines"] = sum(1 for l in udiff if l[:1] in "+-" and l[:3] not in ("+++", "---"))
open(f"{out}/pseudocode-diff.html", "w").write(
    "<!doctype html><meta charset=utf-8><title>local_id fix: pseudocode diff</title>"
    f"<style>{difflib.HtmlDiff()._styles} body{{font-family:sans-serif}} table.diff{{font-family:monospace;font-size:12px}}</style>"
    f"<h1>{os.path.basename(out)[:16]}: same SQL edits, Ghidra 12.2, without vs. with the local_id fix</h1>"
    f"<pre>{json.dumps({k: v for k, v in summary.items() if k != 'chosen'}, indent=1)}</pre>" + "".join(html_parts))
json.dump(summary, open(f"{out}/summary.json", "w"), indent=1)
print(json.dumps({k: v for k, v in summary.items() if k != "chosen"}))
