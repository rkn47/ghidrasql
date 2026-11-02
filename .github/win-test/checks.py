#!/usr/bin/env python3
"""Per-sample checks against a live ghidrasql server.

Usage: checks.py PORT OUT_JSON [MAX_FUNCS]

- decomp_lvars vs. the locals declared in the pseudocode, over an even spread of functions
- duplicate local_ids, HASH-keyed and unresolved-hash (HASH:00000000) locals
- local_id stability: rename, rename again via the original id, same-width retype, rename
"""
import json
import re
import sys
import time
import urllib.request

port, out_path = sys.argv[1], sys.argv[2]
MAXF = int(sys.argv[3]) if len(sys.argv) > 3 else 150
BUDGET = 300  # seconds for the sampling phase
t_start = time.time()


def q(sql, timeout=600):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/query", data=sql.encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.loads(r.read().decode())["results"][0]
    except Exception as e:
        return [], [], f"transport: {e}"
    return res.get("columns") or [], res.get("rows") or [], res.get("error")


DECL = re.compile(r"^\s{2}[A-Za-z_][\w \*]*?[\s\*]\**([A-Za-z_]\w*)(\s*\[[^\]]*\])*;\s*(//.*)?$")
res = {"funcs": 0, "sampled": 0, "declared": 0, "missing": 0, "missing_examples": [], "dup_ids": 0,
       "lvar_rows": 0, "hash_rows": 0, "hash0_rows": 0, "query_errors": 0, "error_examples": [],
       "truncated": False, "idstab": {}}

_, funcs, err = q("SELECT addr, name FROM funcs ORDER BY addr")
if err:
    res["fatal"] = err
    json.dump(res, open(out_path, "w"), indent=1)
    sys.exit(1)
res["funcs"] = len(funcs)
step = max(1, len(funcs) // MAXF)
sample = funcs[::step][:MAXF]

candidates = []  # (func, local_id, name, type)
for addr, fname in sample:
    if time.time() - t_start > BUDGET:
        res["truncated"] = True
        break
    addr = int(addr)
    _, prow, e1 = q(f"SELECT text FROM pseudocode WHERE func_addr = {addr}")
    _, lv, e2 = q(f"SELECT local_id, name, type, storage FROM decomp_lvars WHERE func_addr = {addr}")
    if e1 or e2:
        res["query_errors"] += 1
        if len(res["error_examples"]) < 5:
            res["error_examples"].append(f"0x{addr:X} {fname}: {(e1 or e2)[:200]}")
        continue
    res["sampled"] += 1
    text = "\n".join(str(r[0]) for r in prow)
    body = text.split("{", 1)[1] if "{" in text else ""
    declared = []
    for line in body.splitlines():
        if not line.strip():
            if declared:
                break
            continue
        m = DECL.match(line)
        if not m:
            break
        declared.append(m.group(1))
    names = {str(r[1]) for r in lv}
    ids = [str(r[0]) for r in lv]
    missing = [d for d in declared if d not in names]
    res["declared"] += len(declared)
    res["missing"] += len(missing)
    if missing and len(res["missing_examples"]) < 6:
        res["missing_examples"].append(f"0x{addr:X} {fname}: {missing[:6]}")
    res["dup_ids"] += len(ids) - len(set(ids))
    res["lvar_rows"] += len(lv)
    for lid, name, typ, storage in lv:
        if str(lid).startswith("local:HASH:"):
            res["hash_rows"] += 1
            if str(lid).startswith("local:HASH:00000000:"):
                res["hash0_rows"] += 1
            elif len(candidates) < 50:
                candidates.append((addr, str(lid), str(name), str(typ)))


def lvar(func, lid):
    _, rows, _ = q(f"SELECT name, type FROM decomp_lvars WHERE func_addr = {func} AND local_id = '{lid}'")
    return rows[0] if rows else None


ids = res["idstab"]
if not candidates:
    ids["status"] = "n/a (no HASH-keyed locals in the sampled functions)"
else:
    checks = []
    func, lid, name, typ = candidates[0]
    ids["target1"] = f"0x{func:X} {lid} {name}"
    _, _, e = q(f"UPDATE decomp_lvars SET name = 'vt_a' WHERE func_addr = {func} AND local_id = '{lid}'")
    row = lvar(func, lid)
    checks.append(("rename", not e and row is not None and row[0] == "vt_a", e))
    _, _, e = q(f"UPDATE decomp_lvars SET name = 'vt_b' WHERE func_addr = {func} AND local_id = '{lid}'")
    row = lvar(func, lid)
    checks.append(("rename via pre-edit id", not e and row is not None and row[0] == "vt_b", e))
    other = [c for c in candidates if c[0] != func] or candidates[1:]
    if other:
        func, lid, name, typ = other[0]
        size = lid.split(":")[3]
        new_type = {"1": "byte", "2": "word", "4": "dword", "8": "qword"}.get(size)
        ids["target2"] = f"0x{func:X} {lid} {name} ({typ} -> {new_type})"
        if new_type:
            _, _, e = q(f"UPDATE decomp_lvars SET type = '{new_type}' WHERE func_addr = {func} AND local_id = '{lid}'")
            row = lvar(func, lid)
            checks.append(("same-width retype keeps id", not e and row is not None and row[1] == new_type, e))
            _, _, e = q(f"UPDATE decomp_lvars SET name = 'vt_c' WHERE func_addr = {func} AND local_id = '{lid}'")
            row = lvar(func, lid)
            checks.append(("rename after retype via original id", not e and row is not None and row[0] == "vt_c", e))
    ids["checks"] = [{"check": c, "ok": ok, "error": (er or "")[:300]} for c, ok, er in checks]
    ids["status"] = "pass" if all(ok for _, ok, _ in checks) else "FAIL"

res["seconds"] = round(time.time() - t_start)
json.dump(res, open(out_path, "w"), indent=1)
print(json.dumps({k: res[k] for k in ("funcs", "sampled", "missing", "dup_ids", "hash0_rows")}), ids.get("status"))
