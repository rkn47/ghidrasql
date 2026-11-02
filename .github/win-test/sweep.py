#!/usr/bin/env python3
"""Exercise every ghidrasql table plus the documented write paths against a live server.

Usage: sweep.py PORT OUT_TSV
Writes one line per probe: <probe>\t<ok|ERR>\t<rows>\t<detail>
"""
import json
import sys
import urllib.request

port, out_path = sys.argv[1], sys.argv[2]
URL = f"http://127.0.0.1:{port}/query"


def q(sql, timeout=120):
    req = urllib.request.Request(URL, data=sql.encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode())
    except Exception as e:  # transport-level failure
        return {"success": False, "error": f"transport: {e}"}
    # The server answers {"success", "results": [{columns, rows, error, ...}]}.
    res = (body.get("results") or [{}])[0]
    return {"success": bool(body.get("success")) and bool(res.get("success", True)),
            "columns": res.get("columns") or [], "rows": res.get("rows") or [],
            "error": res.get("error") or body.get("error")}


results = []


def probe(label, sql, timeout=120):
    r = q(sql, timeout)
    ok = bool(r.get("success"))
    rows = r.get("rows") or []
    detail = "" if ok else str(r.get("error", r))[:220].replace("\t", " ").replace("\n", " ")
    results.append((label, "ok" if ok else "ERR", len(rows), detail))
    return r


def scalar(sql):
    r = q(sql)
    try:
        return r["rows"][0][0]
    except Exception:
        return None


# ---- table discovery
r = q("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [row[0] for row in (r.get("rows") or [])]
if not tables:
    r = q("SELECT name FROM pragma_module_list ORDER BY name")
    tables = [row[0] for row in (r.get("rows") or [])]
results.append(("discovered_tables", "ok" if tables else "ERR", len(tables), ""))

# Function used for scoped probes and writes: largest function.
fa = scalar("SELECT printf('0x%X', addr) FROM funcs ORDER BY size DESC LIMIT 1")
fname = scalar(f"SELECT name FROM funcs WHERE addr = {fa}")
results.append(("target_func", "ok" if fa else "ERR", 1, f"{fa} {fname}"))

# ---- read sweep: unscoped, then function-scoped where the table has func_addr
for t in tables:
    r = probe(f"read:{t}", f"SELECT * FROM {t} LIMIT 3", timeout=180)
    cols = r.get("columns") or []
    if fa and ("func_addr" in cols or not r.get("success")):
        probe(f"read_scoped:{t}", f"SELECT * FROM {t} WHERE func_addr = {fa} LIMIT 3", timeout=180)

# ---- decompiler
probe("pseudocode", f"SELECT text FROM pseudocode WHERE func_addr = {fa}", timeout=300)

# ---- writes (documented flows)
probe("w:rename_func", f"UPDATE funcs SET name = 'sweep_renamed' WHERE addr = {fa}")
probe("w:rename_func_check", f"SELECT name FROM funcs WHERE addr = {fa} AND name = 'sweep_renamed'")
probe("w:comment_insert", f"INSERT INTO comments (addr, comment, source) VALUES ({fa}, 'sweep eol', 'eol')")
probe("w:comment_update", f"UPDATE comments SET comment = 'sweep eol 2' WHERE addr = {fa} AND source = 'eol'")
probe("w:comment_check", f"SELECT comment FROM comments WHERE addr = {fa} AND comment = 'sweep eol 2'")
probe("w:comment_plate", f"INSERT INTO comments (addr, comment, source) VALUES ({fa}, 'sweep plate', 'plate')")
probe("w:comment_delete", f"DELETE FROM comments WHERE addr = {fa} AND source = 'eol'")
probe("w:tag_insert", "INSERT INTO function_tags (name, comment) VALUES ('sweep_tag', 'from sweep')")
probe("w:tag_map", f"INSERT INTO function_tag_mappings (func_addr, tag_name) VALUES ({fa}, 'sweep_tag')")
probe("w:tag_map_check", f"SELECT * FROM function_tag_mappings WHERE func_addr = {fa} AND tag_name = 'sweep_tag'")
probe("w:param_rename", f"UPDATE function_params SET param_name = 'sweep_p0' WHERE func_addr = {fa} AND ordinal = 0")
probe("w:prototype", f"UPDATE funcs SET prototype = 'int sweep_renamed(char * a, int b)' WHERE addr = {fa}")
lid = scalar(f"SELECT local_id FROM decomp_lvars WHERE func_addr = {fa} AND local_id NOT LIKE '%param%' LIMIT 1")
if lid:
    lid_sql = lid.replace("'", "''")
    probe("w:lvar_rename", f"UPDATE decomp_lvars SET name = 'sweep_local' WHERE func_addr = {fa} AND local_id = '{lid_sql}'", timeout=300)
    probe("w:lvar_retype", f"UPDATE decomp_lvars SET type = 'char *' WHERE func_addr = {fa} AND local_id = '{lid_sql}'", timeout=300)
else:
    results.append(("w:lvar_rename", "ERR", 0, "no local_id found"))
probe("w:type_insert", "INSERT INTO types (name, kind, size) VALUES ('SweepStruct', 'struct', 16)")
tid = scalar("SELECT type_id FROM types WHERE name = 'SweepStruct'")
if tid:
    probe("w:member_insert", f"INSERT INTO type_members (parent_type_id, member_name, member_type, size) VALUES ('{tid}', 'f0', 'int', 4)")
    probe("w:member_check", f"SELECT * FROM type_members WHERE parent_type_id = '{tid}'")
else:
    results.append(("w:member_insert", "ERR", 0, "no type_id for SweepStruct"))
probe("w:type_delete", "DELETE FROM types WHERE name = 'SweepStruct'")
la = scalar(f"SELECT printf('0x%X', addr + 4) FROM funcs WHERE addr = {fa}")
probe("w:label_insert", f"INSERT INTO names (addr, name) VALUES ({la}, 'sweep_label')")
probe("w:label_delete", f"DELETE FROM names WHERE addr = {la} AND name = 'sweep_label'")
r = probe("w:pseudocode_after", f"SELECT text FROM pseudocode WHERE func_addr = {fa}", timeout=300)
text = "\n".join(str(row[0]) for row in (r.get("rows") or []))
results.append(("w:pseudocode_reflects_rename", "ok" if "sweep_renamed" in text else "ERR", 0, ""))
results.append(("w:pseudocode_reflects_param", "ok" if "sweep_p0" in text or " a" in text else "ERR", 0, ""))

with open(out_path, "w") as f:
    for row in results:
        f.write("\t".join(str(x) for x in row) + "\n")

ok = sum(1 for r in results if r[1] == "ok")
print(f"{ok}/{len(results)} probes ok, {len(tables)} tables")
for r in results:
    if r[1] != "ok":
        print("  ERR", r[0], "-", r[3])
