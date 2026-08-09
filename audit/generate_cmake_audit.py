import csv
import json
import os
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(r"d:\rawrxd")
CMAKE_FILE = ROOT / "CMakeLists.txt"
OUT_DIR = ROOT / "audit"

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".asm", ".rc"}


def strip_comment(line: str) -> str:
    out = []
    in_quote = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == '"':
            in_quote = not in_quote
            out.append(ch)
        elif ch == '#' and not in_quote:
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def collect_statements(text: str):
    statements = []
    buf = []
    depth = 0
    start_line = 1
    if_depth = 0

    lines = text.splitlines()
    for idx, raw in enumerate(lines, start=1):
        line = strip_comment(raw).rstrip()
        if not line and depth == 0:
            continue

        if not buf:
            start_line = idx

        open_parens = line.count('(')
        close_parens = line.count(')')
        depth += open_parens - close_parens
        buf.append(line)

        if depth <= 0 and buf:
            stmt = "\n".join(buf).strip()
            head = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", stmt)
            cmd = head.group(1).lower() if head else ""

            conditional_before = if_depth > 0
            statements.append({
                "line": start_line,
                "text": stmt,
                "cmd": cmd,
                "conditional": conditional_before,
            })

            if cmd == "if":
                if_depth += 1
            elif cmd == "endif":
                if_depth = max(0, if_depth - 1)

            buf = []
            depth = 0

    return statements


def parse_args(stmt: str):
    m = re.search(r"\((.*)\)\s*$", stmt, flags=re.S)
    if not m:
        return []
    body = m.group(1)
    tokens = re.findall(r'"(?:\\.|[^"])*"|\$\{[^}]+\}|[^\s\n\r\t]+', body)
    cleaned = []
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        if t.startswith('"') and t.endswith('"'):
            t = t[1:-1]
        cleaned.append(t)
    return cleaned


def is_source_like(token: str):
    t = token.replace('\\', '/').strip()
    if not t or t.startswith('$<'):
        return False
    if t.startswith('${') and t.endswith('}'):
        return False
    ext = Path(t).suffix.lower()
    return ext in SOURCE_EXTS and '/' in t


def classify_target(name: str, exclude: bool):
    lname = name.lower()
    if re.search(r"bench|benchmark|tps", lname):
        return "benchmark"
    if re.search(r"test|validation|smoke|witness|verify|cert", lname):
        return "test"
    if name in {"RawrXD-Win32IDE", "RawrEngine", "RawrXD_Gold"}:
        return "shipped/product"
    if not exclude:
        return "supporting production"
    return "excluded/experimental"


def bool_str(v: bool):
    return "true" if v else "false"


def norm_rel(path: str):
    p = path.replace('\\', '/').strip()
    p = re.sub(r"^\./", "", p)
    return p


def main():
    text = CMAKE_FILE.read_text(encoding="utf-8", errors="ignore")
    statements = collect_statements(text)

    var_values = defaultdict(list)  # name -> list of dict(token, conditional, line)
    targets = {}  # target -> meta
    target_sources = defaultdict(list)  # target -> list of dict(path, conditional, line)

    add_exec_count = 0
    add_lib_count = 0

    for st in statements:
        cmd = st["cmd"]
        args = parse_args(st["text"])

        if cmd == "set" and len(args) >= 2:
            var = args[0]
            vals = args[1:]
            var_values[var] = []
            for v in vals:
                var_values[var].append({"token": v, "conditional": st["conditional"], "line": st["line"]})

        elif cmd == "list" and len(args) >= 3:
            op = args[0].upper()
            var = args[1]
            rest = args[2:]
            if op == "APPEND":
                for v in rest:
                    var_values[var].append({"token": v, "conditional": st["conditional"], "line": st["line"]})
            elif op == "REMOVE_ITEM":
                remove_set = set(rest)
                var_values[var] = [e for e in var_values[var] if e["token"] not in remove_set]
            elif op == "FILTER" and len(rest) >= 3:
                mode = rest[0].upper()
                kind = rest[1].upper()
                if mode == "EXCLUDE" and kind == "REGEX":
                    pattern = rest[2]
                    try:
                        rx = re.compile(pattern)
                        var_values[var] = [e for e in var_values[var] if not rx.search(e["token"].replace('\\\\', '/'))]
                    except re.error:
                        pass

        elif cmd in {"add_executable", "add_library"} and args:
            target = args[0]
            decl_tokens = args[1:]

            if cmd == "add_executable":
                add_exec_count += 1
                ttype = "executable"
            else:
                add_lib_count += 1
                ttype = "library"

            exclude = any(t == "EXCLUDE_FROM_ALL" for t in decl_tokens)

            meta = targets.get(target, {"name": target, "type": ttype, "exclude_from_all": False, "lines": []})
            meta["exclude_from_all"] = meta["exclude_from_all"] or exclude
            meta["lines"].append(st["line"])
            targets[target] = meta

            skip = {
                "WIN32", "MACOSX_BUNDLE", "EXCLUDE_FROM_ALL", "STATIC", "SHARED", "MODULE", "OBJECT", "INTERFACE", "IMPORTED", "ALIAS"
            }
            source_tokens = [t for t in decl_tokens if t not in skip]

            for tok in source_tokens:
                if tok.startswith("${") and tok.endswith("}"):
                    var = tok[2:-1]
                    for e in var_values.get(var, []):
                        t = e["token"]
                        if is_source_like(t):
                            target_sources[target].append({
                                "path": norm_rel(t),
                                "conditional": st["conditional"] or e["conditional"],
                                "line": st["line"],
                            })
                else:
                    if is_source_like(tok):
                        target_sources[target].append({
                            "path": norm_rel(tok),
                            "conditional": st["conditional"],
                            "line": st["line"],
                        })

        elif cmd == "target_sources" and len(args) >= 2:
            target = args[0]
            mode_tokens = {"PRIVATE", "PUBLIC", "INTERFACE"}
            for tok in args[1:]:
                if tok in mode_tokens:
                    continue
                if tok.startswith("${") and tok.endswith("}"):
                    var = tok[2:-1]
                    for e in var_values.get(var, []):
                        t = e["token"]
                        if is_source_like(t):
                            target_sources[target].append({
                                "path": norm_rel(t),
                                "conditional": st["conditional"] or e["conditional"],
                                "line": st["line"],
                            })
                else:
                    if is_source_like(tok):
                        target_sources[target].append({
                            "path": norm_rel(tok),
                            "conditional": st["conditional"],
                            "line": st["line"],
                        })

        elif cmd == "set_target_properties" and args:
            target = args[0]
            if "EXCLUDE_FROM_ALL" in args and "TRUE" in args:
                meta = targets.get(target, {"name": target, "type": "unknown", "exclude_from_all": False, "lines": []})
                meta["exclude_from_all"] = True
                meta["lines"].append(st["line"])
                targets[target] = meta

    # Build source -> targets index
    source_to_targets = defaultdict(list)
    matrix_rows = []

    for target, srcs in target_sources.items():
        tmeta = targets.get(target, {"type": "unknown", "exclude_from_all": False, "lines": []})
        family = classify_target(target, tmeta["exclude_from_all"])
        production = family in {"shipped/product", "supporting production"}
        is_test = family == "test"
        is_bench = family == "benchmark"
        is_win32ide = target == "RawrXD-Win32IDE"

        for rec in srcs:
            source = rec["path"]
            source_to_targets[source].append(target)
            row = {
                "source": source,
                "target": target,
                "target_type": tmeta["type"],
                "exclude_from_all": bool_str(tmeta["exclude_from_all"]),
                "target_family": family,
                "production": bool_str(production),
                "win32ide": bool_str(is_win32ide),
                "deep2": bool_str("/deep2/" in "/" + source),
                "test": bool_str(is_test),
                "benchmark": bool_str(is_bench),
                "conditional": bool_str(rec["conditional"]),
                "duplicate_family": "",
                "stub_risk": "",
                "line": str(rec["line"]),
            }
            matrix_rows.append(row)

    # Duplicate families by basename
    by_base = defaultdict(set)
    for r in matrix_rows:
        by_base[Path(r["source"]).name.lower()].add(r["source"])

    duplicate_bases = {b for b, paths in by_base.items() if len(paths) > 1}

    stub_rx = re.compile(r"(stub|stubs|shim|shims|fallback|mock|fake|compat|missing_impl|link_stub)", re.I)

    for r in matrix_rows:
        base = Path(r["source"]).name.lower()
        r["duplicate_family"] = base if base in duplicate_bases else ""
        r["stub_risk"] = bool_str(bool(stub_rx.search(base)))

    # De-dup identical source-target rows
    uniq = {}
    for r in matrix_rows:
        k = (r["source"], r["target"])
        if k not in uniq:
            uniq[k] = r
    matrix_rows = sorted(uniq.values(), key=lambda x: (x["source"], x["target"]))

    # Filesystem inventory under src/
    fs_sources = []
    src_root = ROOT / "src"
    for base, _, files in os.walk(src_root):
        for name in files:
            p = Path(base) / name
            if p.suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".asm", ".rc"}:
                rel = p.relative_to(ROOT).as_posix()
                fs_sources.append(rel)

    referenced_sources = {r["source"] for r in matrix_rows}
    orphan_sources = sorted([s for s in fs_sources if s not in referenced_sources])

    # deep2 audit
    deep2_dir = ROOT / "src" / "deep2"
    deep2_rows = []
    deep2_cpp = sorted([p for p in deep2_dir.rglob("*.cpp") if p.is_file()])

    for p in deep2_cpp:
        rel = p.relative_to(ROOT).as_posix()
        targets_for = sorted(set(source_to_targets.get(rel, [])))
        in_cmake = bool(targets_for)
        in_win32ide = "RawrXD-Win32IDE" in targets_for
        deep2_rows.append({
            "source": rel,
            "referenced_in_root_cmake": bool_str(in_cmake),
            "targets": ";".join(targets_for),
            "win32ide": bool_str(in_win32ide),
            "status": "built" if in_cmake else "cmake-orphan",
        })

    # duplicate family report
    dup_rows = []
    for base in sorted(duplicate_bases):
        paths = sorted(by_base[base])
        path_targets = []
        for p in paths:
            t = sorted(set(source_to_targets.get(p, [])))
            path_targets.append(f"{p}=>{';'.join(t)}")
        dup_rows.append({
            "family": base,
            "path_count": str(len(paths)),
            "paths": " | ".join(paths),
            "targets": " | ".join(path_targets),
        })

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Write CSV matrix
    matrix_csv = OUT_DIR / "cmake_source_target_matrix.csv"
    fieldnames = [
        "source", "target", "target_type", "exclude_from_all", "target_family", "production",
        "win32ide", "deep2", "test", "benchmark", "conditional", "duplicate_family", "stub_risk", "line"
    ]
    with matrix_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(matrix_rows)

    # Write JSON matrix
    matrix_json = OUT_DIR / "cmake_source_target_matrix.json"
    matrix_json.write_text(json.dumps(matrix_rows, indent=2), encoding="utf-8")

    # Write deep2 audit
    deep2_csv = OUT_DIR / "deep2_audit.csv"
    with deep2_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["source", "referenced_in_root_cmake", "targets", "win32ide", "status"])
        w.writeheader()
        w.writerows(deep2_rows)

    # Write duplicate families
    dup_csv = OUT_DIR / "duplicate_implementation_families.csv"
    with dup_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["family", "path_count", "paths", "targets"])
        w.writeheader()
        w.writerows(dup_rows)

    # Write orphans
    orphan_csv = OUT_DIR / "orphan_sources.csv"
    with orphan_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source"])
        for s in orphan_sources:
            w.writerow([s])

    # Target summary
    target_rows = []
    for t, meta in sorted(targets.items(), key=lambda kv: kv[0].lower()):
        fam = classify_target(t, meta["exclude_from_all"])
        target_rows.append({
            "target": t,
            "target_type": meta["type"],
            "exclude_from_all": bool_str(meta["exclude_from_all"]),
            "target_family": fam,
            "production": bool_str(fam in {"shipped/product", "supporting production"}),
            "line": ",".join(str(x) for x in sorted(set(meta["lines"])))
        })

    target_csv = OUT_DIR / "target_inventory.csv"
    with target_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["target", "target_type", "exclude_from_all", "target_family", "production", "line"])
        w.writeheader()
        w.writerows(target_rows)

    total_sources_matrix = len({r["source"] for r in matrix_rows})
    deep2_total = len(deep2_rows)
    deep2_built = sum(1 for r in deep2_rows if r["referenced_in_root_cmake"] == "true")
    deep2_orphans = deep2_total - deep2_built
    stub_risk_count = sum(1 for r in matrix_rows if r["stub_risk"] == "true")

    summary = []
    summary.append("# RawrXD CMake Source-to-Target Audit")
    summary.append("")
    summary.append("Scope: static parse of root CMake graph in src-level references from d:/rawrxd/CMakeLists.txt.")
    summary.append("")
    summary.append("## Outputs")
    summary.append("- cmake_source_target_matrix.csv")
    summary.append("- cmake_source_target_matrix.json")
    summary.append("- target_inventory.csv")
    summary.append("- deep2_audit.csv")
    summary.append("- duplicate_implementation_families.csv")
    summary.append("- orphan_sources.csv")
    summary.append("")
    summary.append("## High-Level Counts")
    summary.append(f"- add_executable declarations: {add_exec_count}")
    summary.append(f"- add_library declarations: {add_lib_count}")
    summary.append(f"- targets discovered: {len(targets)}")
    summary.append(f"- source-target edges: {len(matrix_rows)}")
    summary.append(f"- unique referenced sources: {total_sources_matrix}")
    summary.append(f"- duplicate implementation families: {len(dup_rows)}")
    summary.append(f"- stub-risk edges (name-based): {stub_risk_count}")
    summary.append(f"- filesystem source files under src/: {len(fs_sources)}")
    summary.append(f"- source files present in tree but unreferenced in root CMake: {len(orphan_sources)}")
    summary.append("")
    summary.append("## Deep2 Slice")
    summary.append(f"- total deep2 .cpp files scanned: {deep2_total}")
    summary.append(f"- referenced by root CMake: {deep2_built}")
    summary.append(f"- cmake-orphan deep2 files: {deep2_orphans}")
    summary.append("")
    summary.append("## Notes")
    summary.append("- This is root-CMake authoritative only; nested historical/reconstructed trees are intentionally out of scope.")
    summary.append("- Conditional includes are flagged via the 'conditional' column when sources are gathered from inside if(...) scopes.")
    summary.append("- Duplicate/stub flags are heuristic and should be reviewed before cleanup decisions.")

    (OUT_DIR / "AUDIT_SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
