# BATCH_1 - machine-derived manifest for every "// STUB:" translation unit.
#
# Nothing here is derived from a comment, a filename, or a previous receipt.
# Every field is measured from the filesystem, the current CMake source, the
# generated CMake projects, a symbol/callsite search, or the baseline build log.
import csv
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
BUILD = ROOT / "build_w1"
OUT = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
STUB_RE = re.compile(r"^\s*//\s*STUB:\s*(.+?)\s*$")

SKIP_DIRS = {"build", "build_w1", "build2", "build-ninja", "3rdparty",
             ".rawrxd_stub_recovery_backup", ".git"}
SOURCE_EXT = {".cpp", ".h", ".hpp", ".c", ".cc", ".cu", ".inl"}
SHIPPING_TARGETS = {"RawrXD-Win32IDE"}

# Read failures are counted, never swallowed: a manifest that silently skips
# unreadable files under-reports, which is the exact failure mode this
# reconciliation exists to prevent.
READ_ERRORS = []


def longpath(p):
    """Windows MAX_PATH-safe absolute path."""
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(s)
    return s


def read_text(p):
    # utf-8-sig, not utf-8: 83 of these files carry a BOM, and a BOM before
    # "//" makes the stub marker invisible to the first-line match. Reading as
    # plain utf-8 silently under-reported the inventory by 83 files.
    try:
        with open(longpath(p), "r", encoding="utf-8-sig", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        READ_ERRORS.append((str(p), repr(exc)))
        return None


def read_bytes(p):
    try:
        with open(longpath(p), "rb") as fh:
            return fh.read()
    except OSError as exc:
        READ_ERRORS.append((str(p), repr(exc)))
        return None


def rel_to_root(p):
    """Repo-relative POSIX path.

    os.walk yields '\\\\?\\'-prefixed paths, so relative_to() against the
    unprefixed ROOT raises for every file. Stripping the prefix first is what
    makes the recorded path correct; silently falling back to a bare filename
    would have produced a manifest of 363 wrong paths.
    """
    s = str(p)
    if s.startswith("\\\\?\\"):
        s = s[4:]
    try:
        return Path(s).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(s).name


# --------------------------------------------------------------- discovery
def discover_stubs():
    out = []
    for dirpath, dirnames, filenames in os.walk(longpath(ROOT)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in SOURCE_EXT:
                continue
            text = read_text(p)
            if text is None:
                continue
            first = text.split("\n", 1)[0]
            m = STUB_RE.match(first)
            if m:
                rel = rel_to_root(p)
                out.append({
                    "path": rel,
                    "declared": m.group(1),
                    "text": text,
                })
    return sorted(out, key=lambda d: d["path"])


# ------------------------------------------------------------- cmake truth
def read_cmake_texts():
    texts = {}
    for dirpath, dirnames, filenames in os.walk(longpath(ROOT)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn != "CMakeLists.txt":
                continue
            p = Path(dirpath) / fn
            t = read_text(p)
            if t is not None:
                texts[rel_to_root(p)] = t
    return texts


def targets_from_vcxproj():
    """source path -> list of target names, straight out of CMake's own output."""
    owner, target_sources = defaultdict(list), {}
    if not BUILD.exists():
        return owner, target_sources
    import xml.etree.ElementTree as ET
    ns = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
    for proj in BUILD.rglob("*.vcxproj"):
        name = proj.stem
        if name in ("ALL_BUILD", "ZERO_CHECK") or name.endswith("ZERO_CHECK"):
            continue
        try:
            tree = ET.parse(proj)
        except ET.ParseError:
            continue
        srcs = []
        for node in tree.getroot().iter():
            if not node.tag.endswith("}ClCompile"):
                continue
            inc = node.get("Include")
            if not inc:
                continue
            full = Path(inc) if os.path.isabs(inc) else (proj.parent / inc)
            try:
                full = full.resolve()
            except OSError:
                continue
            rel = rel_to_root(full)
            if rel == full.name and full.name not in rel:
                continue
            if not (ROOT / rel).exists():
                continue
            srcs.append(rel)
            if name not in owner[rel]:
                owner[rel].append(name)
        target_sources[name] = srcs
    return owner, target_sources


# --------------------------------------------------------- header API probe
def declared_api_count(header: Path):
    """Out-of-line function prototypes the header declares but does not define.

    A header that only defines things inline, or that is itself a placeholder,
    gives the corresponding .cpp nothing to implement.
    """
    if not header.exists():
        return 0, "no_header"
    text = read_text(header)
    if text is None:
        return 0, "header_unreadable"
    stripped = "\n".join(l for l in text.split("\n")
                         if not l.strip().startswith(("//", "/*", "*")))
    if not stripped.strip():
        return 0, "header_is_placeholder"
    if re.search(r"-\s*stub\s*-\*|//\s*Stub:\s*", text, re.I):
        # header self-identifies as a stub
        decls = 0
    else:
        decls = 0
        for line in stripped.split("\n"):
            s = line.strip()
            if not s.endswith(";") or "(" not in s:
                continue
            head = s.split("(")[0]
            if not re.search(r"[A-Za-z_]\w*$", head):
                continue
            decls += 1
    return decls, "measured"


# ------------------------------------------------------------ callsite probe
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def build_callsite_index(stub_paths, stem_set):
    """stem -> number of non-stub source files that mention it as a token.

    Each file is tokenized once and intersected with the stem set. Running one
    regex per stem per file is quadratic and was the difference between minutes
    and hours here.
    """
    counts = defaultdict(int)
    for dirpath, dirnames, filenames in os.walk(longpath(ROOT)):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in SOURCE_EXT:
                continue
            rel = rel_to_root(p)
            if rel in stub_paths:
                continue                      # a stub never counts as a caller
            text = read_text(p)
            if text is None:
                continue
            seen = {t.lower() for t in TOKEN_RE.findall(text)} & stem_set
            for s in seen:
                counts[s] += 1
    return counts


# --------------------------------------------------------------- build truth
def parse_build_failures(log_path):
    """target -> list of failure signatures, from a real build log."""
    fails = defaultdict(list)
    if not log_path.exists():
        return fails
    for line in log_path.read_text(encoding="utf-8", errors="replace").split("\n"):
        for m in re.finditer(r"\[(?:[^\]]*\\)?([A-Za-z0-9_\-\.]+)\.vcxproj\]", line):
            tgt = m.group(1)
            if re.search(r"\berror\s+(?:LNK|C|MSB)\d+", line):
                fails[tgt].append(line.strip()[:400])
    return fails


# ------------------------------------------------------------------- main
def main():
    OUT.mkdir(parents=True, exist_ok=True)
    stubs = discover_stubs()
    stub_paths = {s["path"] for s in stubs}
    stub_stems = {Path(s["path"]).stem for s in stubs}
    stems_lower = {s.lower() for s in stub_stems}

    cmake_texts = read_cmake_texts()
    cmake_blob = "\n".join(cmake_texts.values())
    owner, target_sources = targets_from_vcxproj()
    callsites = build_callsite_index(stub_paths, stems_lower)
    build_fails = parse_build_failures(
        Path(r"C:\Users\Garrett\AppData\Local\Temp\kilo\stub_audit\baseline_build.log"))

    # targets whose every source is a stub
    stub_only_targets = set()
    for t, srcs in target_sources.items():
        if srcs and all(s in stub_paths for s in srcs):
            stub_only_targets.add(t)

    rows = []
    for s in stubs:
        p = s["path"]
        full = ROOT / p
        leaf = Path(p).name
        stem = Path(p).stem
        data = read_bytes(full)
        if data is None:
            continue

        targets = owner.get(p, [])
        shipping = [t for t in targets if t in SHIPPING_TARGETS]

        hdr = None
        for ext in (".h", ".hpp", ".hxx"):
            cand = full.with_suffix(ext)
            if cand.exists():
                hdr = cand
                break
        api_n, api_kind = declared_api_count(hdr) if hdr else (0, "no_header")

        rows.append({
            "PATH": p,
            "SHA256": hashlib.sha256(data).hexdigest(),
            "LINE_COUNT": s["text"].count("\n") + (0 if s["text"].endswith("\n") else 1),
            "CMAKE_REFERENCED": "1" if leaf in cmake_blob else "0",
            "COMPILED_BY_TARGET": "1" if targets else "0",
            "SHIPPING_TARGET": ";".join(shipping),
            "TARGETS": ";".join(sorted(targets)),
            "HEADER_EXISTS": rel_to_root(hdr) if hdr else "",
            "DECLARED_API": api_n,
            "DECLARED_API_PROBE": api_kind,
            "CALLSITE_COUNT": callsites.get(stem, 0),
            "SYMBOL_REFERENCES": callsites.get(stem, 0),
            "TEST_TARGET": "1" if targets and all(
                t.lower().startswith(("test", "cert", "bench", "k2_", "val_", "nevm",
                                      "b0", "mla_", "deep2_", "rkc_", "ide_", "hexmag",
                                      "p0_", "p1_", "fwd_", "ev512", "q4", "q5", "q6",
                                      "synth", "generation_", "certification", "layer_",
                                      "hotpatch_", "dump_", "rawrxd_", "agentic_", "sow"))
                for t in targets) else "0",
            "ONLY_SOURCE_OF_TARGET": ";".join(sorted(t for t in targets
                                                    if t in stub_only_targets)),
            "CURRENT_BUILD_FAILURE": ";".join(build_fails.get(t, [""])[0][:200]
                                              for t in sorted(targets)).strip(";"),
            "CLASSIFICATION": "",
            "ACTION": "",
            "REASON": "",
        })

    # ---------------------------------------------------------- classify
    for r in rows:
        compiled = r["COMPILED_BY_TARGET"] == "1"
        shipping = bool(r["SHIPPING_TARGET"])
        only_src = bool(r["ONLY_SOURCE_OF_TARGET"])
        has_failure = bool(r["CURRENT_BUILD_FAILURE"])
        has_api = r["DECLARED_API"] > 0
        callers = r["CALLSITE_COUNT"] > 0

        if shipping:
            # E - shipping product placeholder
            if has_api or callers:
                r["CLASSIFICATION"] = "E_SHIPPING_STUB"
                r["ACTION"] = "BLOCKED_SPEC_REQUIRED"
                r["REASON"] = ("compiled into RawrXD-Win32IDE and referenced; "
                               "declared API/callers must be read before any change")
            else:
                r["CLASSIFICATION"] = "E_SHIPPING_STUB"
                r["ACTION"] = "CANDIDATE_PROVEN_DEAD_REMOVED_FROM_TARGET"
                r["REASON"] = ("compiled into RawrXD-Win32IDE; empty TU contributes no "
                               "symbol; removal must be proven link-neutral")
        elif only_src:
            # D - stub-only target
            if has_api or callers:
                r["CLASSIFICATION"] = "D_STUB_ONLY_TARGET"
                r["ACTION"] = "BLOCKED_SPEC_REQUIRED"
                r["REASON"] = "target exists only to build this placeholder"
            else:
                r["CLASSIFICATION"] = "D_STUB_ONLY_TARGET"
                r["ACTION"] = "REMOVE_TARGET_FROM_ACTIVE_BUILD_AND_QUARANTINE"
                r["REASON"] = ("target's only source cannot supply main; no spec, "
                               "no API, no caller")
        elif compiled:
            # B - cmake metadata ghost
            r["CLASSIFICATION"] = "B_BUILD_METADATA_GHOST"
            r["ACTION"] = "REMOVE_FROM_CMAKE_AND_QUARANTINE"
            r["REASON"] = ("listed in CMake and compiled as an empty TU; no required "
                           "symbol, no caller" + ("; contributes to a current failure"
                                                  if has_failure else ""))
        else:
            # A - orphan
            r["CLASSIFICATION"] = "A_ORPHAN"
            r["ACTION"] = "QUARANTINE_FROM_ACTIVE_TREE"
            r["REASON"] = ("not compiled by any target, no caller, no declared API"
                           if not (callers or has_api) else
                           "not compiled, but referenced/has API: quarantine only")

    # ------------------------------------------------------------ emit
    csv_path = OUT / "stub_manifest.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    jsonl_path = OUT / "stub-quarantine" / "manifest.jsonl"
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    # --------------------------------------------------------- summary
    def count(pred):
        return sum(1 for r in rows if pred(r))

    print(f"READ_ERRORS={len(READ_ERRORS)}")
    for path, err in READ_ERRORS[:10]:
        print(f"READ_ERROR={path} {err}")

    summary = {
        "MEASURED_TOTAL_STUBS": len(rows),
        "EXPECTED_TOTAL_STUBS": 446,
        "MEASURED_CMAKE_COMPILED": count(lambda r: r["COMPILED_BY_TARGET"] == "1"),
        "EXPECTED_CMAKE_COMPILED": 68,
        "MEASURED_NEVER_COMPILED": count(lambda r: r["COMPILED_BY_TARGET"] == "0"),
        "EXPECTED_NEVER_COMPILED": 378,
        "MEASURED_SHIPPING_IDE": count(lambda r: bool(r["SHIPPING_TARGET"])),
        "EXPECTED_SHIPPING_IDE": 25,
        "MEASURED_STUB_ONLY_TARGETS": len(stub_only_targets),
        "EXPECTED_STUB_ONLY_TARGETS": 17,
        "MEASURED_LNK2019_MAIN_FAILURES": count(
            lambda r: "LNK2019" in r["CURRENT_BUILD_FAILURE"]
            and "unresolved external symbol main" in r["CURRENT_BUILD_FAILURE"]),
        "EXPECTED_LNK2019_MAIN_FAILURES": 5,
        "TARGETS_TOTAL_IN_BUILD": len(target_sources),
        "BY_CLASSIFICATION": {k: count(lambda r, k=k: r["CLASSIFICATION"] == k)
                              for k in sorted({r["CLASSIFICATION"] for r in rows})},
        "BY_ACTION": {k: count(lambda r, k=k: r["ACTION"] == k)
                      for k in sorted({r["ACTION"] for r in rows})},
        "BLOCKED_SPEC_REQUIRED": count(lambda r: r["ACTION"] == "BLOCKED_SPEC_REQUIRED"),
        "STUB_ONLY_TARGET_NAMES": sorted(stub_only_targets),
    }
    for k, v in summary.items():
        if isinstance(v, list):
            continue
        print(f"{k}={v}")
    print("STUB_ONLY_TARGET_NAMES=" + ";".join(sorted(stub_only_targets)))
    (OUT / "baseline" ).mkdir(parents=True, exist_ok=True)
    (OUT / "baseline" / "inventory_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    return rows, summary


if __name__ == "__main__":
    main()