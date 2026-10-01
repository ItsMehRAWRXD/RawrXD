"""BATCH_1b - placeholder forms the "// STUB:" pattern does not match.

Discovered because RawrXD-AutoFixCLI fails to link on a source whose content is
"// Auto-generated stub". The reconciliation inventory must cover every
placeholder form, not just the one the task text named.
"""
import os
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import build_manifest as bm  # noqa: E402

MARKERS = [
    ("// STUB:", re.compile(r"^\s*//\s*STUB\s*:")),
    ("// Auto-generated stub", re.compile(r"^\s*//\s*Auto-generated stub", re.I)),
    ("// stub", re.compile(r"^\s*//\s*stub\s*$", re.I)),
    ("// Stub:", re.compile(r"^\s*//\s*stub\s*[:.]", re.I)),
    ("// TODO", re.compile(r"^\s*//\s*TODO", re.I)),
    ("// placeholder", re.compile(r"^\s*//\s*placeholder", re.I)),
    ("// not implemented", re.compile(r"^\s*//\s*not implemented", re.I)),
    ("// intentionally", re.compile(r"^\s*//\s*intentionally (empty|left)", re.I)),
    ("[STUB] marker", re.compile(r"\bSTUB\b.*--\s*stub", re.I)),
    ("baseline stub hdr", re.compile(r"RAWRXD_BUILD_AUTHORITY_BASELINE_001")),
    ("stub in header guard", re.compile(r"—\s*stub\s*\*/", re.I)),
]

CODEY = re.compile(r"^\s*(#\s*include|#\s*pragma|#\s*define|\{|}|namespace|"
                   r"(static|inline|extern|template|class|struct|enum|typedef|using|"
                   r"constexpr|const|int|void|bool|float|double|size_t|auto)\b)")


def main():
    hits = {}
    comment_only = []
    for dirpath, dirnames, filenames in os.walk(bm.longpath(bm.ROOT)):
        dirnames[:] = [d for d in dirnames if d not in bm.SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() not in bm.SOURCE_EXT:
                continue
            text = bm.read_text(p)
            if text is None:
                continue
            rel = bm.rel_to_root(p)
            lines = [l for l in text.split("\n") if l.strip()]
            for name, rx in MARKERS:
                if rx.search(lines[0] if lines else ""):
                    hits.setdefault(name, []).append(rel)
            # A translation unit with no code at all is a placeholder whatever
            # its first line says.
            if lines and not any(CODEY.match(l) for l in lines):
                comment_only.append(rel)

    out = bm.ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001" / "baseline"
    out.mkdir(parents=True, exist_ok=True)

    print("=== PLACEHOLDER MARKER COUNTS ===")
    for name, _ in MARKERS:
        print(f"{name}={len(hits.get(name, []))}")
    print(f"COMMENT_ONLY_TRANSLATION_UNITS={len(comment_only)}")

    named_stub = {r["path"] for r in
                  __import__("json").loads("[]")} or set()
    import json
    with (bm.ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001" /
          "stub_manifest.csv").open(encoding="utf-8") as fh:
        import csv as _csv
        known = {r["PATH"] for r in _csv.DictReader(fh)}

    extra = sorted(set(comment_only) - known)
    print(f"PLACEHOLDERS_MISSED_BY_STUB_PATTERN={len(extra)}")
    for e in extra:
        print("  MISSED:", e)

    with (out / "placeholder_forms.json").open("w", encoding="utf-8") as fh:
        json.dump({"marker_counts": {k: len(v) for k, v in hits.items()},
                   "comment_only": comment_only,
                   "missed_by_stub_pattern": extra}, fh, indent=2)


if __name__ == "__main__":
    main()
