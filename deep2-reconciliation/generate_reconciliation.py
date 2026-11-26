import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
manifest = json.loads((HERE / "upstream_source_manifest.json").read_text(encoding="utf-8"))

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest().upper()

upstream = [x for x in manifest["files"] if "AppData\\Local\\Temp\\Deep2-Upstream" in x["root"]]
local = [x for x in manifest["files"] if x["root"].replace("/", "\\").startswith("F:\\rawrxd\\src")]
local_by_path = {x["path"].replace("\\", "/"): x for x in local}

def local_candidates(path):
    p = path.replace("\\", "/")
    names = {p, p.lstrip("./")}
    base = Path(p).name
    names.add(base)
    return [x for x in local if x["path"].replace("\\", "/") in names or Path(x["path"]).name == base]

missing, partial, delta = [], [], []
for item in upstream:
    candidates = local_candidates(item["path"])
    if not candidates:
        status = "missing"
        target = None
    else:
        target = candidates[0]
        status = "matched_source_differs" if target.get("sha256", "").upper() != item["sha256"].upper() else "source_match"
    record = {
        "upstream": {"repository": item["root"], "path": item["path"], "sha256": item["sha256"], "bytes": item["bytes"]},
        "local_candidates": [{"path": x["path"], "sha256": x.get("sha256"), "bytes": x.get("bytes")} for x in candidates],
        "capability_hits": item.get("capability_hits", []),
        "status": status,
        "verification": "manifest/source comparison only; build, runtime, numerical parity, and hardware execution remain unverified",
    }
    delta.append(record)
    if status == "missing":
        missing.append(record)
    elif status == "matched_source_differs":
        partial.append(record)

def queue_entry(record, kind, priority):
    u = record["upstream"]
    return {
        "queue_id": f"{kind}:{u['repository'].split('\\\\')[-1]}:{u['path']}",
        "kind": kind,
        "priority": priority,
        "upstream": u,
        "capability_hits": record["capability_hits"],
        "required_work": [
            "trace transitive dependencies, headers, shaders/kernels, constants, and license notices",
            "adapt interfaces and integrate production call sites/build targets",
            "compile and run real-model numerical parity plus hardware benchmark",
            "record revision-bound evidence before certification or commit",
        ],
        "status": "queued",
    }

queue = [queue_entry(x, "missing", "P1") for x in missing] + [queue_entry(x, "partial", "P2") for x in partial]
queue.sort(key=lambda x: (x["priority"], x["upstream"]["repository"], x["upstream"]["path"]))

summary = {
    "generated_from": {
        "manifest": "deep2-reconciliation/upstream_source_manifest.json",
        "ollama_revision": manifest["ollama_revision"],
        "llama_cpp_revision": manifest["llama_cpp_revision"],
        "rawrxd_revision": manifest["rawrxd_revision"],
    },
    "counts": {"upstream_entries": len(upstream), "missing": len(missing), "partial_or_source_diff": len(partial), "source_matches": len(upstream) - len(missing) - len(partial)},
    "scope": "semantic/source reconciliation; no runtime gate is promoted by this artifact",
}
(HERE / "capability_delta.json").write_text(json.dumps({"summary": summary, "entries": delta}, indent=2) + "\n", encoding="utf-8")
(HERE / "missing_implementations.json").write_text(json.dumps({"summary": summary, "items": missing}, indent=2) + "\n", encoding="utf-8")
(HERE / "partial_implementations.json").write_text(json.dumps({"summary": summary, "items": partial}, indent=2) + "\n", encoding="utf-8")
(HERE / "implementation_queue.json").write_text(json.dumps({"summary": summary, "queue": queue}, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2))
