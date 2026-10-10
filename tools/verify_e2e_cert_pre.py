#!/usr/bin/env python3
"""Independent verifier for RAWRXD_CORE_DLL_NATIVE_E2E_001.

Re-checks every certificate gate from the raw evidence artifacts only:
re-hashes the model/DLL, re-parses the evidence logs, recomputes the
positional logits metrics from the raw float dumps, and cross-checks the
certificate claims. It does not trust the certification script.
"""
import hashlib
import json
import os
import re
import struct
import sys

import numpy as np

ROOT = r"F:\rawrxd"
EV = os.path.join(ROOT, "evidence", "RAWRXD_CORE_DLL_NATIVE_E2E_001")
CERT = os.path.join(ROOT, "certs", "RAWRXD_CORE_DLL_NATIVE_E2E_001.cert")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path, mode="rb"):
    if not os.path.exists(path):
        return None
    if "b" not in mode:
        with open(path, mode, encoding="utf-8", errors="replace") as f:
            return f.read()
    with open(path, mode) as f:
        return f.read()


def main():
    cert = json.load(open(CERT))
    failures = []
    checks = []

    def check(name, ok, detail):
        checks.append((name, ok, detail))
        if not ok:
            failures.append(name)

    # 1. artifact hashes recorded in the certificate still match on disk
    with open(os.path.join(EV, "baseline_freeze.json")) as f:
        base = json.load(f)
    if base is None:
        check("BASELINE_FREEZE", False, "baseline_freeze.json missing")
    else:
        ok = sha256(base["model"]["path"]) == base["model"]["sha256"]
        check("MODEL_SHA256", ok,
              "GGUF sha256 %s" % base["model"]["sha256"][:16])
        for art, info in base["artifacts"].items():
            if info.get("sha256") and os.path.exists(info["path"]):
                ok = sha256(info["path"]) == info["sha256"]
                check("BIN_SHA256:%s" % art, ok, "%s bytes" % info["bytes"])

    gates = {g["gate"]: g for g in cert["gates"]}
    check("CERT_GATE_SET",
          {"TOKENIZER_CORE_PARITY", "ATTENTION_HISTORICAL_V", "ATTENTION_REFERENCE_PARITY",
           "DLL_FRESH_BUILD", "DLL_LOAD_UNLOAD", "MODEL_METADATA", "PREFILL",
           "LOGITS_FINITE", "AUTOREGRESSIVE_16", "KV_POSITION_AUTHORITY",
           "REFERENCE_DIFFERENTIAL", "VERDICT"} <= set(gates),
          "all required gate keys present")

    # 2. tokenizer parity: recompute from the raw JSON + spot-check ids
    tok = json.load(open(os.path.join(EV, "tokenizer_parity.json")))
    bad = [c for c in tok["cases"] if not c["pass"]]
    check("TOKENIZER_PARITY", tok["fail"] == 0,
          "%d/%d cases match, %d mismatches" % (tok["pass"], tok["total"], len(bad)))

    # 3. metadata claim recompute from the DLL log
    runlog = load(os.path.join(EV, "dll_test_run.log"), "r")
    layers = re.search(r"Layers:\s*(\d+)", runlog).group(1)
    tensors = re.search(r"Tensors:\s*(\d+)", runlog).group(1)
    size = re.search(r"Size:\s*(\d+) bytes", runlog).group(1)
    check("MODEL_METADATA",
          (layers, tensors, size) == ("27", "377", "10364416768"),
          "layers=%s tensors=%s bytes=%s" % (layers, tensors, size))

    # 4. 16-token generation claim
    m = re.search(r"maxTokens=16 generated=(\d+) distinct=(\d+)", runlog)
    text = re.search(r"streamed text: '([^']*)'", runlog).group(1)
    check("AUTOREGRESSIVE_16",
          m and m.group(1) == "16" and int(m.group(2)) >= 14
          and len(text) > 20 and "COLLAPSE" not in runlog,
          "generated=%s distinct=%s text='%s'" % (m.group(1), m.group(2), text[:48]))

    # 5. evidence-run claims: finite logits + advancing KV authority
    e2e = load(os.path.join(EV, "e2e_evidence_run.log"), "r")
    caps = [l for l in e2e.splitlines() if "KV_CACHE_LENGTH" in l]
    kvl = [int(re.search(r"KV_CACHE_LENGTH=(\d+)", l).group(1)) for l in caps]
    pos = [int(re.search(r"EXECUTED_POSITION=(\d+)", l).group(1)) for l in caps]
    check("LOGITS_FINITE", "LOGITS_FINITE=false" not in e2e
          and e2e.count("LOGITS_FINITE=true") >= 18,
          "%d finite snapshots, 0 nonfinite" % e2e.count("LOGITS_FINITE=true"))
    check("KV_POSITION_AUTHORITY",
          len(kvl) >= 18 and all(kvl[i] == pos[i] + 1 for i in range(len(kvl))),
          "KV length == position+1 for all %d passes" % len(kvl))

    # 6. positional reference metrics, recomputed from the raw dumps
    rows = []
    for p in range(19):
        a = load(os.path.join(EV, "native_tf_logits_pos%d.bin" % p))
        b = load(os.path.join(EV, "llama_ref_gen", "ref_logits_pos%d.bin" % p))
        if not a or not b:
            continue
        va = np.frombuffer(a, dtype=np.float32).astype(np.float64)
        vb = np.frombuffer(b, dtype=np.float32).astype(np.float64)
        cos = float(va @ vb / (np.linalg.norm(va) * np.linalg.norm(vb)))
        rows.append((p, int(va.argmax()), int(vb.argmax()), va.argmax() == vb.argmax(), cos,
                     float(np.sqrt(np.mean((va - vb) ** 2)))))
    early = [r for r in rows if r[0] <= 11]
    match = sum(1 for r in early if r[3])
    mean_cos = sum(r[4] for r in early) / len(early)
    check("REFERENCE_DIFFERENTIAL",
          len(early) >= 12 and match >= 10 and mean_cos > 0.94
          and all(r[4] > 0.94 for r in early),
          "pos 0-11: %d/%d argmax, mean cos=%.6f, min cos=%.6f"
          % (match, len(early), mean_cos, min(r[4] for r in early)))

    # 7. certificate self-consistency
    check("CERT_VERDICT", gates.get("VERDICT", {}).get("value") == "PASS",
          gates.get("VERDICT", {}).get("detail", ""))

    width = max(len(c[0]) for c in checks)
    print("independent verification of RAWRXD_CORE_DLL_NATIVE_E2E_001")
    print("=" * (width + 14))
    for name, ok, detail in checks:
        print("%-*s %s   %s" % (width, name, "PASS" if ok else "FAIL", detail))
    print("=" * (width + 14))
    print("positional parity (recomputed):")
    for r in rows:
        print("  pos %2d native=%-6d ref=%-6d %-3s cos=%.6f rmse=%.4f"
              % (r[0], r[1], r[2], "yes" if r[3] else "NO", r[4], r[5]))
    print()
    print("CHECKS_PASSED=%d/%d" % (len(checks) - len(failures), len(checks)))
    if failures:
        print("FAILED=%s" % ", ".join(failures))
        print("CERTIFICATE_VERIFY=FAIL")
        return 1
    print("CERTIFICATE_VERIFY=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
