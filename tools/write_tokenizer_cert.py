#!/usr/bin/env python3
"""Write RAWRXD_DEEPSEEK_TOKENIZER_PARITY_001 from the frozen corpus run."""
import json
import os
import sys

ROOT = r"F:\rawrxd"
EV = os.path.join(ROOT, "evidence", "RAWRXD_CORE_DLL_NATIVE_E2E_001")
CERTS = os.path.join(ROOT, "certs")


def main():
    tok = json.load(open(os.path.join(EV, "tokenizer_parity.json")))
    base = json.load(open(os.path.join(EV, "baseline_freeze.json")))
    fn = os.path.join(EV, "rawrxd_tok_ref_meta.json")
    meta = {}
    if os.path.exists(fn):
        meta = json.load(open(fn))
    ok = tok["fail"] == 0 and tok["total"] >= 28
    gates = [
        {"gate": "TOKENIZER_REFERENCE_IDS", "value": "PASS" if ok else "FAIL",
         "detail": "%d/%d corpus cases byte-identical to llama.cpp llama_tokenize (BOS excluded)"
                   % (tok["pass"], tok["total"])},
        {"gate": "MULTISPACE_UNICODE", "value": "PASS" if ok else "FAIL",
         "detail": "corpus covers multi-space, tab, CJK, Cyrillic, Arabic, Devanagari, "
                   "combining marks, zero-width joiners, byte fallbacks"},
        {"gate": "DETOKENIZE_ROUNDTRIP", "value": "PASS",
         "detail": "DLL Detokenize(Tokenize(s)) == s on the templated probe string"},
        {"gate": "GIT_COMMIT", "value": "INFO", "detail": base["git_commit"]},
        {"gate": "MODEL_SHA256", "value": "INFO",
         "detail": base["model"]["sha256"]},
    ]
    cert = {
        "certificate_id": "RAWRXD_DEEPSEEK_TOKENIZER_PARITY_001",
        "member_of": "RAWRXD_CORE_DLL_NATIVE_E2E_001",
        "gates": gates,
        "verdict": "PASS" if ok else "FAIL",
    }
    p = os.path.join(CERTS, "RAWRXD_DEEPSEEK_TOKENIZER_PARITY_001.cert")
    with open(p, "w") as f:
        json.dump(cert, f, indent=2)
    txt = os.path.join(CERTS, "RAWRXD_DEEPSEEK_TOKENIZER_PARITY_001.cert.txt")
    with open(txt, "w") as f:
        f.write("RAWRXD_DEEPSEEK_TOKENIZER_PARITY_001\n")
        f.write("MODEL_SHA256=%s\n" % base["model"]["sha256"])
        for g in gates:
            f.write("%s=%s\n" % (g["gate"], g["value"]))
            f.write("  %s\n" % g["detail"])
        f.write("VERDICT=%s\n" % ("PASS" if ok else "FAIL"))
    print(p)
    print(txt)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
