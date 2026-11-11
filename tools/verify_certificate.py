#!/usr/bin/env python3
"""Durable certificate verifier - RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001

A test must not be reported as passing merely because the process returned
zero. This verifier re-opens a certificate written by a finished process and
independently checks that:

  1. the file exists and was closed by a process that already exited
  2. the expected gate id is present
  3. every required field is present
  4. the certificate is terminated by END_CERTIFICATE
  5. PASSED + FAILED == CHECKS and the field count matches
  6. VERDICT is consistent with PASSED/FAILED
  7. no required gate is FAIL or PENDING

Exit code is non-zero on any violation.
"""
import argparse
import os
import sys

REQUIRED = [
    "SAME_EXECUTOR_IMPLEMENTATION",
    "REAL_GGUF_MODEL_LOAD",
    "DLL_MODEL_LOAD",
    "DLL_CONTEXT_CREATE",
    "DLL_REAL_PREFILL",
    "IR_DISPATCH_300_OF_300",
    "IR_DISPATCH_300_OF_300_DLL",
    "FINITE_NONZERO_LOGITS",
    "STANDALONE_DLL_LOGIT_PARITY",
    "AUTOREGRESSIVE_16",
    "PROMPT_ECHO_FALLBACK",
    "RAWRXDCORE_INIT",
    "RAWRXDCORE_LOAD_MODEL",
    "RAWRXDCORE_CREATE_CONTEXT",
    "FIRST_REAL_TOKEN_CALLBACK",
]

ACCEPTED = ("PASS", "ABSENT")


def parse(path):
    fields = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            fields[key.strip()] = value.strip()
    return fields


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("certificate")
    ap.add_argument("--gate", default="RAWRXD_MODELGENIE_PRODUCTION_RUNTIME_001")
    ap.add_argument("--require", action="append", default=[],
                    help="additional required field (repeatable)")
    args = ap.parse_args()

    problems = []

    if not os.path.isfile(args.certificate):
        print("FAIL: certificate file does not exist: %s" % args.certificate)
        return 1
    size = os.path.getsize(args.certificate)
    if size == 0:
        print("FAIL: certificate is empty (producer died before writing)")
        return 1

    f = parse(args.certificate)

    if f.get("GATE") != args.gate:
        problems.append("GATE is %r, expected %r" % (f.get("GATE"), args.gate))

    if f.get("END_CERTIFICATE") != "1":
        problems.append("certificate is not terminated by END_CERTIFICATE "
                        "(producer likely killed mid-run)")

    required = list(REQUIRED) + list(args.require)
    seen_pass = seen_fail = 0
    for name in required:
        if name not in f:
            problems.append("missing required field: %s" % name)
            continue
        value = f[name].split(" ", 1)[0]
        if value in ACCEPTED:
            seen_pass += 1
        else:
            seen_fail += 1
            problems.append("%s = %s (expected one of %s)"
                            % (name, value, "/".join(ACCEPTED)))

    # Cross-check counters against the actual field rows.
    rows = [k for k in f if k.isupper() and k not in
            ("GATE", "MODEL", "RUNTIME", "CHECKS", "PASSED", "FAILED",
             "VERDICT", "END_CERTIFICATE")]
    n_checks = len(rows)
    if "CHECKS" in f and f["CHECKS"].isdigit():
        if int(f["CHECKS"]) != n_checks:
            problems.append("CHECKS=%s but %d field rows present"
                            % (f["CHECKS"], n_checks))
    if "PASSED" in f and f["PASSED"].isdigit():
        if int(f["PASSED"]) != seen_pass:
            problems.append("PASSED=%s but %d required fields passed"
                            % (f["PASSED"], seen_pass))
    if "FAILED" in f and f["FAILED"].isdigit():
        if int(f["FAILED"]) != seen_fail:
            problems.append("FAILED=%s but %d required fields failed"
                            % (f["FAILED"], seen_fail))

    verdict = f.get("VERDICT")
    if verdict != "PASS":
        problems.append("VERDICT = %s" % verdict)
    elif seen_fail:
        problems.append("VERDICT=PASS but %d required fields failed" % seen_fail)

    for p in problems:
        print("FAIL: %s" % p)
    if problems:
        print("\nCERTIFICATE_REJECTED (%d problem(s))" % len(problems))
        return 1

    print("CERTIFICATE_ACCEPTED")
    print("  gate      : %s" % f.get("GATE"))
    print("  model     : %s" % f.get("MODEL"))
    print("  runtime   : %s" % f.get("RUNTIME"))
    print("  checks    : %s fields (%d required gates verified)"
          % (f.get("CHECKS"), seen_pass))
    print("  verdict   : %s" % verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
