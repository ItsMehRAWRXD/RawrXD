#!/usr/bin/env python3
"""Full regression suite for the certified Deep2 baseline.

Runs every acceptance gate that must hold after a change to the
runtime, in order:

  1. git sync        HEAD == origin/<branch>, tree state reported
  2. E2E verifier    tools/verify_e2e_cert.py (12 independent checks)
  3. certificate     both tracked certificates parse, VERDICT=PASS,
                     every gate PASS (SEPARATE_GATE allowed)
  4. ownership       build (if requested) and run
                     src/core/dll/ownership_test.cpp ->
                     DEEP2_RUNTIME_OWNERSHIP_001=PASS

Exit code is non-zero if any gate fails.

Usage:
  py -3 tools/run_regression_suite.py [--build] [--build-dir DIR]
                                      [--model PATH]
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = r"F:\rawrxd"
BRANCH = "feat/hexmag-polymorphic-repeat-tuner-masm"
CERTS = os.path.join(ROOT, "certs")
E2E_CERT = os.path.join(CERTS, "RAWRXD_CORE_DLL_NATIVE_E2E_001.cert")
REPRO_CERT = os.path.join(CERTS, "RAWRXD_REFERENCE_REPRODUCIBILITY_001.cert")

failures = []


def report(gate, ok, detail=""):
    print("%-28s %s%s" % (gate, "PASS" if ok else "FAIL",
                          ("  " + detail) if detail else ""))
    if not ok:
        failures.append(gate)


def run(cmd, cwd=ROOT, timeout=600, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env=env)


def git_sync():
    out = run(["git", "rev-parse", "HEAD"])
    head = out.stdout.strip()
    out = run(["git", "rev-parse", "origin/%s" % BRANCH])
    remote = out.stdout.strip()
    report("GIT_SYNC", head == remote and head != "",
           "HEAD=%s origin=%s" % (head[:8], remote[:8]))
    out = run(["git", "status", "--porcelain"])
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    # Staged changes would be committed accidentally; modified/untracked
    # files are the expected local state during development (evidence
    # artifacts, in-flight work) and are only reported.
    staged = [l for l in lines if l[0] not in (" ", "?", "!")]
    report("GIT_TREE", not staged,
           "%d modified, %d untracked, %d staged" % (
               len([l for l in lines if l[:2] == " M"]),
               len([l for l in lines if l[:2] == "??"]),
               len(staged)))


def e2e_verifier():
    out = run([sys.executable, os.path.join(ROOT, "tools", "verify_e2e_cert.py")],
              timeout=900)
    m = re.search(r"CHECKS_PASSED=(\d+)/(\d+)", out.stdout)
    ok = m and m.group(1) == m.group(2) and out.returncode == 0
    report("E2E_VERIFIER", bool(ok),
           "checks %s/%s" % (m.group(1), m.group(2)) if m else out.stdout[-200:])


def cert_json(path, name, documented_fail=()):
    """Validate a certificate. `documented_fail` lists gates whose FAIL
    value is the recorded, accepted verdict (e.g. the adjudicated
    STORED_REFERENCE_REPRODUCIBLE=FAIL in the reproducibility cert);
    the certificate's own VERDICT gate governs acceptance."""
    try:
        with open(path) as f:
            cert = json.load(f)
    except Exception as e:  # noqa: BLE001
        report(name, False, "parse error: %s" % e)
        return
    gates = cert.get("gates", [])
    bad = [g["gate"] for g in gates
           if g.get("value") not in ("PASS", "SEPARATE_GATE")
           and g["gate"] not in documented_fail]
    verdict = [g["value"] for g in gates if g["gate"] == "VERDICT"]
    ok = not bad and verdict == ["PASS"]
    report(name, ok,
           "%d gates%s" % (len(gates),
                           "; failing: %s" % ",".join(bad) if bad else ""))


def ownership_test(build_dir, model):
    exe = os.path.join(build_dir, "bin", "Release", "ownership_test.exe")
    if not os.path.exists(exe):
        exe = os.path.join(build_dir, "bin", "Debug", "ownership_test.exe")
    if not os.path.exists(exe):
        report("OWNERSHIP_TEST", False, "binary not found (build first)")
        return
    env = dict(os.environ)
    if model:
        env["RAWRXD_OWNERSHIP_MODEL"] = model
    out = run([exe], cwd=build_dir, env=env, timeout=900)
    ok = "DEEP2_RUNTIME_OWNERSHIP_001=PASS" in out.stdout + out.stderr
    detail = ""
    for line in (out.stdout + out.stderr).splitlines():
        if "FAIL" in line or "ownership" in line.lower():
            detail += line.strip() + " | "
    report("OWNERSHIP_TEST", ok, detail[:300])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", default=None,
                    help="build directory containing ownership_test.exe")
    ap.add_argument("--model", default=None,
                    help="GGUF path for the ownership test")
    args = ap.parse_args()

    print("=== RAWRXD regression suite ===")
    git_sync()
    e2e_verifier()
    cert_json(E2E_CERT, "CERT_E2E")
    # STORED_REFERENCE_REPRODUCIBLE=FAIL is the recorded
    # adjudication: the stored artifact is a non-reproducible
    # historical reference, superseded by ref_teacher_forced.
    cert_json(REPRO_CERT, "CERT_REPRODUCIBILITY",
              documented_fail=("STORED_REFERENCE_REPRODUCIBLE",))
    if args.build_dir:
        ownership_test(args.build_dir, args.model)

    print()
    if failures:
        print("SUITE=FAIL (%d): %s" % (len(failures), ", ".join(failures)))
        return 1
    print("SUITE=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
