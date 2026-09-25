#!/usr/bin/env python3
"""
RAWRXD_WIN32IDE_E2E_001 — BACKGROUND WORKER
Executes the E2E brief from _bg_worker_e2e_brief.txt end-to-end.
"""
import subprocess, os, sys, time, json, hashlib

BUILD_DIR = r"f:\~dev\rawrxd\win32ide_strict\build_v4"
RELEASE_DIR = os.path.join(BUILD_DIR, "Release")
EXE = os.path.join(RELEASE_DIR, "RawrXD-Win32IDE.exe")
MODEL_PATH = r"D:\rawrxd\gemma3-1b-Q2_K.gguf"
RECEIPT_PATH = os.path.join(RELEASE_DIR, "cert_receipt_autoclose.txt")

RECEIPT_KEYS = [
    "MODEL_LOADED",
    "TOKENIZER_READY",
    "FORWARD_PASS_OK",
    "LOGITS_FINITE",
    "GENERATED_TOKEN_COUNT",
    "REAL_GPU_FORWARD",
    "GPU_FALLBACK_DELTA",
    "VERDICT",
]

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    sys.stdout.flush()

def run_cmd(cmd, cwd=None, timeout=600):
    log(f"RUN: {cmd}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd or BUILD_DIR)
    log(f"RC={result.returncode}")
    if result.stdout:
        log(f"STDOUT:\n{result.stdout[:4096]}")
    if result.stderr:
        log(f"STDERR:\n{result.stderr[:4096]}")
    return result.returncode, result.stdout, result.stderr

def build_release():
    log("=== GATE 1: STRICT_RELEASE_BUILD ===")
    rc, out, err = run_cmd(
        ["cmake", "--build", BUILD_DIR, "--config", "Release", "--target", "RawrXD-Win32IDE"],
        timeout=600
    )
    if rc != 0:
        log("BUILD FAILED")
        return False
    if not os.path.exists(EXE):
        log("EXE NOT FOUND")
        return False
    log("BUILD OK")
    return True

def parse_receipt(path):
    data = {}
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
    except Exception as e:
        log(f"Receipt read error: {e}")
    return data

def run_autoclose():
    log("=== GATE 2: AUTOCLOSURE_REAL_RUNTIME ===")
    # Use existing model path or fall back
    model = MODEL_PATH if os.path.exists(MODEL_PATH) else r"G:\~dev\test_model.gguf"
    if not os.path.exists(model):
        log(f"MODEL NOT FOUND: {model}")
        return False

    env = os.environ.copy()
    env["RAWRXD_AUTOCLOSE_DEBUG"] = "1"
    env["RAWRXD_AUTOCLOSE_GEN"] = "1"
    env["RAWRXD_AUTOCLOSE_LAYERS"] = "26"

    cmd = [
        EXE,
        "--autoclose",
        "--model", model,
        "--workspace", r"F:\~dev\rawrxd",
        "--gate-tokens", "8",
        "--nonce", "7E91B462",
        "--receipt", RECEIPT_PATH,
        "--wall-ms", "300000",
    ]

    log(f"Running autoclose with model={model}")
    rc, out, err = run_cmd(cmd, cwd=RELEASE_DIR, timeout=300)
    log(f"Autoclose EXIT_CODE={rc}")

    receipt = parse_receipt(RECEIPT_PATH)
    log(f"Receipt contents: {json.dumps(receipt, indent=2)}")

    ok = True
    for key in ["MODEL_LOADED", "TOKENIZER_READY", "FORWARD_PASS_OK", "LOGITS_FINITE"]:
        if receipt.get(key) != "PASS":
            log(f"RECEIPT FAIL: {key}={receipt.get(key)}")
            ok = False
    try:
        gen_count = int(receipt.get("GENERATED_TOKEN_COUNT", "0"))
        if gen_count <= 0:
            log(f"RECEIPT FAIL: GENERATED_TOKEN_COUNT={gen_count}")
            ok = False
    except ValueError:
        log("RECEIPT FAIL: GENERATED_TOKEN_COUNT not integer")
        ok = False
    if receipt.get("REAL_GPU_FORWARD") != "PASS":
        log(f"RECEIPT FAIL: REAL_GPU_FORWARD={receipt.get('REAL_GPU_FORWARD')}")
        ok = False
    if receipt.get("VERDICT") != "PASS":
        log(f"RECEIPT FAIL: VERDICT={receipt.get('VERDICT')}")
        ok = False
    if ok:
        log("AUTOCLOSE GATE PASSED")
    else:
        log("AUTOCLOSE GATE FAILED")
    return ok

def save_report(passed):
    report_path = os.path.join(RELEASE_DIR, "e2e_report.txt")
    with open(report_path, "w") as f:
        f.write(f"E2E_REPORT={json.dumps({'passed': passed, 'time': time.time()})}\n")
    log(f"Report saved to {report_path}")

def main():
    log("WORKER_START")
    build_ok = build_release()
    if not build_ok:
        save_report(False)
        log("WORKER_DONE: BUILD_FAIL")
        return 1
    autoclose_ok = run_autoclose()
    save_report(autoclose_ok)
    log("WORKER_DONE")
    return 0 if autoclose_ok else 1

if __name__ == "__main__":
    sys.exit(main())
