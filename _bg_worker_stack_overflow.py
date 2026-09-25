#!/usr/bin/env python3
"""
Background Worker: Fix stack overflow in shared forward code for Gemma3-1B Q2_K.
Triggered by: continue-ensure MOTD dispatch.
"""
import subprocess, os, sys, re, json, time

ROOT = r"F:\~dev\rawrxd"
BUILD = r"F:\~dev\rawrxd\win32ide_strict\build_v4"
PARITY_EXE = r"F:\~dev\rawrxd\win32ide_strict\build_v4\bin\Release\rawrxd_real_gguf_parity.exe"
QKR = os.path.join(ROOT, "src", "deep2", "QuantKernelRegistry.cpp")
ENGINE = os.path.join(ROOT, "src", "deep2", "Deep2Engine.cpp")
OUT_LOG = r"F:\~dev\_bg_worker_stack_overflow_log.txt"

def log(msg):
    with open(OUT_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    print(msg)

def run_cmd(cmd, cwd=None, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd or BUILD)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return -1, "", str(e)

def read_lines(path, start, end):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return "".join(lines[start-1:end])
    except Exception as e:
        return f"ERROR reading {path}: {e}"

log("=== BG WORKER START: Stack Overflow Fix ===")

# 1. Inspect gemv_q2_k_scalar for stack allocations
log("1. Reading gemv_q2_k_scalar (~1598-1700) in QuantKernelRegistry.cpp")
chunk = read_lines(QKR, 1590, 1710)
with open(r"F:\~dev\_inspect_gemv_q2_k_scalar.txt", "w", encoding="utf-8") as f:
    f.write(chunk)
log("   Saved to _inspect_gemv_q2_k_scalar.txt")

# 2. Search for alloca / VLA across deep2 sources
log("2. Searching for alloca / VLA / large stack arrays in src/deep2/*.cpp")
patterns = [r"alloca\s*\(", r"__builtin_alloca", r"_malloca\s*\(", r"\bfloat\s+\w+\[\d{5,}\]", r"\bdouble\s+\w+\[\d{5,}\]"]
matches = []
for root, dirs, files in os.walk(os.path.join(ROOT, "src", "deep2")):
    for name in files:
        if name.endswith(".cpp"):
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f, 1):
                        for pat in patterns:
                            if re.search(pat, line):
                                matches.append(f"{path}:{i}: {line.strip()}")
            except Exception:
                pass
with open(r"F:\~dev\_alloca_search.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(matches) if matches else "(no matches)")
log(f"   Found {len(matches)} potential stack allocation matches -> _alloca_search.txt")

# 3. Check for recursion in forward paths
log("3. Checking forwardLayer / forwardTokenAllLayers / tryVulkanHostGEMV for recursion")
recurse_hints = []
for path in [ENGINE, os.path.join(ROOT, "src", "deep2", "Deep2Engine_GpuForward.cpp"), os.path.join(ROOT, "src", "deep2", "Deep2Engine_GpuMoEMLA.cpp")]:
    if not os.path.exists(path):
        continue
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    # crude: look for function calling itself
    funcs = ["forwardLayer", "forwardTokenAllLayers", "tryVulkanHostGEMV", "forwardGpuContiguousRange", "forwardGpuMultiMap"]
    for func in funcs:
        if func + "(" in content:
            # count definitions vs calls
            defs = re.findall(rf"\b{re.escape(func)}\s*\(", content)
            calls = content.count(func + "(")
            if calls > len(defs):
                recurse_hints.append(f"{path}: {func} appears {calls} times ({len(defs)} defs)")
with open(r"F:\~dev\_recurse_hints.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(recurse_hints) if recurse_hints else "(no recursion hints)")
log(f"   Recursion hints -> _recurse_hints.txt")

# 4. Run parity harness to capture fresh stack-overflow evidence
log("4. Running parity harness (expect stack-overflow crash)...")
if os.path.exists(PARITY_EXE):
    rc, out, err = run_cmd([PARITY_EXE, "--model", r"D:\rawrxd\gemma3-1b-Q2_K.gguf", "--gpu", "false", "--max-tokens", "1"], cwd=BUILD, timeout=60)
    log(f"   Parity EXIT_CODE={rc}")
    with open(r"F:\~dev\_parity_run_out.txt", "w", encoding="utf-8") as f:
        f.write(f"RC={rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}")
else:
    log(f"   Parity exe NOT FOUND at {PARITY_EXE}")

# 5. Build parity target to ensure latest binaries
log("5. Rebuilding parity target...")
rc, out, err = run_cmd(["cmake", "--build", BUILD, "--config", "Release", "--target", "rawrxd_real_gguf_parity"], cwd=BUILD, timeout=300)
log(f"   Build RC={rc}")
with open(r"F:\~dev\_parity_build_log.txt", "w", encoding="utf-8") as f:
    f.write(f"RC={rc}\n\nSTDOUT:\n{out}\n\nSTDERR:\n{err}")

log("=== BG WORKER PAUSED ===")
# Keep alive for coordinator inspection
while True:
    time.sleep(3600)
