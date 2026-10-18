import subprocess
import os
import sys
import time
import csv
from datetime import datetime

ENGINE_EXE = r"build\bin\Deep2Engine_Benchmark.exe"
MODEL_BLOB = r"G:\~dev\rawrxd\models\phi3-mini-Q2_K.gguf"
TIMING_REPORT = r"build\thread_latencies_report.csv"

def run_thread_profiler():
    print("====================================================")
    print("      DEEP2ENGINE ASYNC THREAD TIMING PROFILER      ")
    print("====================================================")

    if not os.path.exists(ENGINE_EXE):
        print(f"[ERROR] Compiled executable target missing at: {ENGINE_EXE}")
        return

    if not os.path.exists(MODEL_BLOB):
        print(f"[WARN] Target model file not found at {MODEL_BLOB}. Running placeholder simulation sweep.")

    print(f"[PROFILING] Spawning processing threads against context footprint...")
    
    start_wall = time.perf_counter()
    try:
        # Launch engine matrix calculation pass and capture console string buffers
        result = subprocess.run([ENGINE_EXE, MODEL_BLOB], capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print("[FAIL] Execution thread failed to return within the target safety deadline limit.")
        return

    end_wall = time.perf_counter()
    total_wall_ms = (end_wall - start_wall) * 1000.0

    # Ensure output compilation directories exist
    os.makedirs(os.path.dirname(TIMING_REPORT), exist_ok=True)

    with open(TIMING_REPORT, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "CoreMetric", "ExecutionValue_MS"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "Total_Wall_Latency", f"{total_wall_ms:.3f}"])

        print("\n================ THREAD PERFORMANCE METRICS ================")
        print(f"  TOTAL ENGINE WALL LATENCY : {total_wall_ms:.3f} ms")
        
        # Scan for internal trace signals emitted from our lock-free worker pools
        for line in output.split("\n"):
            if "[POOL_DISPATCH]" in line or "[STATUS]" in line:
                print(f"  -> {line.strip()}")
                
        print("============================================================\n")
        print(f"[SUCCESS] Deep runtime thread diagnostics sealed inside: {TIMING_REPORT}")

if __name__ == "__main__":
    run_thread_profiler()