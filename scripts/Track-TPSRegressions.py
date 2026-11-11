import os
import subprocess
import json
import csv
from datetime import datetime

MODELS_DIR = r"G:\~dev\rawrxd\models"
ENGINE_EXE = r"build\bin\Deep2Engine_Benchmark.exe"
REGRESSION_LOG = r"build\tps_regression_history.csv"

def run_performance_audit():
    print("====================================================")
    print("    STARTING AUTOMATED THROUGHPUT REGRESSION AUDIT   ")
    print("====================================================")

    if not os.path.exists(ENGINE_EXE):
        print(f"[CRITICAL] Compiled benchmark executable not found at: {ENGINE_EXE}")
        return

    model_files = [f for f in os.listdir(MODELS_DIR) if f.endswith(".gguf")]
    if not model_files:
        print("[WARN] Zero verified GGUF model symlinks detected.")
        return

    # Check for historical validation baselines to track performance shifts
    history_exists = os.path.exists(REGRESSION_LOG)
    
    with open(REGRESSION_LOG, mode='a', newline='') as file:
        writer = csv.writer(file)
        if not history_exists:
            writer.writerow(["Timestamp", "ModelName", "Throughput_TPS", "Status"])

        for model in model_files:
            full_path = os.path.join(MODELS_DIR, model)
            print(f"\n[PROFILING] Evaluating conversion path performance for: {model}")

            try:
                # Fire localized processing passes to capture execution telemetry data strings
                result = subprocess.run([ENGINE_EXE, full_path], capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr

                # Parse the logged real throughput metric out of execution telemetry frames
                tps_val = 0.0
                status = "STABLE"
                
                for line in output.split("\n"):
                    if "REAL THROUGHPUT" in line or "DECODE_TPS_REAL" in line:
                        # Extract floating-point transaction count numbers cleanly
                        parts = line.split(":")
                        tps_val = float(parts[1].strip().split()[0])
                        break

                if tps_val == 0.0:
                    status = "STALL_DETECTED"
                elif tps_val < 15.0: # Set a baseline threshold flag for larger model cuts
                    status = "DEGRADED"

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                writer.writerow([timestamp, model, f"{tps_val:.3f}", status])
                print(f"  -> Calculated Performance: {tps_val:.3f} TPS | Status Tag: {status}")

            except subprocess.TimeoutExpired:
                print(f"  -> [FAIL] Execution exceeded target execution deadline on model: {model}")
                writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S"), model, "0.000", "TIMEOUT_CRASH"])
            except Exception as e:
                print(f"  -> [FAIL] Intercepted unexpected runtime breakdown: {str(e)}")

    print("\n[SUCCESS] Production regression logging sweep complete.")

if __name__ == "__main__":
    run_performance_audit()