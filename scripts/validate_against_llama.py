#!/usr/bin/env python3
"""
RawrXD End-to-End Validation Against llama.cpp

Automates the complete validation pipeline:
1. Checks/builds instrumented llama.cpp
2. Generates reference data
3. Builds RawrXD with validation hooks
4. Runs RawrXD inference
5. Compares outputs
6. Generates validation report

Usage:
    python scripts/validate_against_llama.py --model /path/to/model.gguf --prompt "Hello world"
"""

import argparse
import subprocess
import os
import sys
import json
import time
import shutil
from pathlib import Path
from datetime import datetime

# Configuration
LLAMA_CPP_PATH = Path("f:/llama.cpp")
RAWRXD_PATH = Path("d:/rawrxd-ci-bootstrap")
VALIDATION_BUILD_DIR = RAWRXD_PATH / "build_validation"
RESULTS_DIR = RAWRXD_PATH / "validation_results"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def log(msg, color=None):
    """Print colored log message"""
    if color:
        print(f"{color}{msg}{Colors.END}")
    else:
        print(msg)

def run_cmd(cmd, cwd=None, check=True, capture=True):
    """Run shell command and return result"""
    log(f"  Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}", Colors.BLUE)
    
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=capture,
        text=True,
        shell=isinstance(cmd, str)
    )
    
    if check and result.returncode != 0:
        log(f"Command failed with code {result.returncode}", Colors.RED)
        if result.stderr:
            log(f"stderr: {result.stderr}", Colors.RED)
        return None
    
    return result

def check_llama_cpp_instrumented():
    """Check if llama.cpp has validation instrumentation"""
    log("\n[1/6] Checking llama.cpp instrumentation...")
    
    # Check for our patch marker
    llama_cpp_file = LLAMA_CPP_PATH / "llama.cpp"
    if not llama_cpp_file.exists():
        log("  ERROR: llama.cpp not found", Colors.RED)
        return False
    
    with open(llama_cpp_file, 'r') as f:
        content = f.read()
        if "RAWRXD_VALIDATION_MODE" in content:
            log("  llama.cpp is instrumented ✓", Colors.GREEN)
            return True
    
    log("  llama.cpp needs instrumentation patch", Colors.YELLOW)
    log("  Applying patch...")
    
    patch_file = RAWRXD_PATH / "patches" / "llama.cpp" / "rawrxd_validation_instrumentation.patch"
    if not patch_file.exists():
        log(f"  ERROR: Patch file not found: {patch_file}", Colors.RED)
        return False
    
    result = run_cmd(
        ["git", "apply", str(patch_file)],
        cwd=LLAMA_CPP_PATH,
        check=False
    )
    
    if result and result.returncode == 0:
        log("  Patch applied successfully ✓", Colors.GREEN)
        return True
    else:
        log("  ERROR: Failed to apply patch", Colors.RED)
        return False

def build_llama_cpp():
    """Build instrumented llama.cpp"""
    log("\n[2/6] Building instrumented llama.cpp...")
    
    build_dir = LLAMA_CPP_PATH / "build"
    build_dir.mkdir(exist_ok=True)
    
    # Configure
    log("  Configuring...")
    cmake_result = run_cmd([
        "cmake", "..",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DRAWRXD_VALIDATION_MODE=ON",
        "-DLLAMA_AVX512=ON",
        "-DLLAMA_AVX2=ON"
    ], cwd=build_dir, check=False)
    
    if not cmake_result or cmake_result.returncode != 0:
        log("  ERROR: CMake configuration failed", Colors.RED)
        return False
    
    # Build
    log("  Building...")
    build_result = run_cmd(
        ["cmake", "--build", ".", "--config", "Release", "-j"],
        cwd=build_dir,
        check=False
    )
    
    if not build_result or build_result.returncode != 0:
        log("  ERROR: Build failed", Colors.RED)
        return False
    
    log("  llama.cpp built successfully ✓", Colors.GREEN)
    return True

def generate_reference_data(model_path: Path, prompt: str, n_tokens: int):
    """Run llama.cpp to generate reference data"""
    log("\n[3/6] Generating reference data from llama.cpp...")
    
    main_exe = LLAMA_CPP_PATH / "build" / "bin" / "Release" / "main.exe"
    if not main_exe.exists():
        main_exe = LLAMA_CPP_PATH / "build" / "Release" / "main.exe"
    if not main_exe.exists():
        main_exe = LLAMA_CPP_PATH / "build" / "main.exe"
    
    if not main_exe.exists():
        log(f"  ERROR: main.exe not found", Colors.RED)
        return None
    
    # Change to results dir for output
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        str(main_exe),
        "-m", str(model_path),
        "-p", prompt,
        "-n", str(n_tokens),
        "--seed", "42",
        "--temp", "0.0"
    ]
    
    log(f"  Running inference (tokens={n_tokens})...")
    start_time = time.time()
    
    result = run_cmd(cmd, cwd=RESULTS_DIR, check=False)
    
    elapsed = time.time() - start_time
    log(f"  llama.cpp inference: {elapsed:.2f}s")
    
    if not result or result.returncode != 0:
        log("  ERROR: Inference failed", Colors.RED)
        if result and result.stderr:
            log(f"  stderr: {result.stderr}", Colors.RED)
        return None
    
    # Find generated reference file
    model_name = model_path.stem
    ref_file = RESULTS_DIR / f"rawrxd_ref_{model_name}.bin"
    
    if not ref_file.exists():
        log(f"  ERROR: Reference file not generated", Colors.RED)
        return None
    
    log(f"  Reference data: {ref_file.name} ({ref_file.stat().st_size / 1024 / 1024:.2f} MB) ✓", Colors.GREEN)
    return ref_file

def build_rawrxd_validation():
    """Build RawrXD with validation hooks enabled"""
    log("\n[4/6] Building RawrXD with validation hooks...")
    
    VALIDATION_BUILD_DIR.mkdir(exist_ok=True)
    
    # Configure
    log("  Configuring...")
    cmake_result = run_cmd([
        "cmake", "..",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DRAWRXD_ENABLE_VALIDATION=ON"
    ], cwd=VALIDATION_BUILD_DIR, check=False)
    
    if not cmake_result or cmake_result.returncode != 0:
        log("  ERROR: CMake configuration failed", Colors.RED)
        return False
    
    # Build
    log("  Building...")
    build_result = run_cmd(
        ["cmake", "--build", ".", "--config", "Release", "-j"],
        cwd=VALIDATION_BUILD_DIR,
        check=False
    )
    
    if not build_result or build_result.returncode != 0:
        log("  ERROR: Build failed", Colors.RED)
        return False
    
    log("  RawrXD built successfully ✓", Colors.GREEN)
    return True

def run_rawrxd_inference(model_path: Path, prompt: str, n_tokens: int):
    """Run RawrXD to generate output for comparison"""
    log("\n[5/6] Running RawrXD inference...")
    
    rawrxd_exe = VALIDATION_BUILD_DIR / "Release" / "rawrxd.exe"
    if not rawrxd_exe.exists():
        rawrxd_exe = VALIDATION_BUILD_DIR / "rawrxd.exe"
    
    if not rawrxd_exe.exists():
        log(f"  ERROR: rawrxd.exe not found", Colors.RED)
        return None
    
    cmd = [
        str(rawrxd_exe),
        "--model", str(model_path),
        "--prompt", prompt,
        "--tokens", str(n_tokens),
        "--seed", "42"
    ]
    
    log(f"  Running inference (tokens={n_tokens})...")
    start_time = time.time()
    
    result = run_cmd(cmd, cwd=RESULTS_DIR, check=False)
    
    elapsed = time.time() - start_time
    log(f"  RawrXD inference: {elapsed:.2f}s")
    
    if not result or result.returncode != 0:
        log("  ERROR: Inference failed", Colors.RED)
        return None
    
    # Find generated output file
    output_file = RESULTS_DIR / "rawrxd_output.bin"
    
    if not output_file.exists():
        log(f"  ERROR: Output file not generated", Colors.RED)
        return None
    
    log(f"  RawrXD output: {output_file.name} ({output_file.stat().st_size / 1024 / 1024:.2f} MB) ✓", Colors.GREEN)
    return output_file

def compare_outputs(ref_file: Path, output_file: Path, tolerance: float):
    """Run validation comparison"""
    log("\n[6/6] Comparing outputs...")
    
    # Build validation runner if needed
    val_build_dir = RAWRXD_PATH / "tests" / "inference_validation" / "build"
    val_runner = val_build_dir / "Release" / "validation_runner.exe"
    
    if not val_runner.exists():
        log("  Building validation runner...")
        val_build_dir.mkdir(parents=True, exist_ok=True)
        
        cmake_result = run_cmd(
            ["cmake", ".."],
            cwd=val_build_dir,
            check=False
        )
        if not cmake_result or cmake_result.returncode != 0:
            log("  ERROR: Validation runner CMake failed", Colors.RED)
            return False
        
        build_result = run_cmd(
            ["cmake", "--build", ".", "--config", "Release"],
            cwd=val_build_dir,
            check=False
        )
        if not build_result or build_result.returncode != 0:
            log("  ERROR: Validation runner build failed", Colors.RED)
            return False
    
    # Run comparison
    cmd = [
        str(val_runner),
        "--reference", str(ref_file),
        "--actual", str(output_file),
        "--tolerance", str(tolerance)
    ]
    
    result = run_cmd(cmd, check=False, capture=False)
    
    return result and result.returncode == 0

def generate_report(model_path: Path, prompt: str, results: dict):
    """Generate JSON validation report"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "model": str(model_path),
        "prompt": prompt,
        "results": results
    }
    
    report_file = RESULTS_DIR / f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    log(f"\nReport saved: {report_file}", Colors.BLUE)

def main():
    parser = argparse.ArgumentParser(
        description="Validate RawrXD against llama.cpp",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --model /path/to/tinyllama.gguf --prompt "Hello world"
    %(prog)s --model /path/to/model.gguf --prompt "Test" --tokens 20 --tolerance 1e-4
        """
    )
    
    parser.add_argument("--model", type=Path, required=True,
                        help="Path to GGUF model file")
    parser.add_argument("--prompt", type=str, default="Hello world",
                        help="Prompt for inference (default: 'Hello world')")
    parser.add_argument("--tokens", type=int, default=10,
                        help="Number of tokens to generate (default: 10)")
    parser.add_argument("--tolerance", type=float, default=1e-5,
                        help="Error tolerance for comparison (default: 1e-5)")
    parser.add_argument("--skip-llama-build", action="store_true",
                        help="Skip llama.cpp build if already built")
    parser.add_argument("--skip-rawrxd-build", action= "store_true",
                        help="Skip RawrXD build if already built")
    
    args = parser.parse_args()
    
    # Validate model exists
    if not args.model.exists():
        log(f"ERROR: Model not found: {args.model}", Colors.RED)
        return 1
    
    log("\n" + "="*60, Colors.BLUE)
    log("RawrXD End-to-End Validation", Colors.BLUE)
    log("="*60, Colors.BLUE)
    log(f"Model: {args.model}")
    log(f"Prompt: '{args.prompt}'")
    log(f"Tokens: {args.tokens}")
    log(f"Tolerance: {args.tolerance}")
    log("="*60 + "\n", Colors.BLUE)
    
    results = {
        "success": False,
        "steps": {}
    }
    
    start_time = time.time()
    
    # Step 1: Check llama.cpp instrumentation
    if not check_llama_cpp_instrumented():
        results["steps"]["llama_instrumentation"] = "failed"
        generate_report(args.model, args.prompt, results)
        return 1
    results["steps"]["llama_instrumentation"] = "success"
    
    # Step 2: Build llama.cpp
    if not args.skip_llama_build:
        if not build_llama_cpp():
            results["steps"]["llama_build"] = "failed"
            generate_report(args.model, args.prompt, results)
            return 1
    results["steps"]["llama_build"] = "success"
    
    # Step 3: Generate reference data
    ref_file = generate_reference_data(args.model, args.prompt, args.tokens)
    if not ref_file:
        results["steps"]["reference_generation"] = "failed"
        generate_report(args.model, args.prompt, results)
        return 1
    results["steps"]["reference_generation"] = "success"
    
    # Step 4: Build RawrXD
    if not args.skip_rawrxd_build:
        if not build_rawrxd_validation():
            results["steps"]["rawrxd_build"] = "failed"
            generate_report(args.model, args.prompt, results)
            return 1
    results["steps"]["rawrxd_build"] = "success"
    
    # Step 5: Run RawrXD
    output_file = run_rawrxd_inference(args.model, args.prompt, args.tokens)
    if not output_file:
        results["steps"]["rawrxd_inference"] = "failed"
        generate_report(args.model, args.prompt, results)
        return 1
    results["steps"]["rawrxd_inference"] = "success"
    
    # Step 6: Compare
    if not compare_outputs(ref_file, output_file, args.tolerance):
        results["steps"]["comparison"] = "failed"
        generate_report(args.model, args.prompt, results)
        return 1
    results["steps"]["comparison"] = "success"
    
    # Success!
    total_time = time.time() - start_time
    results["success"] = True
    results["total_time_seconds"] = total_time
    
    log("\n" + "="*60, Colors.GREEN)
    log("VALIDATION PASSED ✓", Colors.GREEN)
    log(f"Total time: {total_time:.2f}s", Colors.GREEN)
    log("="*60 + "\n", Colors.GREEN)
    
    generate_report(args.model, args.prompt, results)
    return 0

if __name__ == "__main__":
    sys.exit(main())
