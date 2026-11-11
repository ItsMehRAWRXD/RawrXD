#!/usr/bin/env python3
"""
RawrXD Reference Data Generator

Generates golden reference data from llama.cpp for validation.
Builds llama.cpp with RAWRXD_VALIDATION_MODE and runs inference
to dump layer outputs.

Usage:
    python generate_reference_data.py --model /path/to/model.gguf --prompt "Hello world"
"""

import argparse
import subprocess
import os
import sys
import json
import struct
from pathlib import Path

# Default paths
LLAMA_CPP_PATH = Path("f:/llama.cpp")
OUTPUT_DIR = Path("d:/rawrxd-ci-bootstrap/tests/inference_validation/fixtures")


def build_instrumented_llama():
    """Build llama.cpp with validation instrumentation."""
    build_dir = LLAMA_CPP_PATH / "build"
    build_dir.mkdir(exist_ok=True)
    
    # Configure with validation mode
    cmake_cmd = [
        "cmake", "..",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DRAWRXD_VALIDATION_MODE=ON",
        "-DLLAMA_AVX512=ON",
        "-DLLAMA_AVX2=ON",
    ]
    
    print("Configuring llama.cpp with validation instrumentation...")
    result = subprocess.run(cmake_cmd, cwd=build_dir, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"CMake failed: {result.stderr}")
        return False
    
    # Build
    print("Building instrumented llama.cpp...")
    result = subprocess.run(["cmake", "--build", ".", "-j", "--config", "Release"],
                            cwd=build_dir, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Build failed: {result.stderr}")
        return False
    
    print("Build successful!")
    return True


def run_inference(model_path: Path, prompt: str, n_tokens: int = 10):
    """Run llama.cpp inference and capture dumped tensors."""
    build_dir = LLAMA_CPP_PATH / "build"
    main_exe = build_dir / "bin" / "Release" / "main.exe"
    
    if not main_exe.exists():
        main_exe = build_dir / "main.exe"
    
    if not main_exe.exists():
        print(f"llama.cpp main.exe not found at {main_exe}")
        return None
    
    # Run inference
    cmd = [
        str(main_exe),
        "-m", str(model_path),
        "-p", prompt,
        "-n", str(n_tokens),
        "--seed", "42",  # Deterministic
        "--temp", "0.0",  # Greedy
    ]
    
    print(f"Running inference: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Inference failed: {result.stderr}")
        return None
    
    # Find output file
    model_name = model_path.stem
    ref_file = Path(f"rawrxd_ref_{model_name}.bin")
    
    if not ref_file.exists():
        print(f"Reference file not generated: {ref_file}")
        return None
    
    return ref_file


def parse_reference_file(ref_file: Path):
    """Parse the binary reference file and convert to JSON."""
    with open(ref_file, 'rb') as f:
        # Read header
        magic = struct.unpack('I', f.read(4))[0]
        version = struct.unpack('I', f.read(4))[0]
        
        if magic != 0x52414452:  # "RADR"
            print(f"Invalid magic: {hex(magic)}")
            return None
        
        print(f"Reference file version: {version}")
        
        records = []
        
        while True:
            try:
                # Read record header
                layer_idx = struct.unpack('i', f.read(4))[0]
                name_len = struct.unpack('H', f.read(2))[0]
                name = f.read(name_len).decode('utf-8')
                n_dims = struct.unpack('i', f.read(4))[0]
                shape = struct.unpack(f'{n_dims}i', f.read(n_dims * 4))
                n_elements = struct.unpack('Q', f.read(8))[0]
                
                # Read data
                data = struct.unpack(f'{n_elements}f', f.read(n_elements * 4))
                
                records.append({
                    'layer': layer_idx,
                    'name': name,
                    'shape': list(shape),
                    'n_elements': n_elements,
                    'data': list(data)[:10] + ['...'] if n_elements > 10 else list(data),
                    'data_hash': hash(tuple(data)) & 0xFFFFFFFF
                })
                
            except struct.error:
                break
        
        return records


def save_as_json(records, output_path: Path):
    """Save records as JSON for inspection."""
    with open(output_path, 'w') as f:
        json.dump(records, f, indent=2)
    print(f"Saved JSON to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate RawrXD reference data")
    parser.add_argument("--model", type=Path, required=True,
                        help="Path to GGUF model file")
    parser.add_argument("--prompt", type=str, default="Hello world",
                        help="Prompt for inference")
    parser.add_argument("--n-tokens", type=int, default=10,
                        help="Number of tokens to generate")
    parser.add_argument("--skip-build", action="store_true",
                        help="Skip building llama.cpp")
    
    args = parser.parse_args()
    
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Build instrumented llama.cpp
    if not args.skip_build:
        if not build_instrumented_llama():
            sys.exit(1)
    
    # Run inference
    ref_file = run_inference(args.model, args.prompt, args.n_tokens)
    if not ref_file:
        sys.exit(1)
    
    # Parse and save
    records = parse_reference_file(ref_file)
    if records:
        json_path = OUTPUT_DIR / f"{args.model.stem}_reference.json"
        save_as_json(records, json_path)
        
        # Also copy binary file
        bin_output = OUTPUT_DIR / f"{args.model.stem}_reference.bin"
        ref_file.rename(bin_output)
        print(f"Saved binary reference to: {bin_output}")
        
        print(f"\nGenerated {len(records)} tensor records")
        print("Reference data ready for validation!")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
