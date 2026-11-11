#!/usr/bin/env python3
"""Verify which physical address contains the patched vs original tensor data."""
import hashlib
import struct
from pathlib import Path

DIAGNOSTIC_GGUF = Path("F:/rawrxd/evidence/HEADER_AUTHORITY_MILESTONE/DeepSeek-V2-Lite-Chat.Q4_K_M.DIAGNOSTIC_REPAIRED.gguf")

# Three candidate addresses for blk.0.attn_norm.weight
A = 289996800   # relative offset treated as absolute
B = 293968800   # old dataStart (3972000) + relative
C = 293993216   # authoritative dataStart (3996416) + relative

def analyze_region(data, label):
    """Analyze 8192 bytes as 2048 float32 values."""
    if len(data) != 8192:
        print(f"{label}: ERROR expected 8192 bytes, got {len(data)}")
        return
    
    floats = struct.unpack('<2048f', data)
    
    nonfinite = 0
    nan_count = 0
    inf_count = 0
    first_nonfinite = -1
    min_val = float('inf')
    max_val = float('-inf')
    
    for i, v in enumerate(floats):
        if not (float('-inf') < v < float('inf')):
            nonfinite += 1
            if v != v:  # NaN check
                nan_count += 1
            else:
                inf_count += 1
            if first_nonfinite == -1:
                first_nonfinite = i
        else:
            if v < min_val:
                min_val = v
            if v > max_val:
                max_val = v
    
    sha256 = hashlib.sha256(data).hexdigest()[:16]
    
    print(f"{label}:")
    print(f"  NONFINITE={nonfinite}")
    print(f"  NAN={nan_count}")
    print(f"  INF={inf_count}")
    print(f"  FIRST_NONFINITE={first_nonfinite}")
    if nonfinite == 0:
        print(f"  MIN={min_val:.6e}")
        print(f"  MAX={max_val:.6e}")
    else:
        print(f"  MIN=nan")
        print(f"  MAX=nan")
    print(f"  SHA256_8192={sha256}")
    print()

def main():
    print("=" * 60)
    print("ADDRESS VERIFICATION 001")
    print("=" * 60)
    print(f"Diagnostic GGUF: {DIAGNOSTIC_GGUF}")
    print(f"Size: {DIAGNOSTIC_GGUF.stat().st_size / 1024 / 1024 / 1024:.2f} GB")
    print()
    
    with open(DIAGNOSTIC_GGUF, 'rb') as f:
        # Read from address A (relative offset treated as absolute)
        f.seek(A)
        data_a = f.read(8192)
        analyze_region(data_a, f"A=289996800 (relative as absolute)")
        
        # Read from address B (old dataStart + relative)
        f.seek(B)
        data_b = f.read(8192)
        analyze_region(data_b, f"B=293968800 (old dataStart 3972000 + relative)")
        
        # Read from address C (authoritative dataStart + relative)
        f.seek(C)
        data_c = f.read(8192)
        analyze_region(data_c, f"C=293993216 (authoritative dataStart 3996416 + relative)")
    
    # Determine which address the runtime is reading from
    # The runtime now uses kDataStart = 3996416, so it reads from C
    print("=" * 60)
    print("CONCLUSION")
    print("=" * 60)
    print(f"Runtime reads from address C={C}")
    print(f"Patch was applied at address B={B}")
    print(f"Delta = {C - B} bytes")
    print()
    print("If C has NaNs and B is finite, the patch missed the runtime address.")
    print("The correct patch target is C.")

if __name__ == "__main__":
    main()
