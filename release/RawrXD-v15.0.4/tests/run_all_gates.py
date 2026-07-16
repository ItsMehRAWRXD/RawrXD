#!/usr/bin/env python3
"""
Master Test Runner - Run All Validation Gates
Runs gates 1-20 and generates comprehensive report
"""

import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime


GATES = [
    ("Gate 1: GGUF Validation", "gate1_gguf_validation.py"),
    ("Gate 2: Quantization", "gate2_quantization_validation.py"),
    ("Gate 3: Embedding Lookup", "gate3_embedding_lookup.py"),
    ("Gate 4: GPU Inference", "gate4_gpu_inference.py"),
    ("Gate 5: Transformer Layer", "gate5_transformer_layer.py"),
    ("Gate 6: Multi-Layer", "gate6_multi_layer_fast.py"),
    ("Gate 7: Token Generation", "gate7_token_gen_simple.py"),
    ("Gate 8: KV Cache", "gate8_kv_cache.py"),
    ("Gate 9: Autoregressive Gen", "gate9_autoregressive_gen.py"),
    ("Gate 10: Sampling", "gate10_sampling.py"),
    ("Gate 11: Full Integration", "gate11_full_integration.py"),
    ("Gate 12: Streaming Load", "gate12_streaming_load.py"),
    ("Gate 13: Memory Mapped", "gate13_memory_mapped.py"),
    ("Gate 14: Progress Callbacks", "gate14_progress_callbacks.py"),
    ("Gate 15: Production Ready", "gate15_production_ready.py"),
    ("Gate 16: Multi-Model", "gate16_multi_model.py"),
    ("Gate 17: Error Recovery", "gate17_error_recovery.py"),
    ("Gate 18: Performance Bench", "gate18_performance_bench.py"),
    ("Gate 19: Integration Tests", "gate19_integration_tests.py"),
    ("Gate 20: Documentation", "gate20_documentation.py"),
]


def run_gate(name: str, script: str) -> tuple[bool, float, str]:
    """Run a single gate test"""
    print(f"\n{'='*60}")
    print(f"Running: {name}")
    print('='*60)
    
    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=Path(__file__).parent
        )
        elapsed = time.time() - start
        
        # Print output
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        
        success = result.returncode == 0
        status = "PASS" if success else "FAIL"
        
        print(f"\n[{name}] {status} in {elapsed:.2f}s")
        
        return success, elapsed, result.stdout
        
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"\n[{name}] TIMEOUT after {elapsed:.2f}s")
        return False, elapsed, "Timeout"
    except Exception as e:
        elapsed = time.time() - start
        print(f"\n[{name}] ERROR: {e}")
        return False, elapsed, str(e)


def main():
    """Run all gates"""
    print("="*60)
    print("RawrXD Master Test Runner")
    print("="*60)
    print(f"Started: {datetime.now().isoformat()}")
    print(f"Python: {sys.version}")
    print()
    
    results = []
    total_start = time.time()
    
    for name, script in GATES:
        success, elapsed, output = run_gate(name, script)
        results.append({
            'name': name,
            'script': script,
            'success': success,
            'elapsed': elapsed,
            'output': output
        })
    
    total_elapsed = time.time() - total_start
    
    # Generate report
    print("\n" + "="*60)
    print("FINAL REPORT")
    print("="*60)
    
    passed = sum(1 for r in results if r['success'])
    failed = sum(1 for r in results if not r['success'])
    
    print(f"\nTotal: {len(results)} gates")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Time: {total_elapsed:.2f}s")
    
    print("\n" + "-"*60)
    print("Results by Gate:")
    print("-"*60)
    
    for r in results:
        symbol = "✓" if r['success'] else "✗"
        status = "PASS" if r['success'] else "FAIL"
        print(f"{symbol} {r['name']:<30} {status:<6} {r['elapsed']:>6.2f}s")
    
    print("-"*60)
    
    if failed == 0:
        print("\n🎉 ALL GATES PASSED! 🎉")
        print("\nSystem is PRODUCTION READY")
        return 0
    else:
        print(f"\n⚠️  {failed} gate(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
