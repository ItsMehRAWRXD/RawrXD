#!/usr/bin/env python3
"""
Regression checker for RawrXD validation results
Compares current results against baseline and reports regressions
"""

import json
import sys
from pathlib import Path

# Performance regression thresholds
REGRESSION_THRESHOLDS = {
    'kernel': {
        'speedup': 0.8,  # Speedup must be >= 80% of baseline
        'max_abs_error': 1.5,  # Error can be 1.5x baseline
    },
    'inference': {
        'tokens_per_sec': 0.9,  # TPS must be >= 90% of baseline
        'load_time_ms': 1.2,  # Load time can be 1.2x baseline
    }
}

def load_results(path):
    """Load validation results from JSON"""
    with open(path, 'r') as f:
        return json.load(f)

def check_kernel_regression(current, baseline):
    """Check for kernel performance regressions"""
    regressions = []
    
    current_kernels = {k['name']: k for k in current.get('kernels', [])}
    baseline_kernels = {k['name']: k for k in baseline.get('kernels', [])}
    
    for name, base in baseline_kernels.items():
        if name not in current_kernels:
            regressions.append(f"Kernel {name}: Missing in current results")
            continue
            
        curr = current_kernels[name]
        
        # Check speedup regression
        if 'speedup' in curr and 'speedup' in base:
            speedup_ratio = curr['speedup'] / base['speedup']
            if speedup_ratio < REGRESSION_THRESHOLDS['kernel']['speedup']:
                regressions.append(
                    f"Kernel {name}: Speedup regression "
                    f"({curr['speedup']:.2f}x vs {base['speedup']:.2f}x)"
                )
        
        # Check error increase
        if 'max_abs_error' in curr and 'max_abs_error' in base:
            error_ratio = curr['max_abs_error'] / base['max_abs_error']
            if error_ratio > REGRESSION_THRESHOLDS['kernel']['max_abs_error']:
                regressions.append(
                    f"Kernel {name}: Error increased "
                    f"({curr['max_abs_error']:.6f} vs {base['max_abs_error']:.6f})"
                )
    
    return regressions

def check_inference_regression(current, baseline):
    """Check for inference performance regressions"""
    regressions = []
    
    curr_inf = current.get('inference', {})
    base_inf = baseline.get('inference', {})
    
    # Check tokens per second
    if 'tokens_per_sec' in curr_inf and 'tokens_per_sec' in base_inf:
        tps_ratio = curr_inf['tokens_per_sec'] / base_inf['tokens_per_sec']
        if tps_ratio < REGRESSION_THRESHOLDS['inference']['tokens_per_sec']:
            regressions.append(
                f"Inference TPS regression: "
                f"{curr_inf['tokens_per_sec']:.2f} vs {base_inf['tokens_per_sec']:.2f}"
            )
    
    # Check load time
    if 'load_time_ms' in curr_inf and 'load_time_ms' in base_inf:
        load_ratio = curr_inf['load_time_ms'] / base_inf['load_time_ms']
        if load_ratio > REGRESSION_THRESHOLDS['inference']['load_time_ms']:
            regressions.append(
                f"Load time regression: "
                f"{curr_inf['load_time_ms']:.2f}ms vs {base_inf['load_time_ms']:.2f}ms"
            )
    
    return regressions

def main():
    if len(sys.argv) != 3:
        print("Usage: check_regression.py <current.json> <baseline.json>")
        sys.exit(1)
    
    current_path = sys.argv[1]
    baseline_path = sys.argv[2]
    
    try:
        current = load_results(current_path)
        baseline = load_results(baseline_path)
    except Exception as e:
        print(f"Error loading results: {e}")
        sys.exit(1)
    
    print("Checking for regressions...")
    print()
    
    all_regressions = []
    all_regressions.extend(check_kernel_regression(current, baseline))
    all_regressions.extend(check_inference_regression(current, baseline))
    
    if all_regressions:
        print("REGRESSIONS DETECTED:")
        for r in all_regressions:
            print(f"  ✗ {r}")
        sys.exit(1)
    else:
        print("✓ No regressions detected")
        print()
        print("Performance Summary:")
        
        # Print summary
        curr_total = current.get('summary', {}).get('total_tests', 0)
        base_total = baseline.get('summary', {}).get('total_tests', 0)
        print(f"  Tests: {curr_total} (baseline: {base_total})")
        
        curr_time = current.get('summary', {}).get('total_time_ms', 0)
        base_time = baseline.get('summary', {}).get('total_time_ms', 0)
        if curr_time and base_time:
            time_diff = (curr_time - base_time) / base_time * 100
            print(f"  Time: {curr_time:.2f}ms (baseline: {base_time:.2f}ms, {time_diff:+.1f}%)")
        
        sys.exit(0)

if __name__ == '__main__':
    main()
