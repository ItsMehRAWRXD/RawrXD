#!/usr/bin/env python3
"""
Benchmark comparison tool for RawrXD validation results
Compares two benchmark runs and generates a comparison report
"""

import json
import sys
from pathlib import Path

def load_benchmark(path):
    """Load benchmark results from JSON"""
    with open(path, 'r') as f:
        return json.load(f)

def compare_kernels(current, baseline):
    """Compare kernel performance"""
    print("\n=== Kernel Performance Comparison ===\n")
    
    current_kernels = {k['name']: k for k in current.get('kernels', [])}
    baseline_kernels = {k['name']: k for k in baseline.get('kernels', [])}
    
    print(f"{'Kernel':<20} {'Speedup':>12} {'vs Baseline':>12} {'Status':>10}")
    print("-" * 60)
    
    for name in sorted(baseline_kernels.keys()):
        base = baseline_kernels[name]
        curr = current_kernels.get(name, {})
        
        if not curr:
            print(f"{name:<20} {'N/A':>12} {'N/A':>12} {'MISSING':>10}")
            continue
        
        base_speedup = base.get('speedup', 0)
        curr_speedup = curr.get('speedup', 0)
        
        if base_speedup > 0:
            ratio = curr_speedup / base_speedup
            change = f"{ratio:.2f}x"
            
            if ratio >= 1.0:
                status = "✓ IMPROVED"
            elif ratio >= 0.9:
                status = "~ OK"
            else:
                status = "✗ REGRESSION"
        else:
            change = "N/A"
            status = "?"
        
        print(f"{name:<20} {curr_speedup:>11.2f}x {change:>12} {status:>10}")

def compare_inference(current, baseline):
    """Compare inference performance"""
    print("\n=== Inference Performance Comparison ===\n")
    
    curr_inf = current.get('inference', {})
    base_inf = baseline.get('inference', {})
    
    metrics = [
        ('Load Time (ms)', 'load_time_ms', lambda c, b: f"{c:.2f} vs {b:.2f}"),
        ('Tokens/sec', 'tokens_per_sec', lambda c, b: f"{c:.2f} vs {b:.2f}"),
        ('First Token (ms)', 'first_token_ms', lambda c, b: f"{c:.2f} vs {b:.2f}"),
    ]
    
    print(f"{'Metric':<20} {'Current vs Baseline':>25} {'Change':>15}")
    print("-" * 65)
    
    for label, key, formatter in metrics:
        curr_val = curr_inf.get(key, 0)
        base_val = base_inf.get(key, 0)
        
        if curr_val and base_val:
            comparison = formatter(curr_val, base_val)
            
            if key == 'tokens_per_sec':
                change = ((curr_val - base_val) / base_val) * 100
            else:
                change = ((base_val - curr_val) / base_val) * 100
            
            change_str = f"{change:+.1f}%"
            print(f"{label:<20} {comparison:>25} {change_str:>15}")
        else:
            print(f"{label:<20} {'N/A':>25} {'N/A':>15}")

def generate_summary(current, baseline):
    """Generate overall summary"""
    print("\n=== Summary ===\n")
    
    curr_summary = current.get('summary', {})
    base_summary = baseline.get('summary', {})
    
    curr_total = curr_summary.get('total_tests', 0)
    base_total = base_summary.get('total_tests', 0)
    
    curr_passed = curr_summary.get('passed_tests', 0)
    base_passed = base_summary.get('passed_tests', 0)
    
    curr_time = curr_summary.get('total_time_ms', 0)
    base_time = base_summary.get('total_time_ms', 0)
    
    print(f"Tests: {curr_passed}/{curr_total} passed (baseline: {base_passed}/{base_total})")
    
    if curr_time and base_time:
        time_change = ((curr_time - base_time) / base_time) * 100
        print(f"Time: {curr_time:.2f}ms (baseline: {base_time:.2f}ms, {time_change:+.1f}%)")
    
    # Overall assessment
    if curr_passed >= base_passed:
        print("\n✓ Overall: PASSED (no regressions)")
        return 0
    else:
        print("\n✗ Overall: FAILED (regressions detected)")
        return 1

def main():
    if len(sys.argv) != 3:
        print("Usage: compare_benchmarks.py <current.json> <baseline.json>")
        sys.exit(1)
    
    current_path = sys.argv[1]
    baseline_path = sys.argv[2]
    
    try:
        current = load_benchmark(current_path)
        baseline = load_benchmark(baseline_path)
    except Exception as e:
        print(f"Error loading results: {e}")
        sys.exit(1)
    
    print(f"Comparing:")
    print(f"  Current:  {current_path}")
    print(f"  Baseline: {baseline_path}")
    
    compare_kernels(current, baseline)
    compare_inference(current, baseline)
    exit_code = generate_summary(current, baseline)
    
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
