#!/usr/bin/env python3
"""
Compare benchmark results between two runs.
Exits with error if performance regression exceeds threshold.
"""

import json
import sys
import argparse
from pathlib import Path


def load_benchmarks(path: Path) -> dict:
    """Load benchmark results from JSON file."""
    with open(path) as f:
        return json.load(f)


def compare_benchmarks(baseline: dict, current: dict, threshold: float = 1.1) -> bool:
    """
    Compare benchmark results.
    Returns True if no regressions found.
    """
    baseline_tests = {b['name']: b for b in baseline.get('benchmarks', [])}
    current_tests = {b['name']: b for b in current.get('benchmarks', [])}
    
    regressions = []
    improvements = []
    missing = []
    new_tests = []
    
    # Check for regressions and improvements
    for name, current_test in current_tests.items():
        if name not in baseline_tests:
            new_tests.append(name)
            continue
        
        baseline_test = baseline_tests[name]
        baseline_time = baseline_test.get('real_time', baseline_test.get('cpu_time', 0))
        current_time = current_test.get('real_time', current_test.get('cpu_time', 0))
        
        if baseline_time == 0:
            continue
        
        ratio = current_time / baseline_time
        
        if ratio > threshold:
            regressions.append({
                'name': name,
                'baseline': baseline_time,
                'current': current_time,
                'ratio': ratio
            })
        elif ratio < 1 / threshold:
            improvements.append({
                'name': name,
                'baseline': baseline_time,
                'current': current_time,
                'ratio': ratio
            })
    
    # Check for missing tests
    for name in baseline_tests:
        if name not in current_tests:
            missing.append(name)
    
    # Print results
    print("## Benchmark Comparison Results\n")
    
    if new_tests:
        print(f"### 🆕 New Tests ({len(new_tests)})")
        for name in new_tests:
            print(f"  - {name}")
        print()
    
    if missing:
        print(f"### ⚠️ Missing Tests ({len(missing)})")
        for name in missing:
            print(f"  - {name}")
        print()
    
    if improvements:
        print(f"### 🚀 Performance Improvements ({len(improvements)})")
        for imp in improvements:
            improvement_pct = (1 - imp['ratio']) * 100
            print(f"  - {imp['name']}: {improvement_pct:.1f}% faster")
        print()
    
    if regressions:
        print(f"### ❌ Performance Regressions ({len(regressions)})")
        for reg in regressions:
            regression_pct = (reg['ratio'] - 1) * 100
            print(f"  - {reg['name']}: +{regression_pct:.1f}% slower")
            print(f"    Baseline: {reg['baseline']:.2f}ms")
            print(f"    Current:  {reg['current']:.2f}ms")
        print()
        return False
    
    print("### ✅ No Performance Regressions Found")
    return True


def main():
    parser = argparse.ArgumentParser(description='Compare benchmark results')
    parser.add_argument('baseline', type=Path, help='Baseline benchmark results JSON')
    parser.add_argument('current', type=Path, help='Current benchmark results JSON')
    parser.add_argument('--threshold', type=float, default=1.1,
                        help='Regression threshold (default: 1.1 = 10%%)')
    
    args = parser.parse_args()
    
    if not args.baseline.exists():
        print(f"Error: Baseline file not found: {args.baseline}")
        sys.exit(1)
    
    if not args.current.exists():
        print(f"Error: Current file not found: {args.current}")
        sys.exit(1)
    
    baseline = load_benchmarks(args.baseline)
    current = load_benchmarks(args.current)
    
    success = compare_benchmarks(baseline, current, args.threshold)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
