#!/usr/bin/env python3
# compare_fingerprints.py — Golden Master regression detection
# Usage: python compare_fingerprints.py --baseline baseline.json --current current.json --threshold 10

import json
import sys
import argparse
from pathlib import Path

def hamming_distance(a: int, b: int) -> int:
    """Calculate Hamming distance between two 64-bit integers."""
    x = a ^ b
    dist = 0
    while x:
        dist += x & 1
        x >>= 1
    return dist

def load_fingerprints(path: Path) -> dict:
    with open(path, 'r') as f:
        return json.load(f)

def compare_fingerprints(baseline: dict, current: dict, threshold: int) -> dict:
    results = {
        'tests_compared': 0,
        'identical': 0,
        'acceptable_variance': 0,
        'regressions': 0,
        'details': []
    }
    
    for test_name in baseline:
        if test_name not in current:
            results['details'].append({
                'test': test_name,
                'status': 'MISSING',
                'message': 'Test not found in current run'
            })
            results['regressions'] += 1
            continue
        
        base_fp = baseline[test_name]
        curr_fp = current[test_name]
        
        # Compare 128-bit fingerprint (low + high)
        dist_low = hamming_distance(base_fp['low'], curr_fp['low'])
        dist_high = hamming_distance(base_fp['high'], curr_fp['high'])
        total_dist = dist_low + dist_high
        
        results['tests_compared'] += 1
        
        if total_dist == 0:
            results['identical'] += 1
            status = 'IDENTICAL'
        elif total_dist <= threshold:
            results['acceptable_variance'] += 1
            status = 'ACCEPTABLE'
        else:
            results['regressions'] += 1
            status = 'REGRESSION'
        
        results['details'].append({
            'test': test_name,
            'status': status,
            'hamming_distance': total_dist,
            'threshold': threshold,
            'low_dist': dist_low,
            'high_dist': dist_high
        })
    
    return results

def main():
    parser = argparse.ArgumentParser(description='Compare Golden Master fingerprints')
    parser.add_argument('--baseline', required=True, help='Baseline fingerprint JSON')
    parser.add_argument('--current', required=True, help='Current fingerprint JSON')
    parser.add_argument('--threshold', type=int, default=10, help='Hamming distance threshold')
    parser.add_argument('--output', default='fingerprint_report.json', help='Output report path')
    args = parser.parse_args()
    
    baseline = load_fingerprints(Path(args.baseline))
    current = load_fingerprints(Path(args.current))
    
    results = compare_fingerprints(baseline, current, args.threshold)
    
    # Print summary
    print("=" * 60)
    print("  GOLDEN MASTER FINGERPRINT REPORT")
    print("=" * 60)
    print(f"  Tests Compared:      {results['tests_compared']}")
    print(f"  Identical:           {results['identical']}")
    print(f"  Acceptable Variance: {results['acceptable_variance']}")
    print(f"  Regressions:         {results['regressions']}")
    print(f"  Threshold:           {args.threshold} bits")
    print("=" * 60)
    
    # Print regressions
    if results['regressions'] > 0:
        print("\n  REGRESSIONS DETECTED:")
        for detail in results['details']:
            if detail['status'] == 'REGRESSION':
                print(f"    ❌ {detail['test']}: {detail['hamming_distance']} bits")
        print()
        sys.exit(1)
    else:
        print("\n  ✅ ALL TESTS WITHIN THRESHOLD")
        print()
        sys.exit(0)
    
    # Write report
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"  Report written to: {args.output}")

if __name__ == '__main__':
    main()
