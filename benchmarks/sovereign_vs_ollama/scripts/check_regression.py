#!/usr/bin/env python3
"""
check_regression.py
Batch 6: Performance Regression Detection Script
Compares current benchmark results against baseline and detects regressions
"""

import argparse
import json
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import math


@dataclass
class MetricThreshold:
    """Threshold configuration for a metric"""
    name: str
    direction: str  # "lower_is_better" or "higher_is_better"
    warning_threshold: float  # Percentage change for warning
    critical_threshold: float  # Percentage change for critical/error


# Default thresholds for different metrics
DEFAULT_THRESHOLDS = [
    MetricThreshold("latency_ms", "lower_is_better", 10.0, 20.0),
    MetricThreshold("throughput_tps", "higher_is_better", -10.0, -20.0),
    MetricThreshold("ttft_ms", "lower_is_better", 15.0, 30.0),
    MetricThreshold("error_rate", "lower_is_better", 50.0, 100.0),  # Relative to baseline
    MetricThreshold("memory_mb", "lower_is_better", 20.0, 50.0),
    MetricThreshold("cpu_percent", "lower_is_better", 25.0, 50.0),
]


class RegressionChecker:
    """Checks benchmark results for performance regressions"""
    
    def __init__(self, thresholds: Optional[List[MetricThreshold]] = None):
        self.thresholds = thresholds or DEFAULT_THRESHOLDS
        self.threshold_map = {t.name: t for t in self.thresholds}
        self.violations: List[Dict] = []
        self.warnings: List[Dict] = []
    
    def load_results(self, filepath: str) -> Dict:
        """Load benchmark results from JSON file"""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def calculate_change(self, current: float, baseline: float) -> float:
        """Calculate percentage change between current and baseline"""
        if baseline == 0:
            return float('inf') if current > 0 else 0.0
        return ((current - baseline) / baseline) * 100.0
    
    def check_metric(self, benchmark: str, metric: str, 
                     current: float, baseline: float) -> Tuple[str, float]:
        """
        Check a single metric for regression
        Returns: (status, change_percent)
        """
        change = self.calculate_change(current, baseline)
        
        threshold = self.threshold_map.get(metric)
        if not threshold:
            return "ok", change
        
        # Determine if change is in the bad direction
        is_regression = False
        if threshold.direction == "lower_is_better":
            is_regression = change > threshold.warning_threshold
        else:  # higher_is_better
            is_regression = change < threshold.warning_threshold
        
        if not is_regression:
            return "ok", change
        
        # Check severity
        is_critical = False
        if threshold.direction == "lower_is_better":
            is_critical = change > threshold.critical_threshold
        else:
            is_critical = change < threshold.critical_threshold
        
        return ("critical" if is_critical else "warning"), change
    
    def check_benchmark(self, benchmark: str, current_data: Dict, 
                       baseline_data: Dict) -> Dict:
        """Check all metrics for a single benchmark"""
        results = {
            "benchmark": benchmark,
            "metrics": {},
            "status": "ok",
            "violations": [],
            "warnings": []
        }
        
        # Get metrics to check
        metrics_to_check = set(current_data.keys()) & set(baseline_data.keys())
        
        for metric in metrics_to_check:
            if not isinstance(current_data[metric], (int, float)):
                continue
                
            status, change = self.check_metric(
                benchmark, metric,
                current_data[metric], baseline_data[metric]
            )
            
            results["metrics"][metric] = {
                "current": current_data[metric],
                "baseline": baseline_data[metric],
                "change_percent": change,
                "status": status
            }
            
            if status == "critical":
                results["status"] = "critical"
                results["violations"].append({
                    "metric": metric,
                    "change": change,
                    "current": current_data[metric],
                    "baseline": baseline_data[metric]
                })
            elif status == "warning":
                if results["status"] == "ok":
                    results["status"] = "warning"
                results["warnings"].append({
                    "metric": metric,
                    "change": change,
                    "current": current_data[metric],
                    "baseline": baseline_data[metric]
                })
        
        return results
    
    def check_all(self, current_results: Dict, baseline_results: Dict) -> Dict:
        """Check all benchmarks for regressions"""
        report = {
            "summary": {
                "total_benchmarks": 0,
                "ok": 0,
                "warnings": 0,
                "critical": 0
            },
            "benchmarks": []
        }
        
        # Get all benchmarks from current results
        current_benchmarks = current_results.get("benchmarks", [])
        baseline_benchmarks = {b["name"]: b for b in baseline_results.get("benchmarks", [])}
        
        for current_bench in current_benchmarks:
            bench_name = current_bench.get("name")
            if not bench_name:
                continue
            
            baseline_bench = baseline_benchmarks.get(bench_name)
            if not baseline_bench:
                print(f"Warning: No baseline for benchmark '{bench_name}'")
                continue
            
            result = self.check_benchmark(
                bench_name,
                current_bench.get("metrics", {}),
                baseline_bench.get("metrics", {})
            )
            
            report["benchmarks"].append(result)
            report["summary"]["total_benchmarks"] += 1
            
            if result["status"] == "ok":
                report["summary"]["ok"] += 1
            elif result["status"] == "warning":
                report["summary"]["warnings"] += 1
            else:  # critical
                report["summary"]["critical"] += 1
        
        return report
    
    def print_report(self, report: Dict, verbose: bool = False):
        """Print regression report to console"""
        summary = report["summary"]
        
        print("\n" + "=" * 70)
        print("REGRESSION CHECK REPORT")
        print("=" * 70)
        
        print(f"\nTotal Benchmarks: {summary['total_benchmarks']}")
        print(f"  ✓ OK:       {summary['ok']}")
        print(f"  ⚠ Warning:  {summary['warnings']}")
        print(f"  ✗ Critical: {summary['critical']}")
        
        # Print critical violations
        critical_benches = [b for b in report["benchmarks"] if b["status"] == "critical"]
        if critical_benches:
            print("\n" + "-" * 70)
            print("CRITICAL REGRESSIONS")
            print("-" * 70)
            for bench in critical_benches:
                print(f"\n{bench['benchmark']}:")
                for v in bench["violations"]:
                    print(f"  {v['metric']}: {v['change']:+.1f}% "
                          f"({v['baseline']:.2f} → {v['current']:.2f})")
        
        # Print warnings
        warning_benches = [b for b in report["benchmarks"] if b["status"] == "warning"]
        if warning_benches:
            print("\n" + "-" * 70)
            print("WARNINGS")
            print("-" * 70)
            for bench in warning_benches:
                print(f"\n{bench['benchmark']}:")
                for w in bench["warnings"]:
                    print(f"  {w['metric']}: {w['change']:+.1f}% "
                          f"({w['baseline']:.2f} → {w['current']:.2f})")
        
        if verbose:
            print("\n" + "-" * 70)
            print("ALL METRICS")
            print("-" * 70)
            for bench in report["benchmarks"]:
                print(f"\n{bench['benchmark']} [{bench['status']}]:")
                for metric, data in bench["metrics"].items():
                    symbol = "✓" if data["status"] == "ok" else "⚠" if data["status"] == "warning" else "✗"
                    print(f"  {symbol} {metric}: {data['change_percent']:+.1f}%")
        
        print("\n" + "=" * 70)
        
        # Return exit code based on status
        if summary["critical"] > 0:
            return 2
        elif summary["warnings"] > 0:
            return 1
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Check benchmark results for performance regressions"
    )
    parser.add_argument(
        "--current", "-c",
        required=True,
        help="Path to current benchmark results JSON"
    )
    parser.add_argument(
        "--baseline", "-b",
        required=True,
        help="Path to baseline benchmark results JSON"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for detailed report (JSON)"
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=10.0,
        help="Regression threshold percentage (default: 10.0)"
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with non-zero code if regressions detected"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed metric information"
    )
    
    args = parser.parse_args()
    
    # Validate input files
    if not Path(args.current).exists():
        print(f"Error: Current results file not found: {args.current}", file=sys.stderr)
        sys.exit(1)
    
    if not Path(args.baseline).exists():
        print(f"Error: Baseline results file not found: {args.baseline}", file=sys.stderr)
        sys.exit(1)
    
    # Create checker with custom threshold
    thresholds = [
        MetricThreshold("latency_ms", "lower_is_better", args.threshold, args.threshold * 2),
        MetricThreshold("throughput_tps", "higher_is_better", -args.threshold, -args.threshold * 2),
        MetricThreshold("ttft_ms", "lower_is_better", args.threshold * 1.5, args.threshold * 3),
        MetricThreshold("error_rate", "lower_is_better", args.threshold * 5, args.threshold * 10),
    ]
    
    checker = RegressionChecker(thresholds)
    
    # Load results
    try:
        current = checker.load_results(args.current)
        baseline = checker.load_results(args.baseline)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Check for regressions
    report = checker.check_all(current, baseline)
    
    # Print report
    exit_code = checker.print_report(report, args.verbose)
    
    # Save detailed report if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nDetailed report saved to: {args.output}")
    
    # Exit with appropriate code
    if args.fail_on_regression and exit_code > 0:
        sys.exit(exit_code)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
