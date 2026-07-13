#!/usr/bin/env python3
"""
Check benchmark results against v1.0.0 baseline for performance regressions.

Usage:
    python check_performance_regression.py benchmark_results.json

Exit codes:
    0 - No regressions found
    1 - Performance regressions detected
    2 - Error processing results
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, Any, Tuple


def load_baseline() -> Dict[str, Any]:
    """Load the v1.0.0 performance baseline."""
    baseline_path = Path(__file__).parent.parent / "benchmarks" / "BASELINE_v1.0.0.json"
    
    if not baseline_path.exists():
        print(f"Error: Baseline file not found: {baseline_path}")
        sys.exit(2)
    
    with open(baseline_path) as f:
        return json.load(f)


def load_results(results_path: Path) -> Dict[str, Any]:
    """Load benchmark results to compare."""
    if not results_path.exists():
        print(f"Error: Results file not found: {results_path}")
        sys.exit(2)
    
    with open(results_path) as f:
        return json.load(f)


def compare_throughput(baseline: Dict, current: Dict) -> Tuple[bool, list]:
    """Compare throughput metrics."""
    regressions = []
    
    baseline_results = baseline.get("benchmarks", {}).get("inference_throughput", {}).get("results", {})
    current_results = current.get("benchmarks", {}).get("inference_throughput", {}).get("results", {})
    
    thresholds = baseline.get("regression_thresholds", {}).get("throughput", {})
    warning_threshold = thresholds.get("warning", 0.95)
    critical_threshold = thresholds.get("critical", 0.90)
    
    for model, batches in baseline_results.items():
        if model not in current_results:
            regressions.append({
                "metric": f"throughput.{model}",
                "status": "missing",
                "message": f"Model {model} not found in current results"
            })
            continue
        
        for batch, baseline_value in batches.items():
            current_value = current_results[model].get(batch)
            if current_value is None:
                continue
            
            ratio = current_value / baseline_value
            
            if ratio < critical_threshold:
                regressions.append({
                    "metric": f"throughput.{model}.{batch}",
                    "status": "critical",
                    "baseline": baseline_value,
                    "current": current_value,
                    "ratio": ratio,
                    "message": f"CRITICAL: {model} batch {batch} throughput dropped by {(1-ratio)*100:.1f}%"
                })
            elif ratio < warning_threshold:
                regressions.append({
                    "metric": f"throughput.{model}.{batch}",
                    "status": "warning",
                    "baseline": baseline_value,
                    "current": current_value,
                    "ratio": ratio,
                    "message": f"WARNING: {model} batch {batch} throughput dropped by {(1-ratio)*100:.1f}%"
                })
    
    return len(regressions) == 0, regressions


def compare_latency(baseline: Dict, current: Dict) -> Tuple[bool, list]:
    """Compare latency metrics."""
    regressions = []
    
    baseline_results = baseline.get("benchmarks", {}).get("latency", {}).get("results", {})
    current_results = current.get("benchmarks", {}).get("latency", {}).get("results", {})
    
    thresholds = baseline.get("regression_thresholds", {}).get("latency", {})
    warning_threshold = thresholds.get("warning", 1.10)
    critical_threshold = thresholds.get("critical", 1.20)
    
    for metric, percentiles in baseline_results.items():
        if metric not in current_results:
            continue
        
        for percentile, baseline_value in percentiles.items():
            current_value = current_results[metric].get(percentile)
            if current_value is None:
                continue
            
            ratio = current_value / baseline_value
            
            if ratio > critical_threshold:
                regressions.append({
                    "metric": f"latency.{metric}.{percentile}",
                    "status": "critical",
                    "baseline": baseline_value,
                    "current": current_value,
                    "ratio": ratio,
                    "message": f"CRITICAL: {metric} {percentile} latency increased by {(ratio-1)*100:.1f}%"
                })
            elif ratio > warning_threshold:
                regressions.append({
                    "metric": f"latency.{metric}.{percentile}",
                    "status": "warning",
                    "baseline": baseline_value,
                    "current": current_value,
                    "ratio": ratio,
                    "message": f"WARNING: {metric} {percentile} latency increased by {(ratio-1)*100:.1f}%"
                })
    
    return len(regressions) == 0, regressions


def compare_memory(baseline: Dict, current: Dict) -> Tuple[bool, list]:
    """Compare memory efficiency metrics."""
    regressions = []
    
    baseline_results = baseline.get("benchmarks", {}).get("memory_efficiency", {}).get("results", {})
    current_results = current.get("benchmarks", {}).get("memory_efficiency", {}).get("results", {})
    
    thresholds = baseline.get("regression_thresholds", {}).get("memory", {})
    warning_threshold = thresholds.get("warning", 1.10)
    critical_threshold = thresholds.get("critical", 1.25)
    
    for model, metrics in baseline_results.items():
        if model not in current_results:
            continue
        
        baseline_efficiency = metrics.get("efficiency", 0)
        current_efficiency = current_results[model].get("efficiency", 0)
        
        if baseline_efficiency > 0 and current_efficiency > 0:
            ratio = current_efficiency / baseline_efficiency
            
            if ratio < critical_threshold:
                regressions.append({
                    "metric": f"memory_efficiency.{model}",
                    "status": "critical",
                    "baseline": baseline_efficiency,
                    "current": current_efficiency,
                    "ratio": ratio,
                    "message": f"CRITICAL: {model} memory efficiency dropped by {(1-ratio)*100:.1f}%"
                })
            elif ratio < warning_threshold:
                regressions.append({
                    "metric": f"memory_efficiency.{model}",
                    "status": "warning",
                    "baseline": baseline_efficiency,
                    "current": current_efficiency,
                    "ratio": ratio,
                    "message": f"WARNING: {model} memory efficiency dropped by {(1-ratio)*100:.1f}%"
                })
    
    return len(regressions) == 0, regressions


def generate_report(baseline: Dict, current: Dict, regressions: list) -> str:
    """Generate a markdown report."""
    lines = [
        "# Performance Regression Report",
        "",
        f"**Baseline**: RawrXD v{baseline.get('version', 'unknown')}",
        f"**Current**: {current.get('version', 'unknown')}",
        f"**Date**: {current.get('date', 'unknown')}",
        "",
        "## Summary",
        "",
    ]
    
    if not regressions:
        lines.append("✅ **No performance regressions detected**")
    else:
        critical = [r for r in regressions if r["status"] == "critical"]
        warnings = [r for r in regressions if r["status"] == "warning"]
        
        lines.append(f"❌ **{len(critical)} critical** and **{len(warnings)} warning** regressions found")
        lines.append("")
        lines.append("## Details")
        lines.append("")
        
        if critical:
            lines.append("### Critical Regressions")
            lines.append("")
            for r in critical:
                lines.append(f"- {r['message']}")
            lines.append("")
        
        if warnings:
            lines.append("### Warnings")
            lines.append("")
            for r in warnings:
                lines.append(f"- {r['message']}")
            lines.append("")
    
    lines.append("## System Information")
    lines.append("")
    lines.append("### Baseline")
    lines.append(f"- CPU: {baseline.get('system_info', {}).get('cpu', 'unknown')}")
    lines.append(f"- GPU: {baseline.get('system_info', {}).get('gpu', 'unknown')}")
    lines.append(f"- Memory: {baseline.get('system_info', {}).get('memory', 'unknown')}")
    lines.append("")
    lines.append("### Current")
    lines.append(f"- CPU: {current.get('system_info', {}).get('cpu', 'unknown')}")
    lines.append(f"- GPU: {current.get('system_info', {}).get('gpu', 'unknown')}")
    lines.append(f"- Memory: {current.get('system_info', {}).get('memory', 'unknown')}")
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Check benchmark results against v1.0.0 baseline")
    parser.add_argument("results", type=Path, help="Path to benchmark results JSON")
    parser.add_argument("--output", "-o", type=Path, help="Output report file (default: stdout)")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="markdown",
                        help="Output format")
    
    args = parser.parse_args()
    
    # Load data
    baseline = load_baseline()
    current = load_results(args.results)
    
    # Compare metrics
    all_regressions = []
    
    _, throughput_regs = compare_throughput(baseline, current)
    all_regressions.extend(throughput_regs)
    
    _, latency_regs = compare_latency(baseline, current)
    all_regressions.extend(latency_regs)
    
    _, memory_regs = compare_memory(baseline, current)
    all_regressions.extend(memory_regs)
    
    # Generate report
    if args.format == "markdown":
        report = generate_report(baseline, current, all_regressions)
    elif args.format == "json":
        report = json.dumps({
            "regressions": all_regressions,
            "has_regressions": len(all_regressions) > 0,
            "baseline_version": baseline.get("version"),
            "current_version": current.get("version")
        }, indent=2)
    else:
        # Text format
        lines = ["Performance Regression Check", "=" * 40]
        if all_regressions:
            lines.append(f"\nFound {len(all_regressions)} regressions:")
            for r in all_regressions:
                lines.append(f"  [{r['status'].upper()}] {r['message']}")
        else:
            lines.append("\nNo regressions found.")
        report = "\n".join(lines)
    
    # Output report
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"Report written to: {args.output}")
    else:
        print(report)
    
    # Exit with appropriate code
    critical_count = len([r for r in all_regressions if r["status"] == "critical"])
    if critical_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
