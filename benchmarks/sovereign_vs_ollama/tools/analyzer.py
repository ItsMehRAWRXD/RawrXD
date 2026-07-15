#!/usr/bin/env python3
"""
RawrXD Benchmark Suite - Result Analyzer
Statistical analysis and visualization of benchmark results

Copyright (c) 2026 RawrXD Team
"""

import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import click
import numpy as np
from scipy import stats


@dataclass
class StatisticalSummary:
    """Statistical summary of benchmark results"""
    count: int
    mean: float
    median: float
    std_dev: float
    min_val: float
    max_val: float
    p50: float
    p90: float
    p95: float
    p99: float
    variance: float
    skewness: float
    kurtosis: float
    confidence_interval_95: Tuple[float, float]


class BenchmarkAnalyzer:
    """Analyzes benchmark results"""
    
    def __init__(self, results_dir: Path):
        self.results_dir = results_dir
    
    def load_results(self, pattern: str = "*.json") -> List[Dict]:
        """Load benchmark results from files"""
        results = []
        for file in self.results_dir.glob(pattern):
            try:
                with open(file) as f:
                    data = json.load(f)
                    data["_source_file"] = file.name
                    results.append(data)
            except Exception as e:
                print(f"Warning: Failed to load {file}: {e}", file=sys.stderr)
        return results
    
    def calculate_statistics(self, values: List[float]) -> StatisticalSummary:
        """Calculate statistical summary"""
        if not values:
            raise ValueError("Empty value list")
        
        arr = np.array(values)
        
        # Calculate confidence interval
        confidence = 0.95
        n = len(arr)
        mean = np.mean(arr)
        std_err = stats.sem(arr)
        h = std_err * stats.t.ppf((1 + confidence) / 2, n - 1)
        ci = (mean - h, mean + h)
        
        return StatisticalSummary(
            count=len(values),
            mean=float(np.mean(arr)),
            median=float(np.median(arr)),
            std_dev=float(np.std(arr)),
            min_val=float(np.min(arr)),
            max_val=float(np.max(arr)),
            p50=float(np.percentile(arr, 50)),
            p90=float(np.percentile(arr, 90)),
            p95=float(np.percentile(arr, 95)),
            p99=float(np.percentile(arr, 99)),
            variance=float(np.var(arr)),
            skewness=float(stats.skew(arr)),
            kurtosis=float(stats.kurtosis(arr)),
            confidence_interval_95=ci
        )
    
    def compare_benchmarks(
        self,
        baseline: List[float],
        current: List[float]
    ) -> Dict:
        """Compare two benchmark runs"""
        # Welch's t-test
        t_stat, p_value = stats.ttest_ind(baseline, current, equal_var=False)
        
        # Effect size (Cohen's d)
        mean_diff = np.mean(current) - np.mean(baseline)
        pooled_std = math.sqrt(
            (np.var(baseline) + np.var(current)) / 2
        )
        cohens_d = mean_diff / pooled_std if pooled_std > 0 else 0
        
        # Percentage change
        pct_change = (np.mean(current) - np.mean(baseline)) / np.mean(baseline) * 100
        
        # Determine significance
        is_significant = p_value < 0.05
        
        return {
            "t_statistic": float(t_stat),
            "p_value": float(p_value),
            "cohens_d": float(cohens_d),
            "mean_difference": float(mean_diff),
            "percent_change": float(pct_change),
            "is_significant": is_significant,
            "interpretation": self._interpret_effect_size(cohens_d)
        }
    
    def _interpret_effect_size(self, d: float) -> str:
        """Interpret Cohen's d effect size"""
        abs_d = abs(d)
        if abs_d < 0.2:
            return "negligible"
        elif abs_d < 0.5:
            return "small"
        elif abs_d < 0.8:
            return "medium"
        else:
            return "large"
    
    def detect_regression(
        self,
        current: List[float],
        baseline: List[float],
        threshold_percent: float = 10.0
    ) -> Dict:
        """Detect performance regression"""
        current_mean = np.mean(current)
        baseline_mean = np.mean(baseline)
        
        regression_percent = (
            (current_mean - baseline_mean) / baseline_mean * 100
        )
        
        is_regression = regression_percent > threshold_percent
        
        return {
            "is_regression": is_regression,
            "regression_percent": float(regression_percent),
            "threshold_percent": threshold_percent,
            "baseline_mean": float(baseline_mean),
            "current_mean": float(current_mean),
            "severity": (
                "critical" if regression_percent > 50 else
                "high" if regression_percent > 20 else
                "medium" if regression_percent > 10 else
                "low"
            ) if is_regression else "none"
        }
    
    def generate_report(self, results: List[Dict]) -> str:
        """Generate text report"""
        lines = []
        lines.append("=" * 70)
        lines.append("RawrXD Benchmark Analysis Report")
        lines.append("=" * 70)
        lines.append("")
        
        # Extract latency data
        latencies = []
        for result in results:
            if "latencies" in result:
                latencies.extend(result["latencies"])
            elif "latency_samples" in result:
                latencies.extend(result["latency_samples"])
        
        if latencies:
            stats = self.calculate_statistics(latencies)
            
            lines.append("Latency Statistics:")
            lines.append("-" * 70)
            lines.append(f"  Count:              {stats.count}")
            lines.append(f"  Mean:               {stats.mean:.2f} ms")
            lines.append(f"  Median:             {stats.median:.2f} ms")
            lines.append(f"  Std Dev:            {stats.std_dev:.2f} ms")
            lines.append(f"  Min:                {stats.min_val:.2f} ms")
            lines.append(f"  Max:                {stats.max_val:.2f} ms")
            lines.append("")
            lines.append("Percentiles:")
            lines.append(f"  P50:                {stats.p50:.2f} ms")
            lines.append(f"  P90:                {stats.p90:.2f} ms")
            lines.append(f"  P95:                {stats.p95:.2f} ms")
            lines.append(f"  P99:                {stats.p99:.2f} ms")
            lines.append("")
            lines.append(f"95% Confidence Interval: [{stats.confidence_interval_95[0]:.2f}, "
                        f"{stats.confidence_interval_95[1]:.2f}] ms")
            lines.append("")
            lines.append("Distribution Shape:")
            lines.append(f"  Skewness:           {stats.skewness:.3f}")
            lines.append(f"  Kurtosis:           {stats.kurtosis:.3f}")
        
        lines.append("")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def export_csv(self, results: List[Dict], output: Path):
        """Export results to CSV"""
        import csv
        
        with open(output, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'backend', 'model', 'latency_ms',
                'throughput_rps', 'success_rate', 'iterations'
            ])
            
            for result in results:
                writer.writerow([
                    result.get('timestamp', ''),
                    result.get('backend', ''),
                    result.get('model', ''),
                    result.get('avg_latency_ms', ''),
                    result.get('throughput_rps', ''),
                    result.get('success_rate', ''),
                    result.get('iterations', '')
                ])


@click.group()
def cli():
    """RawrXD Benchmark Result Analyzer"""
    pass


@cli.command()
@click.option('--results-dir', '-d', default='./results', help='Results directory')
@click.option('--pattern', '-p', default='*.json', help='File pattern')
def summary(results_dir: str, pattern: str):
    """Generate summary statistics"""
    analyzer = BenchmarkAnalyzer(Path(results_dir))
    results = analyzer.load_results(pattern)
    
    if not results:
        click.echo("No results found", err=True)
        return
    
    click.echo(f"\nLoaded {len(results)} result files\n")
    
    # Extract and analyze latencies
    latencies = []
    for result in results:
        if "latencies" in result:
            latencies.extend(result["latencies"])
        elif "latency_samples" in result:
            latencies.extend(result["latency_samples"])
    
    if latencies:
        stats = analyzer.calculate_statistics(latencies)
        
        click.echo("Latency Statistics:")
        click.echo("-" * 50)
        click.echo(f"  Count:    {stats.count}")
        click.echo(f"  Mean:     {stats.mean:.2f} ms")
        click.echo(f"  Median:   {stats.median:.2f} ms")
        click.echo(f"  Std Dev:  {stats.std_dev:.2f} ms")
        click.echo(f"  Min:      {stats.min_val:.2f} ms")
        click.echo(f"  Max:      {stats.max_val:.2f} ms")
        click.echo("")
        click.echo("Percentiles:")
        click.echo(f"  P50:      {stats.p50:.2f} ms")
        click.echo(f"  P90:      {stats.p90:.2f} ms")
        click.echo(f"  P95:      {stats.p95:.2f} ms")
        click.echo(f"  P99:      {stats.p99:.2f} ms")


@cli.command()
@click.option('--baseline', '-b', required=True, help='Baseline results file')
@click.option('--current', '-c', required=True, help='Current results file')
def compare(baseline: str, current: str):
    """Compare two benchmark runs"""
    analyzer = BenchmarkAnalyzer(Path("."))
    
    # Load results
    with open(baseline) as f:
        baseline_data = json.load(f)
    with open(current) as f:
        current_data = json.load(f)
    
    # Extract latencies
    baseline_latencies = baseline_data.get("latencies", [])
    current_latencies = current_data.get("latencies", [])
    
    if not baseline_latencies or not current_latencies:
        click.echo("No latency data found", err=True)
        return
    
    # Compare
    comparison = analyzer.compare_benchmarks(baseline_latencies, current_latencies)
    
    click.echo("\nBenchmark Comparison:")
    click.echo("=" * 50)
    click.echo(f"Mean Difference:      {comparison['mean_difference']:.2f} ms")
    click.echo(f"Percent Change:       {comparison['percent_change']:.2f}%")
    click.echo(f"T-Statistic:          {comparison['t_statistic']:.4f}")
    click.echo(f"P-Value:              {comparison['p_value']:.6f}")
    click.echo(f"Cohen's d:            {comparison['cohens_d']:.4f}")
    click.echo(f"Effect Size:          {comparison['interpretation']}")
    click.echo(f"Statistically Significant: {'Yes' if comparison['is_significant'] else 'No'}")


@cli.command()
@click.option('--results-dir', '-d', default='./results', help='Results directory')
@click.option('--output', '-o', default='report.txt', help='Output file')
def report(results_dir: str, output: str):
    """Generate analysis report"""
    analyzer = BenchmarkAnalyzer(Path(results_dir))
    results = analyzer.load_results()
    
    report_text = analyzer.generate_report(results)
    
    with open(output, 'w') as f:
        f.write(report_text)
    
    click.echo(f"Report saved to: {output}")
    click.echo("\n" + report_text)


@cli.command()
@click.option('--results-dir', '-d', default='./results', help='Results directory')
@click.option('--output', '-o', default='results.csv', help='Output CSV file')
def export(results_dir: str, output: str):
    """Export results to CSV"""
    analyzer = BenchmarkAnalyzer(Path(results_dir))
    results = analyzer.load_results()
    
    analyzer.export_csv(results, Path(output))
    
    click.echo(f"Exported {len(results)} results to: {output}")


if __name__ == "__main__":
    cli()
