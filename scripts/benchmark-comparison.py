#!/usr/bin/env python3
#=============================================================================
# benchmark-comparison.py
# Compares benchmark results against baselines and generates reports
#=============================================================================

import json
import sys
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

class BenchmarkResult:
    def __init__(self, name: str, value: float, unit: str, status: str):
        self.name = name
        self.value = value
        self.unit = unit
        self.status = status
        self.timestamp = datetime.now().isoformat()

class BenchmarkComparison:
    def __init__(self, baseline_file: Optional[str] = None):
        self.baseline = self._load_baseline(baseline_file) if baseline_file else {}
        self.results: List[BenchmarkResult] = []
        
    def _load_baseline(self, filepath: str) -> Dict:
        """Load baseline results from JSON file"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: Baseline file {filepath} not found")
            return {}
    
    def add_result(self, result: BenchmarkResult):
        """Add a benchmark result"""
        self.results.append(result)
    
    def compare_to_baseline(self, name: str, current_value: float) -> Dict:
        """Compare current result to baseline"""
        if name not in self.baseline:
            return {"status": "new", "change_pct": 0}
        
        baseline_value = self.baseline[name]["value"]
        change_pct = ((current_value - baseline_value) / baseline_value) * 100
        
        status = "improved" if change_pct < -5 else "regressed" if change_pct > 5 else "stable"
        
        return {
            "status": status,
            "baseline": baseline_value,
            "current": current_value,
            "change_pct": change_pct
        }
    
    def generate_report(self, output_file: str):
        """Generate JSON report"""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.status == "pass"),
                "failed": sum(1 for r in self.results if r.status == "fail")
            },
            "results": []
        }
        
        for result in self.results:
            entry = {
                "name": result.name,
                "value": result.value,
                "unit": result.unit,
                "status": result.status,
                "timestamp": result.timestamp
            }
            
            # Add baseline comparison if available
            if result.name in self.baseline:
                comparison = self.compare_to_baseline(result.name, result.value)
                entry["baseline_comparison"] = comparison
            
            report["results"].append(entry)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def generate_markdown(self, output_file: str):
        """Generate Markdown report"""
        lines = [
            "# Benchmark Comparison Report",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            "",
            f"- **Total Tests:** {len(self.results)}",
            f"- **Passed:** {sum(1 for r in self.results if r.status == 'pass')}",
            f"- **Failed:** {sum(1 for r in self.results if r.status == 'fail')}",
            "",
            "## Results",
            "",
            "| Test | Value | Unit | Status | vs Baseline |",
            "|------|-------|------|--------|-------------|"
        ]
        
        for result in self.results:
            status_emoji = "✅" if result.status == "pass" else "❌"
            
            baseline_str = "N/A"
            if result.name in self.baseline:
                comparison = self.compare_to_baseline(result.name, result.value)
                change = comparison["change_pct"]
                baseline_str = f"{change:+.1f}%"
            
            lines.append(
                f"| {result.name} | {result.value:.2f} | {result.unit} | {status_emoji} | {baseline_str} |"
            )
        
        lines.extend([
            "",
            "## Details",
            ""
        ])
        
        for result in self.results:
            lines.extend([
                f"### {result.name}",
                "",
                f"- **Value:** {result.value:.2f} {result.unit}",
                f"- **Status:** {result.status}",
                f"- **Timestamp:** {result.timestamp}",
                ""
            ])
            
            if result.name in self.baseline:
                comparison = self.compare_to_baseline(result.name, result.value)
                lines.extend([
                    "**Baseline Comparison:**",
                    f"- Baseline: {comparison['baseline']:.2f}",
                    f"- Current: {comparison['current']:.2f}",
                    f"- Change: {comparison['change_pct']:+.2f}%",
                    f"- Status: {comparison['status']}",
                    ""
                ])
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))

def main():
    parser = argparse.ArgumentParser(description='Compare benchmark results')
    parser.add_argument('--baseline', '-b', help='Baseline JSON file')
    parser.add_argument('--output', '-o', default='benchmark_report.json', help='Output JSON file')
    parser.add_argument('--markdown', '-m', help='Output Markdown file')
    parser.add_argument('results', nargs='+', help='Result files to process')
    
    args = parser.parse_args()
    
    comparison = BenchmarkComparison(args.baseline)
    
    # Process result files
    for result_file in args.results:
        path = Path(result_file)
        if not path.exists():
            print(f"Warning: {result_file} not found, skipping")
            continue
        
        # Parse result file (simple format: name=value unit)
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    name, rest = line.split('=', 1)
                    parts = rest.split()
                    if len(parts) >= 2:
                        try:
                            value = float(parts[0])
                            unit = parts[1]
                            status = "pass" if "PASS" in line or "pass" in line.lower() else "fail"
                            comparison.add_result(BenchmarkResult(name, value, unit, status))
                        except ValueError:
                            pass
    
    # Generate reports
    report = comparison.generate_report(args.output)
    print(f"JSON report saved to: {args.output}")
    
    if args.markdown:
        comparison.generate_markdown(args.markdown)
        print(f"Markdown report saved to: {args.markdown}")
    
    # Print summary
    print(f"\nSummary: {report['summary']['passed']}/{report['summary']['total']} tests passed")
    
    if report['summary']['failed'] > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == '__main__':
    main()
