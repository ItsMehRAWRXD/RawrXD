#!/usr/bin/env python3
"""
RawrXD Test Result Comparison Tool
Compare current results against historical baselines
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime


class ResultComparator:
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.baseline_file = reports_dir / 'baseline.json'
        
    def load_baseline(self) -> Optional[Dict]:
        """Load baseline results"""
        if self.baseline_file.exists():
            with open(self.baseline_file, 'r') as f:
                return json.load(f)
        return None
    
    def save_baseline(self, results: Dict):
        """Save current results as baseline"""
        self.baseline_file.parent.mkdir(exist_ok=True)
        with open(self.baseline_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Baseline saved to: {self.baseline_file}")
    
    def load_latest_results(self) -> Optional[Dict]:
        """Load the most recent test results"""
        latest_file = self.reports_dir / 'latest.json'
        if latest_file.exists():
            with open(latest_file, 'r') as f:
                return json.load(f)
        
        # Try to find the most recent report
        reports = list(self.reports_dir.glob('report_*.json'))
        if reports:
            latest = max(reports, key=lambda p: p.stat().st_mtime)
            with open(latest, 'r') as f:
                return json.load(f)
        
        return None
    
    def compare_performance(self, current: Dict, baseline: Dict) -> Dict:
        """Compare performance metrics"""
        comparison = {
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'summary': {
                'improved': 0,
                'regressed': 0,
                'unchanged': 0,
                'new': 0,
                'removed': 0
            }
        }
        
        current_tests = {r['test']: r for r in current.get('results', [])}
        baseline_tests = {r['test']: r for r in baseline.get('results', [])}
        
        # Compare common tests
        for test_name in set(current_tests.keys()) & set(baseline_tests.keys()):
            curr = current_tests[test_name]
            base = baseline_tests[test_name]
            
            curr_time = curr.get('elapsed_ms', 0)
            base_time = base.get('elapsed_ms', 0)
            
            if base_time > 0:
                change_pct = ((curr_time - base_time) / base_time) * 100
            else:
                change_pct = 0
            
            # Determine status
            if abs(change_pct) < 5:  # Within 5% tolerance
                status = 'unchanged'
                comparison['summary']['unchanged'] += 1
            elif change_pct < 0:
                status = 'improved'
                comparison['summary']['improved'] += 1
            else:
                status = 'regressed'
                comparison['summary']['regressed'] += 1
            
            comparison['tests'][test_name] = {
                'status': status,
                'current_ms': curr_time,
                'baseline_ms': base_time,
                'change_pct': change_pct,
                'current_status': curr.get('status'),
                'baseline_status': base.get('status')
            }
        
        # Find new tests
        for test_name in set(current_tests.keys()) - set(baseline_tests.keys()):
            comparison['tests'][test_name] = {
                'status': 'new',
                'current_ms': current_tests[test_name].get('elapsed_ms', 0)
            }
            comparison['summary']['new'] += 1
        
        # Find removed tests
        for test_name in set(baseline_tests.keys()) - set(current_tests.keys()):
            comparison['tests'][test_name] = {
                'status': 'removed',
                'baseline_ms': baseline_tests[test_name].get('elapsed_ms', 0)
            }
            comparison['summary']['removed'] += 1
        
        return comparison
    
    def print_comparison(self, comparison: Dict):
        """Print comparison results"""
        print("\n" + "=" * 70)
        print("Test Result Comparison")
        print("=" * 70)
        
        summary = comparison['summary']
        print(f"\nSummary:")
        print(f"  Improved:   {summary['improved']}")
        print(f"  Regressed:  {summary['regressed']}")
        print(f"  Unchanged:  {summary['unchanged']}")
        print(f"  New:        {summary['new']}")
        print(f"  Removed:    {summary['removed']}")
        
        # Print regressed tests
        regressed = [
            (name, data) for name, data in comparison['tests'].items()
            if data['status'] == 'regressed'
        ]
        
        if regressed:
            print(f"\n⚠️  Regressed Tests ({len(regressed)}):")
            print("-" * 70)
            for name, data in sorted(regressed, key=lambda x: x[1]['change_pct'], reverse=True):
                print(f"  {name:<40} +{data['change_pct']:>6.1f}%  "
                      f"({data['baseline_ms']:.1f}ms → {data['current_ms']:.1f}ms)")
        
        # Print improved tests
        improved = [
            (name, data) for name, data in comparison['tests'].items()
            if data['status'] == 'improved'
        ]
        
        if improved:
            print(f"\n✓ Improved Tests ({len(improved)}):")
            print("-" * 70)
            for name, data in sorted(improved, key=lambda x: x[1]['change_pct']):
                print(f"  {name:<40} {data['change_pct']:>6.1f}%  "
                      f"({data['baseline_ms']:.1f}ms → {data['current_ms']:.1f}ms)")
        
        # Print new tests
        new_tests = [
            name for name, data in comparison['tests'].items()
            if data['status'] == 'new'
        ]
        
        if new_tests:
            print(f"\n+ New Tests ({len(new_tests)}):")
            print("-" * 70)
            for name in sorted(new_tests):
                print(f"  {name}")
        
        print("\n" + "=" * 70)
        
        # Overall assessment
        if summary['regressed'] == 0:
            print("✓ No performance regressions detected")
        else:
            print(f"⚠️  {summary['regressed']} test(s) show performance regression")
        
        if summary['improved'] > 0:
            print(f"✓ {summary['improved']} test(s) show performance improvement")
        
        print("=" * 70)
    
    def save_comparison(self, comparison: Dict, output_file: str = None):
        """Save comparison to file"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"comparison_{timestamp}.json"
        
        output_path = self.reports_dir / output_file
        with open(output_path, 'w') as f:
            json.dump(comparison, f, indent=2)
        
        print(f"\nComparison saved to: {output_path}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='RawrXD Test Result Comparison')
    parser.add_argument('--baseline', '-b', action='store_true',
                        help='Set current results as baseline')
    parser.add_argument('--output', '-o', help='Output file for comparison')
    parser.add_argument('--list', '-l', action='store_true',
                        help='List available reports')
    
    args = parser.parse_args()
    
    # Find reports directory
    script_dir = Path(__file__).parent
    reports_dir = script_dir / 'reports'
    
    if not reports_dir.exists():
        print(f"Reports directory not found: {reports_dir}")
        print("Run tests first to generate reports.")
        return 1
    
    comparator = ResultComparator(reports_dir)
    
    if args.list:
        print("Available reports:")
        reports = sorted(reports_dir.glob('report_*.json'), 
                        key=lambda p: p.stat().st_mtime, reverse=True)
        for report in reports[:10]:
            mtime = datetime.fromtimestamp(report.stat().st_mtime)
            print(f"  {report.name} ({mtime.strftime('%Y-%m-%d %H:%M')})")
        return 0
    
    if args.baseline:
        current = comparator.load_latest_results()
        if current:
            comparator.save_baseline(current)
        else:
            print("No current results found to set as baseline")
            return 1
        return 0
    
    # Compare current against baseline
    current = comparator.load_latest_results()
    baseline = comparator.load_baseline()
    
    if not current:
        print("No current results found. Run tests first.")
        return 1
    
    if not baseline:
        print("No baseline found. Use --baseline to set current results as baseline.")
        print("Proceeding with comparison against previous run...")
        
        # Try to find previous report
        reports = sorted(reports_dir.glob('report_*.json'), 
                        key=lambda p: p.stat().st_mtime, reverse=True)
        if len(reports) >= 2:
            with open(reports[1], 'r') as f:
                baseline = json.load(f)
        else:
            print("No previous results found for comparison")
            return 1
    
    comparison = comparator.compare_performance(current, baseline)
    comparator.print_comparison(comparison)
    
    if args.output:
        comparator.save_comparison(comparison, args.output)
    
    # Return exit code based on regressions
    return 1 if comparison['summary']['regressed'] > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
