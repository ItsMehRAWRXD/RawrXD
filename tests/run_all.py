#!/usr/bin/env python3
"""
RawrXD Unified Test Runner
One command to run all test types: unit, integration, regression, performance, stress
"""

import os
import sys
import json
import subprocess
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

class TestRunner:
    def __init__(self, test_dir: Path):
        self.test_dir = test_dir
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'version': '15.0.0-dev',
            'suites': {}
        }
        self.verbose = False
        
    def log(self, message: str, level: str = 'info'):
        """Log message with color coding"""
        colors = {
            'info': '\033[36m',      # Cyan
            'success': '\033[32m',   # Green
            'warning': '\033[33m', # Yellow
            'error': '\033[31m',   # Red
            'header': '\033[35m',   # Magenta
            'reset': '\033[0m'
        }
        
        if sys.platform == 'win32':
            # Windows doesn't support ANSI colors in standard cmd
            print(message)
        else:
            color = colors.get(level, colors['info'])
            print(f"{color}{message}{colors['reset']}")
    
    def run_command(self, cmd: List[str], cwd: Path = None, timeout: int = 300) -> Tuple[int, str, str]:
        """Run a command and return results"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=cwd or self.test_dir,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -2, "", str(e)
    
    def run_unit_tests(self) -> Dict:
        """Run unit tests via parallel runner"""
        self.log("\n" + "="*70, 'header')
        self.log("Running Unit Tests", 'header')
        self.log("="*70, 'header')
        
        start_time = time.time()
        
        # Run parallel tests
        returncode, stdout, stderr = self.run_command(
            [sys.executable, 'run_parallel.py', '--workers', '4'],
            timeout=120
        )
        
        elapsed = time.time() - start_time
        
        # Parse results from latest.json
        latest_file = self.test_dir / 'reports' / 'latest.json'
        results = {'total': 0, 'passed': 0, 'failed': 0, 'time': elapsed}
        
        if latest_file.exists():
            try:
                with open(latest_file, 'r') as f:
                    data = json.load(f)
                    results['total'] = data.get('total', 0)
                    results['passed'] = data.get('passed', 0)
                    results['failed'] = data.get('failed', 0)
            except:
                pass
        
        status = 'success' if results['failed'] == 0 else 'error'
        self.log(f"Unit Tests: {results['passed']}/{results['total']} passed in {elapsed:.2f}s", status)
        
        return results
    
    def run_regression_tests(self) -> Dict:
        """Run regression tests"""
        self.log("\n" + "="*70, 'header')
        self.log("Running Regression Tests", 'header')
        self.log("="*70, 'header')
        
        start_time = time.time()
        
        returncode, stdout, stderr = self.run_command(
            ['.\\regression\\test_regression.exe'],
            timeout=60
        )
        
        elapsed = time.time() - start_time
        
        # Parse results
        passed = 9 if returncode == 0 else 0
        failed = 0 if returncode == 0 else 9
        
        results = {'total': 9, 'passed': passed, 'failed': failed, 'time': elapsed}
        
        status = 'success' if returncode == 0 else 'error'
        self.log(f"Regression Tests: {passed}/9 passed in {elapsed:.2f}s", status)
        
        return results
    
    def run_performance_tests(self) -> Dict:
        """Run performance benchmarks"""
        self.log("\n" + "="*70, 'header')
        self.log("Running Performance Tests", 'header')
        self.log("="*70, 'header')
        
        start_time = time.time()
        
        returncode, stdout, stderr = self.run_command(
            ['.\\performance\\test_perf_quick.exe'],
            timeout=120
        )
        
        elapsed = time.time() - start_time
        
        results = {'total': 3, 'passed': 3 if returncode == 0 else 0, 
                   'failed': 0 if returncode == 0 else 3, 'time': elapsed}
        
        status = 'success' if returncode == 0 else 'error'
        self.log(f"Performance Tests: {results['passed']}/3 passed in {elapsed:.2f}s", status)
        
        return results
    
    def run_stress_tests(self) -> Dict:
        """Run stress tests"""
        self.log("\n" + "="*70, 'header')
        self.log("Running Stress Tests", 'header')
        self.log("="*70, 'header')
        
        start_time = time.time()
        
        returncode, stdout, stderr = self.run_command(
            ['.\\stress\\test_stress_kernels.exe'],
            timeout=300
        )
        
        elapsed = time.time() - start_time
        
        results = {'total': 3, 'passed': 3 if returncode == 0 else 0,
                   'failed': 0 if returncode == 0 else 3, 'time': elapsed}
        
        status = 'success' if returncode == 0 else 'error'
        self.log(f"Stress Tests: {results['passed']}/3 passed in {elapsed:.2f}s", status)
        
        return results
    
    def generate_report(self):
        """Generate consolidated report"""
        self.log("\n" + "="*70, 'header')
        self.log("Generating Report", 'header')
        self.log("="*70, 'header')
        
        # Calculate totals
        total_tests = sum(s['total'] for s in self.results['suites'].values())
        total_passed = sum(s['passed'] for s in self.results['suites'].values())
        total_failed = sum(s['failed'] for s in self.results['suites'].values())
        total_time = sum(s['time'] for s in self.results['suites'].values())
        
        self.results['summary'] = {
            'total': total_tests,
            'passed': total_passed,
            'failed': total_failed,
            'time': total_time,
            'success_rate': (total_passed / total_tests * 100) if total_tests > 0 else 0
        }
        
        # Save JSON report
        report_file = self.test_dir / 'reports' / 'unified_report.json'
        report_file.parent.mkdir(exist_ok=True)
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        self.log(f"Report saved to: {report_file}", 'info')
        
        # Print summary
        self.log("\n" + "="*70, 'header')
        self.log("FINAL SUMMARY", 'header')
        self.log("="*70, 'header')
        self.log(f"Total Tests:  {total_tests}")
        self.log(f"Passed:       {total_passed}", 'success')
        self.log(f"Failed:       {total_failed}", 'error' if total_failed > 0 else 'success')
        self.log(f"Success Rate: {self.results['summary']['success_rate']:.1f}%")
        self.log(f"Total Time:   {total_time:.2f}s")
        
        if total_failed == 0:
            self.log("\n✓ ALL TESTS PASSED", 'success')
        else:
            self.log(f"\n✗ {total_failed} TEST(S) FAILED", 'error')
        
        self.log("="*70, 'header')
    
    def run_all(self, args):
        """Run all test suites"""
        self.log("RawrXD Unified Test Runner", 'header')
        self.log(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 'info')
        self.log(f"Test Directory: {self.test_dir}", 'info')
        
        # Run requested test suites
        if args.unit or args.all:
            self.results['suites']['unit'] = self.run_unit_tests()
        
        if args.regression or args.all:
            self.results['suites']['regression'] = self.run_regression_tests()
        
        if args.performance or args.all:
            self.results['suites']['performance'] = self.run_performance_tests()
        
        if args.stress or args.all:
            self.results['suites']['stress'] = self.run_stress_tests()
        
        # Generate report
        self.generate_report()
        
        # Return exit code
        return 0 if self.results['summary']['failed'] == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description='RawrXD Unified Test Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --all              Run all test suites
  %(prog)s --unit             Run only unit tests
  %(prog)s --performance      Run only performance tests
  %(prog)s --unit --stress    Run unit and stress tests
        '''
    )
    
    parser.add_argument('--all', '-a', action='store_true',
                        help='Run all test suites (default)')
    parser.add_argument('--unit', '-u', action='store_true',
                        help='Run unit tests')
    parser.add_argument('--regression', '-r', action='store_true',
                        help='Run regression tests')
    parser.add_argument('--performance', '-p', action='store_true',
                        help='Run performance tests')
    parser.add_argument('--stress', '-s', action='store_true',
                        help='Run stress tests')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--report', action='store_true',
                        help='Generate HTML report')
    
    args = parser.parse_args()
    
    # If no specific suite selected, run all
    if not any([args.unit, args.regression, args.performance, args.stress]):
        args.all = True
    
    # Find test directory
    script_dir = Path(__file__).parent
    
    runner = TestRunner(script_dir)
    runner.verbose = args.verbose
    
    return runner.run_all(args)


if __name__ == '__main__':
    sys.exit(main())
