#!/usr/bin/env python3
"""
RawrXD Parallel Test Runner
Executes tests in parallel for faster validation
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple

class ParallelTestRunner:
    def __init__(self, test_dir: str, max_workers: int = 4):
        self.test_dir = Path(test_dir)
        self.max_workers = max_workers
        self.results = []
        self.categories = [
            'cpu', 'gpu', 'tokenizer', 'gguf', 'kernels',
            'transformer', 'sampler', 'integration', 'regression', 'performance'
        ]
        
    def discover_tests(self, category: str = None) -> List[Tuple[str, Path]]:
        """Discover all test executables"""
        tests = []
        
        if category:
            categories = [category]
        else:
            categories = self.categories
            
        for cat in categories:
            cat_dir = self.test_dir / cat
            if cat_dir.exists():
                for test_file in cat_dir.glob('test_*.exe'):
                    tests.append((cat, test_file))
                    
        return tests
    
    def run_test(self, category: str, test_path: Path) -> Dict:
        """Run a single test and return results"""
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [str(test_path)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=self.test_dir
            )
            
            elapsed = time.time() - start_time
            
            return {
                'category': category,
                'test': test_path.stem,
                'path': str(test_path),
                'status': 'PASS' if result.returncode == 0 else 'FAIL',
                'returncode': result.returncode,
                'elapsed_ms': elapsed * 1000,
                'stdout': result.stdout[:1000] if result.stdout else '',
                'stderr': result.stderr[:1000] if result.stderr else '',
                'timestamp': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {
                'category': category,
                'test': test_path.stem,
                'path': str(test_path),
                'status': 'TIMEOUT',
                'returncode': -1,
                'elapsed_ms': 300000,
                'stdout': '',
                'stderr': 'Test timed out after 300 seconds',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'category': category,
                'test': test_path.stem,
                'path': str(test_path),
                'status': 'ERROR',
                'returncode': -2,
                'elapsed_ms': 0,
                'stdout': '',
                'stderr': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def run_all(self, category: str = None) -> Dict:
        """Run all tests in parallel"""
        tests = self.discover_tests(category)
        
        if not tests:
            print(f"No tests found{' in category ' + category if category else ''}")
            return {'total': 0, 'passed': 0, 'failed': 0, 'results': []}
        
        print(f"Running {len(tests)} test(s) with {self.max_workers} workers...")
        print()
        
        results = []
        passed = 0
        failed = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tests
            future_to_test = {
                executor.submit(self.run_test, cat, path): (cat, path)
                for cat, path in tests
            }
            
            # Process results as they complete
            for future in as_completed(future_to_test):
                cat, path = future_to_test[future]
                result = future.result()
                results.append(result)
                
                # Print result immediately
                status_icon = '✓' if result['status'] == 'PASS' else '✗'
                print(f"  [{status_icon}] {result['test']:<40} {result['status']:>6} ({result['elapsed_ms']:.1f}ms)")
                
                if result['status'] == 'PASS':
                    passed += 1
                else:
                    failed += 1
        
        return {
            'total': len(results),
            'passed': passed,
            'failed': failed,
            'results': results,
            'timestamp': datetime.now().isoformat(),
            'duration_ms': sum(r['elapsed_ms'] for r in results)
        }
    
    def print_summary(self, summary: Dict):
        """Print test summary"""
        print()
        print("=" * 60)
        print("Parallel Test Summary")
        print("=" * 60)
        print(f"Total Tests:  {summary['total']}")
        print(f"Passed:       {summary['passed']}")
        print(f"Failed:       {summary['failed']}")
        print(f"Duration:     {summary['duration_ms']:.1f}ms")
        print(f"Parallel:     {self.max_workers} workers")
        print()
        
        if summary['failed'] == 0:
            print("✓ ALL TESTS PASSED")
        else:
            print(f"✗ {summary['failed']} TEST(S) FAILED")
            print()
            print("Failed Tests:")
            for result in summary['results']:
                if result['status'] != 'PASS':
                    print(f"  - {result['category']}/{result['test']}: {result['status']}")
                    if result['stderr']:
                        print(f"    Error: {result['stderr'][:100]}")
    
    def save_report(self, summary: Dict, output_file: str = None):
        """Save test report to JSON"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"parallel_report_{timestamp}.json"
        
        output_path = self.test_dir / 'reports' / output_file
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\nReport saved to: {output_path}")
        return output_path


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='RawrXD Parallel Test Runner')
    parser.add_argument('--category', '-c', help='Run tests from specific category')
    parser.add_argument('--workers', '-w', type=int, default=4, help='Number of parallel workers')
    parser.add_argument('--output', '-o', help='Output JSON file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Find test directory
    script_dir = Path(__file__).parent
    test_dir = script_dir
    
    print("RawrXD Parallel Test Runner")
    print("=" * 60)
    print(f"Test Directory: {test_dir}")
    print(f"Workers: {args.workers}")
    if args.category:
        print(f"Category: {args.category}")
    print()
    
    runner = ParallelTestRunner(test_dir, max_workers=args.workers)
    summary = runner.run_all(category=args.category)
    
    runner.print_summary(summary)
    
    if args.output or summary['failed'] > 0:
        runner.save_report(summary, args.output)
    
    return 0 if summary['failed'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
