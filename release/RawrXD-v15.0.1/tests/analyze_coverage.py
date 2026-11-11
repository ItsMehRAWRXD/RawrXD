#!/usr/bin/env python3
"""
RawrXD Test Coverage Analyzer
Analyzes test coverage across the codebase
"""

import os
import json
import glob
from pathlib import Path
from collections import defaultdict

class CoverageAnalyzer:
    def __init__(self, root_dir):
        self.root_dir = Path(root_dir)
        self.coverage = defaultdict(lambda: {
            'tested': False,
            'test_files': [],
            'category': None
        })
        
    def scan_source_files(self):
        """Scan source files in the codebase"""
        source_patterns = [
            'src/**/*.c',
            'src/**/*.cpp',
            'src/**/*.h',
            'src/**/*.hpp',
            'kernels/**/*.c',
            'kernels/**/*.cpp',
            'kernels/**/*.h',
        ]
        
        sources = []
        for pattern in source_patterns:
            sources.extend(self.root_dir.glob(pattern))
        
        return sources
    
    def scan_test_files(self):
        """Scan test files"""
        test_dir = self.root_dir / 'tests'
        test_files = []
        
        for category in ['cpu', 'gpu', 'tokenizer', 'gguf', 'kernels', 
                        'transformer', 'sampler', 'integration', 'regression', 'performance']:
            category_dir = test_dir / category
            if category_dir.exists():
                test_files.extend(category_dir.glob('test_*.c'))
                test_files.extend(category_dir.glob('test_*.cpp'))
                test_files.extend(category_dir.glob('test_*.exe'))
        
        return test_files
    
    def analyze_test_coverage(self):
        """Analyze which source files have tests"""
        sources = self.scan_source_files()
        tests = self.scan_test_files()
        
        # Map test files to source categories
        test_categories = {
            'cpu': ['avx2', 'cpu', 'simd'],
            'gpu': ['cuda', 'vulkan', 'gpu', 'compute'],
            'tokenizer': ['token', 'bpe', 'vocab'],
            'gguf': ['gguf', 'loader', 'format'],
            'kernels': ['kernel', 'matmul', 'softmax', 'norm', 'attention', 'gelu', 'silu', 'rope'],
            'transformer': ['transformer', 'layer', 'block', 'mlp'],
            'sampler': ['sample', 'temperature', 'topk', 'topp'],
            'integration': ['integration', 'pipeline', 'e2e'],
            'regression': ['regression', 'reference'],
            'performance': ['perf', 'benchmark', 'speed']
        }
        
        # Analyze each source file
        for source in sources:
            source_name = source.stem.lower()
            
            # Check if there's a corresponding test
            for test in tests:
                test_name = test.stem.lower()
                if source_name.replace('_', '') in test_name or test_name.replace('test_', '') in source_name:
                    self.coverage[source]['tested'] = True
                    self.coverage[source]['test_files'].append(str(test))
                    
            # Determine category
            for category, keywords in test_categories.items():
                if any(kw in source_name for kw in keywords):
                    self.coverage[source]['category'] = category
                    break
    
    def generate_report(self):
        """Generate coverage report"""
        self.analyze_test_coverage()
        
        total_sources = len(self.coverage)
        tested_sources = sum(1 for v in self.coverage.values() if v['tested'])
        
        report = {
            'summary': {
                'total_source_files': total_sources,
                'tested_files': tested_sources,
                'coverage_percent': (tested_sources / total_sources * 100) if total_sources > 0 else 0,
                'untested_files': total_sources - tested_sources
            },
            'by_category': defaultdict(lambda: {'total': 0, 'tested': 0}),
            'untested': [],
            'tested': []
        }
        
        for source, info in self.coverage.items():
            category = info['category'] or 'uncategorized'
            report['by_category'][category]['total'] += 1
            
            if info['tested']:
                report['by_category'][category]['tested'] += 1
                report['tested'].append({
                    'file': str(source.relative_to(self.root_dir)),
                    'tests': info['test_files']
                })
            else:
                report['untested'].append(str(source.relative_to(self.root_dir)))
        
        return report
    
    def print_report(self, report):
        """Print coverage report to console"""
        print("=" * 60)
        print("RawrXD Test Coverage Report")
        print("=" * 60)
        print()
        
        summary = report['summary']
        print(f"Total Source Files: {summary['total_source_files']}")
        print(f"Tested Files:       {summary['tested_files']}")
        print(f"Untested Files:     {summary['untested_files']}")
        print(f"Coverage:           {summary['coverage_percent']:.1f}%")
        print()
        
        print("Coverage by Category:")
        print("-" * 40)
        for category, stats in sorted(report['by_category'].items()):
            pct = (stats['tested'] / stats['total'] * 100) if stats['total'] > 0 else 0
            status = "✓" if pct >= 80 else "⚠" if pct >= 50 else "✗"
            print(f"  {status} {category:20s} {stats['tested']:3d}/{stats['total']:<3d} ({pct:5.1f}%)")
        print()
        
        if report['untested']:
            print("Untested Files (Top 10):")
            print("-" * 40)
            for f in report['untested'][:10]:
                print(f"  • {f}")
            if len(report['untested']) > 10:
                print(f"  ... and {len(report['untested']) - 10} more")
            print()
        
        print("=" * 60)
        
        # Save JSON report
        report_path = self.root_dir / 'tests' / 'reports' / 'coverage_report.json'
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Detailed report saved to: {report_path}")


def main():
    import sys
    
    # Determine root directory
    script_dir = Path(__file__).parent
    root_dir = script_dir.parent
    
    print(f"Analyzing coverage in: {root_dir}")
    print()
    
    analyzer = CoverageAnalyzer(root_dir)
    report = analyzer.generate_report()
    analyzer.print_report(report)
    
    # Return exit code based on coverage
    coverage = report['summary']['coverage_percent']
    if coverage >= 80:
        return 0
    elif coverage >= 50:
        return 1  # Warning
    else:
        return 2  # Error


if __name__ == '__main__':
    exit(main())
