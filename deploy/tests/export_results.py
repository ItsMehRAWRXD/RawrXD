#!/usr/bin/env python3
"""
RawrXD Test Result Exporter
Export test results to various formats for CI/CD integration
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
import csv
import sys


class ResultExporter:
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.results = None
        
    def load_latest_results(self) -> bool:
        """Load the most recent test results"""
        latest_file = self.reports_dir / 'latest.json'
        
        if not latest_file.exists():
            # Try unified report
            unified_file = self.reports_dir / 'unified_report.json'
            if unified_file.exists():
                latest_file = unified_file
            else:
                print(f"No results found in {self.reports_dir}")
                return False
        
        try:
            with open(latest_file, 'r') as f:
                self.results = json.load(f)
            return True
        except Exception as e:
            print(f"Error loading results: {e}")
            return False
    
    def to_junit_xml(self, output_file: Path) -> bool:
        """Export to JUnit XML format for CI/CD integration"""
        if not self.results:
            return False
        
        # Create root element
        testsuites = ET.Element('testsuites')
        testsuites.set('name', 'RawrXD Validation')
        
        # Add timestamp
        timestamp = self.results.get('timestamp', datetime.now().isoformat())
        testsuites.set('timestamp', timestamp)
        
        # Group results by category
        categories = {}
        for result in self.results.get('results', []):
            cat = result.get('category', 'unknown')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(result)
        
        # Create testsuite for each category
        for category, tests in categories.items():
            testsuite = ET.SubElement(testsuites, 'testsuite')
            testsuite.set('name', f'tests.{category}')
            testsuite.set('tests', str(len(tests)))
            
            failures = sum(1 for t in tests if t.get('status') != 'PASS')
            testsuite.set('failures', str(failures))
            testsuite.set('time', str(sum(t.get('elapsed_ms', 0) for t in tests) / 1000.0))
            
            for test in tests:
                testcase = ET.SubElement(testsuite, 'testcase')
                testcase.set('name', test.get('test', 'unknown'))
                testcase.set('classname', f'tests.{category}')
                testcase.set('time', str(test.get('elapsed_ms', 0) / 1000.0))
                
                if test.get('status') != 'PASS':
                    failure = ET.SubElement(testcase, 'failure')
                    failure.set('message', f"Test {test.get('status')}")
                    failure.text = test.get('stderr', 'No error details')
        
        # Write XML
        tree = ET.ElementTree(testsuites)
        ET.indent(tree, space='  ')
        tree.write(output_file, encoding='utf-8', xml_declaration=True)
        
        print(f"JUnit XML exported to: {output_file}")
        return True
    
    def to_csv(self, output_file: Path) -> bool:
        """Export to CSV for spreadsheet analysis"""
        if not self.results:
            return False
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Category', 'Test Name', 'Status', 'Time (ms)',
                'Timestamp', 'Error Details'
            ])
            
            # Data
            for result in self.results.get('results', []):
                writer.writerow([
                    result.get('category', ''),
                    result.get('test', ''),
                    result.get('status', ''),
                    result.get('elapsed_ms', 0),
                    result.get('timestamp', ''),
                    result.get('stderr', '')[:100]  # Truncate errors
                ])
        
        print(f"CSV exported to: {output_file}")
        return True
    
    def to_markdown(self, output_file: Path) -> bool:
        """Export to Markdown for documentation"""
        if not self.results:
            return False
        
        with open(output_file, 'w') as f:
            f.write("# RawrXD Test Results\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            total = self.results.get('total', 0)
            passed = self.results.get('passed', 0)
            failed = self.results.get('failed', 0)
            
            f.write("## Summary\n\n")
            f.write(f"- **Total Tests:** {total}\n")
            f.write(f"- **Passed:** {passed} ✅\n")
            f.write(f"- **Failed:** {failed} {'✅' if failed == 0 else '❌'}\n")
            f.write(f"- **Success Rate:** {(passed/total*100) if total > 0 else 0:.1f}%\n\n")
            
            # Results by category
            f.write("## Results by Category\n\n")
            f.write("| Category | Test | Status | Time (ms) |\n")
            f.write("|----------|------|--------|-----------|\n")
            
            for result in self.results.get('results', []):
                status_icon = '✅' if result.get('status') == 'PASS' else '❌'
                f.write(f"| {result.get('category', '')} | {result.get('test', '')} | "
                       f"{status_icon} {result.get('status', '')} | "
                       f"{result.get('elapsed_ms', 0):.1f} |\n")
            
            f.write("\n")
        
        print(f"Markdown exported to: {output_file}")
        return True
    
    def to_github_actions(self) -> str:
        """Output formatted for GitHub Actions annotations"""
        if not self.results:
            return ""
        
        output = []
        
        for result in self.results.get('results', []):
            if result.get('status') != 'PASS':
                # GitHub Actions error annotation
                output.append(f"::error file={result.get('category')}/{result.get('test')}.c,"
                              f"title=Test Failed::{result.get('test')} failed: "
                              f"{result.get('stderr', 'Unknown error')}")
        
        return '\n'.join(output)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='RawrXD Test Result Exporter')
    parser.add_argument('--format', '-f', choices=['junit', 'csv', 'markdown', 'github'],
                        default='junit', help='Export format')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--reports-dir', '-r', default='reports',
                        help='Reports directory')
    
    args = parser.parse_args()
    
    # Find reports directory
    script_dir = Path(__file__).parent
    reports_dir = script_dir / args.reports_dir
    
    exporter = ResultExporter(reports_dir)
    
    if not exporter.load_latest_results():
        return 1
    
    # Determine output file
    if args.output:
        output_file = Path(args.output)
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extensions = {
            'junit': 'xml',
            'csv': 'csv',
            'markdown': 'md',
            'github': 'txt'
        }
        output_file = reports_dir / f"test_results_{timestamp}.{extensions[args.format]}"
    
    # Export
    success = False
    
    if args.format == 'junit':
        success = exporter.to_junit_xml(output_file)
    elif args.format == 'csv':
        success = exporter.to_csv(output_file)
    elif args.format == 'markdown':
        success = exporter.to_markdown(output_file)
    elif args.format == 'github':
        output = exporter.to_github_actions()
        print(output)
        success = True
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
