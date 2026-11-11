#!/usr/bin/env python3
"""
Migration Candidate Identifier

Identifies all usages of legacy AgenticEngine and CPUInferenceEngine
that need to be migrated to the new unified interfaces.

Usage:
    python identify_migration_candidates.py [path]

Output:
    migration_report.json - Detailed report of all candidates
    migration_summary.txt - Human-readable summary
"""

import os
import re
import json
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime


class MigrationCandidateFinder:
    """Finds all legacy API usages that need migration."""
    
    # Legacy patterns to search for
    LEGACY_PATTERNS = {
        'AgenticEngine': {
            'class': r'\bAgenticEngine\b',
            'methods': [
                r'->\s*initialize\s*\(\)',
                r'->\s*grepFiles\s*\(',
                r'->\s*readFile\s*\(',
                r'->\s*writeFile\s*\(',
                r'->\s*listDir\s*\(',
                r'->\s*executeCommand\s*\(',
                r'->\s*chat\s*\(',
                r'->\s*processQuery\s*\(',
                r'->\s*isCommandSafe\s*\(',
                r'->\s*searchFiles\s*\(',
                r'->\s*analyzeCode\s*\(',
                r'->\s*generateCode\s*\(',
            ],
            'migration_priority': 'P1',
            'complexity': 'medium'
        },
        'CPUInferenceEngine': {
            'class': r'\bCPUInferenceEngine\b',
            'methods': [
                r'::\s*GetSharedInstance\s*\(\)',
                r'::\s*getInstance\s*\(\)',
                r'->\s*LoadModel\s*\(',
                r'->\s*Generate\s*\(',
                r'->\s*Tokenize\s*\(',
                r'->\s*Detokenize\s*\(',
                r'->\s*IsModelLoaded\s*\(',
                r'->\s*GetModelInfo\s*\(',
                r'->\s*UnloadModel\s*\(',
            ],
            'migration_priority': 'P1',
            'complexity': 'low'
        },
        'LegacyIncludes': {
            'patterns': [
                r'#include\s*["<].*agentic_engine\.h[">]',
                r'#include\s*["<].*cpu_inference_engine\.h[">]',
                r'#include\s*["<].*agentic_core[^/]*\.h[">]',
            ],
            'migration_priority': 'P0',
            'complexity': 'low'
        }
    }
    
    def __init__(self, root_path):
        self.root_path = Path(root_path)
        self.candidates = defaultdict(list)
        self.stats = {
            'files_scanned': 0,
            'files_with_legacy': 0,
            'total_occurrences': 0,
            'by_category': defaultdict(int)
        }
    
    def scan_file(self, file_path):
        """Scan a single file for legacy usages."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return
        
        self.stats['files_scanned'] += 1
        file_has_legacy = False
        
        for category, patterns in self.LEGACY_PATTERNS.items():
            if 'class' in patterns:
                # Check for class usage
                for i, line in enumerate(lines, 1):
                    if re.search(patterns['class'], line):
                        if not self._is_comment_or_string(line):
                            self.candidates[category].append({
                                'file': str(file_path),
                                'line': i,
                                'content': line.strip(),
                                'type': 'class_reference',
                                'priority': patterns['migration_priority'],
                                'complexity': patterns['complexity']
                            })
                            file_has_legacy = True
                            self.stats['by_category'][category] += 1
                
                # Check for method calls
                for method_pattern in patterns['methods']:
                    for i, line in enumerate(lines, 1):
                        if re.search(method_pattern, line):
                            if not self._is_comment_or_string(line):
                                self.candidates[category].append({
                                    'file': str(file_path),
                                    'line': i,
                                    'content': line.strip(),
                                    'type': 'method_call',
                                    'priority': patterns['migration_priority'],
                                    'complexity': patterns['complexity']
                                })
                                file_has_legacy = True
                                self.stats['by_category'][category] += 1
            
            elif 'patterns' in patterns:
                # Check for include patterns
                for pattern in patterns['patterns']:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line):
                            self.candidates[category].append({
                                'file': str(file_path),
                                'line': i,
                                'content': line.strip(),
                                'type': 'include',
                                'priority': patterns['migration_priority'],
                                'complexity': patterns['complexity']
                            })
                            file_has_legacy = True
                            self.stats['by_category'][category] += 1
        
        if file_has_legacy:
            self.stats['files_with_legacy'] += 1
    
    def _is_comment_or_string(self, line):
        """Check if a line is inside a comment or string."""
        # Simple check - can be improved
        stripped = line.strip()
        return stripped.startswith('//') or stripped.startswith('*')
    
    def scan_directory(self):
        """Scan all C++ files in the directory."""
        cpp_extensions = {'.cpp', '.h', '.hpp', '.cc', '.cxx'}
        
        for ext in cpp_extensions:
            for file_path in self.root_path.rglob(f'*{ext}'):
                # Skip certain directories
                if any(skip in str(file_path) for skip in ['.git', 'build', 'obj', 'bin', 'third_party']):
                    continue
                self.scan_file(file_path)
    
    def generate_report(self):
        """Generate migration report."""
        report = {
            'generated_at': datetime.now().isoformat(),
            'root_path': str(self.root_path),
            'statistics': dict(self.stats),
            'candidates': dict(self.candidates),
            'summary': self._generate_summary()
        }
        
        return report
    
    def _generate_summary(self):
        """Generate human-readable summary."""
        summary = []
        summary.append("=" * 80)
        summary.append("MIGRATION CANDIDATE SUMMARY")
        summary.append("=" * 80)
        summary.append("")
        summary.append(f"Files Scanned: {self.stats['files_scanned']}")
        summary.append(f"Files with Legacy Code: {self.stats['files_with_legacy']}")
        summary.append(f"Total Legacy Occurrences: {sum(len(v) for v in self.candidates.values())}")
        summary.append("")
        
        summary.append("By Category:")
        for category, count in sorted(self.stats['by_category'].items()):
            summary.append(f"  {category}: {count}")
        
        summary.append("")
        summary.append("Files Requiring Migration (Top 20):")
        
        # Group by file
        files_with_issues = defaultdict(list)
        for category, items in self.candidates.items():
            for item in items:
                files_with_issues[item['file']].append(item)
        
        # Sort by number of issues
        sorted_files = sorted(files_with_issues.items(), key=lambda x: len(x[1]), reverse=True)
        
        for file_path, items in sorted_files[:20]:
            summary.append(f"  {file_path}: {len(items)} occurrences")
        
        summary.append("")
        summary.append("=" * 80)
        
        return '\n'.join(summary)
    
    def save_report(self, output_dir):
        """Save report to files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        report = self.generate_report()
        
        # Save JSON report
        json_path = output_dir / 'migration_report.json'
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save summary
        summary_path = output_dir / 'migration_summary.txt'
        with open(summary_path, 'w') as f:
            f.write(report['summary'])
        
        print(f"Report saved to: {json_path}")
        print(f"Summary saved to: {summary_path}")


def main():
    """Main entry point."""
    if len(sys.argv) > 1:
        root_path = sys.argv[1]
    else:
        root_path = '.'
    
    print(f"Scanning for migration candidates in: {root_path}")
    print("This may take a few minutes...")
    print()
    
    finder = MigrationCandidateFinder(root_path)
    finder.scan_directory()
    
    # Print summary
    print(finder._generate_summary())
    
    # Save report
    finder.save_report('migration_report')
    
    print()
    print("Migration analysis complete!")
    print("Review migration_report/migration_summary.txt for details.")


if __name__ == '__main__':
    main()
