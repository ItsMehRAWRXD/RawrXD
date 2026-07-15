#!/usr/bin/env python3
"""
RawrXD Repository Inventory Generator (Phase 0)
Generates evidence-based metrics for architecture planning.

Usage:
    python tools/generate_inventory.py [--output-dir repo_audit]

Output:
    repo_audit/inventory.json       - Complete file inventory
    repo_audit/duplicates.json      - Duplicate implementations
    repo_audit/components.json     - Component matrix
    repo_audit/violations.json     - Architectural violations
    repo_audit/report.txt          - Human-readable report
"""

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional


class FileClassifier:
    """Classifies files by behavior, not just name."""
    
    PATTERNS = {
        'scaffold': [
            r'TODO:\s*implement',
            r'FIXME:\s*implement',
            r'XXX:\s*implement',
            r'stub\s*implementation',
            r'not\s*implemented',
            r'unimplemented',
            r'placeholder',
            r'//\s*TODO',
            r'#\s*TODO',
        ],
        'deprecated': [
            r'\[deprecated\]',
            r'__deprecated__',
            r'DEPRECATED',
            r'@deprecated',
            r'legacy',
            r'obsolete',
        ],
        'experimental': [
            r'experimental',
            r'prototype',
            r'preview',
            r'alpha',
            r'beta',
            r'test_',
            r'_test\.',
        ],
        'production_candidate': [
            r'production',
            r'real',
            r'final',
            r'stable',
        ],
    }
    
    @classmethod
    def classify(cls, filepath: Path, content: str) -> str:
        """Classify file by content markers."""
        text = content.lower()
        
        for category, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return category
        
        return 'reference'


class ComponentExtractor:
    """Extracts class/function names to find duplicates."""
    
    CLASS_PATTERN = re.compile(
        r'(?:class|struct)\s+(\w+)(?:\s*:\s*(?:public|private|protected)\s+(\w+))?',
        re.MULTILINE
    )
    
    FUNCTION_PATTERN = re.compile(
        r'(?:virtual\s+)?(?:static\s+)?(?:inline\s+)?'
        r'(?:\w+::)?(\w+)\s*\([^)]*\)\s*(?:const)?\s*(?:override)?\s*(?:=\s*0)?\s*\{',
        re.MULTILINE
    )
    
    @classmethod
    def extract(cls, content: str) -> Dict[str, List[str]]:
        """Extract components from source code."""
        classes = cls.CLASS_PATTERN.findall(content)
        functions = cls.FUNCTION_PATTERN.findall(content)
        
        return {
            'classes': [c[0] for c in classes],
            'base_classes': [c[1] for c in classes if c[1]],
            'functions': functions[:100],  # Limit to avoid noise
        }


class ArchitectureAnalyzer:
    """Analyzes architectural layer violations."""
    
    LAYERS = {
        'hal': {'layer': 0, 'name': 'Hardware Abstraction'},
        'ggml': {'layer': 1, 'name': 'GGML Adapter'},
        'platform': {'layer': 2, 'name': 'Platform'},
        'inference': {'layer': 3, 'name': 'Inference Engine'},
        'agentic': {'layer': 4, 'name': 'Agentic Core'},
        'ui': {'layer': 5, 'name': 'UI Layer'},
        'server': {'layer': 5, 'name': 'Server Layer'},
    }
    
    VIOLATION_PATTERNS = {
        'agentic': [
            (r'__cpuid', 'Agentic using CPUID directly (should use HAL)'),
            (r'_mm256', 'Agentic using AVX2 directly (should use HAL)'),
            (r'_mm512', 'Agentic using AVX-512 directly (should use HAL)'),
            (r'CreateWindow', 'Agentic creating UI (should use UI layer)'),
            (r'ggml_', 'Agentic calling GGML directly (should use Inference)'),
        ],
        'hal': [
            (r'std::', 'HAL using C++ STL (should be pure C)'),
            (r'class\s+\w+', 'HAL using C++ classes (should be C)'),
        ],
        'inference': [
            (r'ggml_', 'Inference calling GGML directly (should use Adapter)'),
        ],
        'server': [
            (r'ggml_', 'Server calling GGML directly (should use Agentic)'),
            (r'gguf_', 'Server using GGUF directly (should use Inference)'),
        ],
    }
    
    @classmethod
    def get_layer(cls, filepath: Path) -> Optional[Tuple[int, str]]:
        """Determine which layer a file belongs to."""
        path_str = filepath.as_posix().lower()
        
        for prefix, info in cls.LAYERS.items():
            if f'/src/{prefix}/' in path_str or f'\\src\\{prefix}\\' in path_str:
                return info['layer'], info['name']
        
        return None
    
    @classmethod
    def find_violations(cls, filepath: Path, content: str) -> List[Dict]:
        """Find architectural violations in file."""
        violations = []
        layer_info = cls.get_layer(filepath)
        
        if not layer_info:
            return violations
        
        layer_num, layer_name = layer_info
        path_str = filepath.as_posix().lower()
        
        # Check layer-specific patterns
        for layer_prefix, patterns in cls.VIOLATION_PATTERNS.items():
            if layer_prefix in path_str:
                for pattern, description in patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count('\n') + 1
                        violations.append({
                            'file': str(filepath),
                            'line': line_num,
                            'pattern': pattern,
                            'description': description,
                            'layer': layer_name,
                            'severity': 'error',
                        })
        
        return violations


class InventoryGenerator:
    """Generates complete repository inventory."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.inventory = {
            'generated_at': datetime.now().isoformat(),
            'repo_root': str(repo_root),
            'files': [],
            'summary': {},
        }
        self.duplicates = defaultdict(list)
        self.components = defaultdict(lambda: defaultdict(list))
        self.violations = []
        
    def scan_file(self, filepath: Path) -> Optional[Dict]:
        """Scan a single file and return inventory entry."""
        try:
            content_bytes = filepath.read_bytes()
            content = content_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"  Warning: Cannot read {filepath}: {e}", file=sys.stderr)
            return None
        
        rel_path = filepath.relative_to(self.repo_root)
        file_hash = hashlib.sha256(content_bytes).hexdigest()[:16]
        
        entry = {
            'path': str(rel_path),
            'size': len(content_bytes),
            'hash': file_hash,
            'lines': content.count('\n'),
            'extension': filepath.suffix.lower(),
            'classification': FileClassifier.classify(filepath, content),
        }
        
        # Extract components for source files
        if filepath.suffix in {'.cpp', '.h', '.hpp', '.c'}:
            entry['components'] = ComponentExtractor.extract(content)
            
            # Track duplicates by class name
            for cls in entry['components']['classes']:
                self.components[cls][file_hash].append(str(rel_path))
            
            # Find architectural violations
            self.violations.extend(
                ArchitectureAnalyzer.find_violations(rel_path, content)
            )
        
        # Track duplicates by hash
        self.duplicates[file_hash].append(str(rel_path))
        
        return entry
    
    def scan_repository(self) -> None:
        """Scan entire repository."""
        print(f"Scanning repository: {self.repo_root}")
        
        # Scan source files
        extensions = {'.cpp', '.h', '.hpp', '.c', '.asm', '.py', '.ps1', '.cmake'}
        
        for ext in extensions:
            for filepath in self.repo_root.rglob(f'*{ext}'):
                # Skip build directories and archives
                if any(skip in str(filepath) for skip in [
                    '/build', '\\build',
                    '/.git', '\\.git',
                    '/archive', '\\archive',
                    '/.archived', '\\.archived',
                    '/node_modules', '\\node_modules',
                ]):
                    continue
                
                entry = self.scan_file(filepath)
                if entry:
                    self.inventory['files'].append(entry)
        
        print(f"  Scanned {len(self.inventory['files'])} files")
    
    def generate_summary(self) -> None:
        """Generate summary statistics."""
        files = self.inventory['files']
        
        self.inventory['summary'] = {
            'total_files': len(files),
            'by_extension': defaultdict(int),
            'by_classification': defaultdict(int),
            'total_lines': sum(f['lines'] for f in files),
            'total_size_bytes': sum(f['size'] for f in files),
            'duplicate_hashes': len([h for h, paths in self.duplicates.items() if len(paths) > 1]),
            'architectural_violations': len(self.violations),
        }
        
        for f in files:
            self.inventory['summary']['by_extension'][f['extension']] += 1
            self.inventory['summary']['by_classification'][f['classification']] += 1
    
    def find_duplicate_components(self) -> Dict:
        """Find components with multiple implementations."""
        duplicates = {}
        
        for component, hashes in self.components.items():
            if len(hashes) > 1:
                duplicates[component] = {
                    'implementations': []
                }
                for file_hash, paths in hashes.items():
                    duplicates[component]['implementations'].append({
                        'hash': file_hash,
                        'files': paths,
                    })
        
        return duplicates
    
    def write_outputs(self, output_dir: Path) -> None:
        """Write all output files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Main inventory
        with open(output_dir / 'inventory.json', 'w') as f:
            json.dump(self.inventory, f, indent=2)
        
        # Duplicates by hash
        duplicates_by_hash = {
            hash_val: paths for hash_val, paths in self.duplicates.items()
            if len(paths) > 1
        }
        with open(output_dir / 'duplicates_by_hash.json', 'w') as f:
            json.dump(duplicates_by_hash, f, indent=2)
        
        # Duplicate components
        duplicate_components = self.find_duplicate_components()
        with open(output_dir / 'duplicates.json', 'w') as f:
            json.dump(duplicate_components, f, indent=2)
        
        # Violations
        with open(output_dir / 'violations.json', 'w') as f:
            json.dump({
                'total': len(self.violations),
                'by_category': self._categorize_violations(),
                'violations': self.violations,
            }, f, indent=2)
        
        # Human-readable report
        self._write_report(output_dir / 'report.txt')
        
        print(f"\nOutput written to: {output_dir}")
        print(f"  - inventory.json")
        print(f"  - duplicates.json")
        print(f"  - violations.json")
        print(f"  - report.txt")
    
    def _categorize_violations(self) -> Dict:
        """Categorize violations by type."""
        categories = defaultdict(int)
        for v in self.violations:
            category = v['description'].split('(')[0].strip()
            categories[category] += 1
        return dict(categories)
    
    def _write_report(self, filepath: Path) -> None:
        """Write human-readable report."""
        with open(filepath, 'w') as f:
            f.write("RawrXD Repository Inventory Report\n")
            f.write("=" * 60 + "\n")
            f.write(f"Generated: {self.inventory['generated_at']}\n")
            f.write(f"Repository: {self.inventory['repo_root']}\n\n")
            
            # Summary
            summary = self.inventory['summary']
            f.write("Summary\n")
            f.write("-" * 60 + "\n")
            f.write(f"Total Files: {summary['total_files']:,}\n")
            f.write(f"Total Lines: {summary['total_lines']:,}\n")
            f.write(f"Total Size: {summary['total_size_bytes'] / (1024*1024):.2f} MB\n")
            f.write(f"Duplicate Hashes: {summary['duplicate_hashes']}\n")
            f.write(f"Architectural Violations: {summary['architectural_violations']}\n\n")
            
            # By extension
            f.write("Files by Extension\n")
            f.write("-" * 60 + "\n")
            for ext, count in sorted(summary['by_extension'].items(), key=lambda x: -x[1]):
                f.write(f"  {ext or '(no ext)'}: {count:,}\n")
            f.write("\n")
            
            # By classification
            f.write("Files by Classification\n")
            f.write("-" * 60 + "\n")
            for cls, count in sorted(summary['by_classification'].items(), key=lambda x: -x[1]):
                f.write(f"  {cls}: {count:,}\n")
            f.write("\n")
            
            # Duplicate components
            duplicate_components = self.find_duplicate_components()
            if duplicate_components:
                f.write("Duplicate Components\n")
                f.write("-" * 60 + "\n")
                for component, info in sorted(duplicate_components.items()):
                    f.write(f"\n{component}:\n")
                    for impl in info['implementations']:
                        f.write(f"  Hash: {impl['hash'][:8]}...\n")
                        for path in impl['files']:
                            f.write(f"    - {path}\n")
                f.write("\n")
            
            # Violations summary
            if self.violations:
                f.write("Architectural Violations Summary\n")
                f.write("-" * 60 + "\n")
                categories = self._categorize_violations()
                for category, count in sorted(categories.items(), key=lambda x: -x[1]):
                    f.write(f"  {category}: {count}\n")
                f.write("\n")
                
                # Top violations
                f.write("Top 20 Violations\n")
                f.write("-" * 60 + "\n")
                for v in self.violations[:20]:
                    f.write(f"  {v['file']}:{v['line']}\n")
                    f.write(f"    {v['description']}\n\n")


def main():
    parser = argparse.ArgumentParser(
        description='Generate RawrXD repository inventory'
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('repo_audit'),
        help='Output directory for inventory files'
    )
    parser.add_argument(
        '--repo-root',
        type=Path,
        default=Path(__file__).parent.parent,
        help='Repository root directory'
    )
    
    args = parser.parse_args()
    
    # Generate inventory
    generator = InventoryGenerator(args.repo_root)
    generator.scan_repository()
    generator.generate_summary()
    generator.write_outputs(args.output_dir)
    
    # Print summary
    summary = generator.inventory['summary']
    print(f"\n{'='*60}")
    print("Inventory Complete")
    print(f"{'='*60}")
    print(f"Files scanned: {summary['total_files']:,}")
    print(f"Total lines: {summary['total_lines']:,}")
    print(f"Duplicate hashes: {summary['duplicate_hashes']}")
    print(f"Architectural violations: {summary['architectural_violations']}")
    
    # Exit with error if violations found
    if summary['architectural_violations'] > 0:
        print(f"\n⚠️  {summary['architectural_violations']} architectural violations found")
        print("   See repo_audit/violations.json for details")
        sys.exit(1)
    else:
        print("\n✅ No architectural violations found")
        sys.exit(0)


if __name__ == '__main__':
    main()
