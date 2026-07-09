#!/usr/bin/env python3
"""
RawrXD Architecture Enforcement Script
Enforces 5-layer architecture boundaries
"""

import re
import sys
from pathlib import Path
from typing import List, Dict, Set, Tuple

# Layer definitions: path prefix -> allowed includes
LAYER_RULES = {
    'src/hal/': {
        'layer': 0,
        'name': 'Hardware Abstraction',
        'can_include': set(),  # Layer 0 can only use system headers
        'forbidden_patterns': [
            r'std::',  # No C++ STL in HAL
            r'class\s+\w+.*:',  # No C++ classes (C only)
        ],
    },
    'src/ggml/': {
        'layer': 1,
        'name': 'GGML Core',
        'can_include': {'src/hal/'},
        'forbidden_patterns': [
            r'std::vector',  # Use C arrays in API
            r'std::string',  # Use const char* in API
            r'class\s+\w+.*:',  # C API only
        ],
    },
    'src/inference/': {
        'layer': 2,
        'name': 'Inference Engine',
        'can_include': {'src/hal/', 'src/ggml/'},
        'forbidden_patterns': [
            r'ggml_',  # Should use wrapper, not direct GGML
            r'CreateWindow',  # No UI in inference layer
            r'WinMain',  # No UI in inference layer
        ],
    },
    'src/agentic/': {
        'layer': 3,
        'name': 'Agentic Core',
        'can_include': {'src/hal/', 'src/ggml/', 'src/inference/'},
        'forbidden_patterns': [
            r'__cpuid',  # Use HAL
            r'_mm256',   # Use HAL
            r'_mm512',   # Use HAL
            r'CreateWindow',  # No UI in agentic layer
        ],
    },
    'src/ui/': {
        'layer': 4,
        'name': 'User Interface',
        'can_include': {'src/hal/', 'src/ggml/', 'src/inference/', 'src/agentic/'},
        'forbidden_patterns': [
            r'ggml_',  # Must go through Agentic
            r'CPUInferenceEngine',  # Must go through Agentic
            r'gguf_',  # Must go through Inference
        ],
    },
    'src/server/': {
        'layer': 4,
        'name': 'HTTP Server',
        'can_include': {'src/hal/', 'src/ggml/', 'src/inference/', 'src/agentic/'},
        'forbidden_patterns': [
            r'ggml_',
            r'CPUInferenceEngine',
            r'gguf_',
        ],
    },
}

# Known duplicate implementations to flag
DUPLICATE_IMPLEMENTATIONS = {
    'CPUInferenceEngine': [
        'src/cpu_inference_engine.h',
        'src/cpu_inference_engine_Clean.h',
        'src/cpu_inference_engine_fixed.cpp',
        'src/cpu_inference_engine_init_fix.cpp',
        'src/cpu_inference_engine_production.cpp',
        'src/cpu_inference_engine_real.cpp',
    ],
    'AgenticEngine': [
        'src/agentic_engine.h',
        'src/agentic_core.h',
        'src/agentic_core_win32.h',
        'src/agentic_executor.h',
    ],
    'ExecutionScheduler': [
        'src/ExecutionScheduler.h',
        'src/ExecutionScheduler_v2.h',
        'src/ExecutionScheduler_PATCH_PLAN.md',
    ],
}

class ArchitectureEnforcer:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.violations: List[str] = []
        self.warnings: List[str] = []
        self.stats = {
            'files_checked': 0,
            'violations': 0,
            'warnings': 0,
        }

    def get_layer_for_file(self, filepath: Path) -> Tuple[int, str]:
        """Determine which layer a file belongs to."""
        rel_path = filepath.relative_to(self.root_dir).as_posix()
        
        for prefix, rules in sorted(LAYER_RULES.items(), 
                                     key=lambda x: -len(x[0])):  # Longest first
            if rel_path.startswith(prefix):
                return rules['layer'], rules['name']
        
        return -1, 'Unknown'

    def check_file(self, filepath: Path) -> None:
        """Check a single file for architectural violations."""
        self.stats['files_checked'] += 1
        
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            self.warnings.append(f"Cannot read {filepath}: {e}")
            return

        rel_path = filepath.relative_to(self.root_dir).as_posix()
        layer, layer_name = self.get_layer_for_file(filepath)
        
        if layer < 0:
            return  # Skip files not in src/

        # Get rules for this layer
        rules = None
        for prefix, r in LAYER_RULES.items():
            if rel_path.startswith(prefix):
                rules = r
                break
        
        if not rules:
            return

        # Check forbidden patterns
        for pattern in rules.get('forbidden_patterns', []):
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count('\n') + 1
                self.violations.append(
                    f"[{layer_name}] {rel_path}:{line_num}: Forbidden pattern '{pattern}'"
                )
                self.stats['violations'] += 1

        # Check #include violations
        includes = re.findall(r'#include\s+["<]([^">]+)[">]', content)
        for inc in includes:
            inc_path = inc.replace('\\', '/')
            
            # Check if include crosses layer boundary
            for prefix, r in LAYER_RULES.items():
                if inc_path.startswith(prefix) and prefix not in rules['can_include']:
                    if not any(inc_path.startswith(a) for a in rules['can_include']):
                        line_num = content.find(f'#include {inc}')
                        line_num = content[:line_num].count('\n') + 1 if line_num >= 0 else 0
                        self.violations.append(
                            f"[{layer_name}] {rel_path}:{line_num}: "
                            f"Cannot include '{inc}' (layer {r['layer']} from layer {layer})"
                        )
                        self.stats['violations'] += 1

    def check_duplicates(self) -> None:
        """Check for duplicate implementations."""
        for component, files in DUPLICATE_IMPLEMENTATIONS.items():
            existing = []
            for f in files:
                path = self.root_dir / f
                if path.exists():
                    existing.append(f)
            
            if len(existing) > 1:
                self.warnings.append(
                    f"Duplicate implementations of {component}: {', '.join(existing)}"
                )
                self.stats['warnings'] += 1

    def scan_directory(self) -> None:
        """Scan all source files."""
        src_dir = self.root_dir / 'src'
        
        if not src_dir.exists():
            print(f"Error: {src_dir} does not exist")
            return

        for pattern in ['**/*.cpp', '**/*.h', '**/*.hpp', '**/*.c']:
            for filepath in src_dir.glob(pattern):
                self.check_file(filepath)

    def generate_report(self) -> str:
        """Generate a report of findings."""
        lines = []
        lines.append("=" * 80)
        lines.append("RawrXD Architecture Enforcement Report")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Files checked: {self.stats['files_checked']}")
        lines.append(f"Violations: {self.stats['violations']}")
        lines.append(f"Warnings: {self.stats['warnings']}")
        lines.append("")
        
        if self.violations:
            lines.append("-" * 80)
            lines.append("VIOLATIONS (Must Fix)")
            lines.append("-" * 80)
            for v in self.violations:
                lines.append(f"  ❌ {v}")
            lines.append("")
        
        if self.warnings:
            lines.append("-" * 80)
            lines.append("WARNINGS (Should Review)")
            lines.append("-" * 80)
            for w in self.warnings:
                lines.append(f"  ⚠️  {w}")
            lines.append("")
        
        if not self.violations and not self.warnings:
            lines.append("✅ No architectural violations found!")
        
        return '\n'.join(lines)

    def run(self) -> int:
        """Run the enforcement check."""
        print("Scanning for architectural violations...")
        self.scan_directory()
        self.check_duplicates()
        
        report = self.generate_report()
        print(report)
        
        # Write report to file
        report_path = self.root_dir / 'architecture_report.txt'
        report_path.write_text(report)
        print(f"\nReport saved to: {report_path}")
        
        return 1 if self.violations else 0


def main():
    """Main entry point."""
    root_dir = Path(__file__).parent.parent
    
    enforcer = ArchitectureEnforcer(root_dir)
    exit_code = enforcer.run()
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
