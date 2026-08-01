#!/usr/bin/env python3
"""
RAWRXD Compiler Smoke Test Suite
Validates that all production compilers work correctly
"""

import subprocess
import json
import os
import sys
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class TestStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class TestResult:
    name: str
    status: TestStatus
    duration_ms: float
    checks: Dict[str, bool]
    output: str
    error: str = ""

# Test configuration
TEST_CASES = [
    {
        "name": "C Hello World",
        "source": "tests/compiler/c/hello_world.c",
        "language": "c",
        "expected_compile": True,
        "expected_run": True,
        "expected_output": "Hello, World!\n",
    },
    {
        "name": "ASM Minimal",
        "source": "tests/compiler/asm/hello_world.asm",
        "language": "asm",
        "expected_compile": True,
        "expected_run": True,
        "expected_output": "",
        "expected_exit_code": 0,
    },
    {
        "name": "C# Parse Test",
        "source": "tests/compiler/csharp/hello_world.cs",
        "language": "csharp",
        "expected_compile": True,
        "expected_run": False,  # Roslyn test only parses
        "expected_output": "",
    },
]

class RAWRXDTester:
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.bin_dir = self.base_dir / "bin"
        self.temp_dir = None
        self.results: List[TestResult] = []
        
    def setup(self):
        """Create temporary directory for test outputs"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="rawrxd_test_"))
        print(f"Test output directory: {self.temp_dir}")
        
    def cleanup(self):
        """Remove temporary directory"""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def find_compiler(self, language: str) -> Optional[Path]:
        """Find the appropriate compiler executable"""
        compiler_map = {
            "c": "rawrxd-c.exe",
            "asm": "rawrxd-asm.exe",
            "csharp": "micro-roslyn.exe",
        }
        
        exe_name = compiler_map.get(language)
        if not exe_name:
            return None
            
        compiler_path = self.bin_dir / exe_name
        if compiler_path.exists():
            return compiler_path
            
        # Try alternative locations
        alt_paths = [
            self.base_dir / "compilers" / "native_toolchain" / exe_name,
            self.base_dir / "enterprise_kernel" / "bin" / exe_name,
            self.base_dir / exe_name,
        ]
        
        for path in alt_paths:
            if path.exists():
                return path
                
        return None
        
    def run_compile(self, source: Path, output: Path, language: str) -> Tuple[bool, str, str]:
        """Run compilation and return (success, stdout, stderr)"""
        compiler = self.find_compiler(language)
        if not compiler:
            return False, "", f"Compiler not found for language: {language}"
            
        cmd = [str(compiler), str(source), str(output)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=self.base_dir
            )
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Compilation timed out"
        except Exception as e:
            return False, "", str(e)
            
    def run_executable(self, exe_path: Path, timeout: int = 5) -> Tuple[bool, str, str, int]:
        """Run compiled executable and return (success, stdout, stderr, exit_code)"""
        try:
            result = subprocess.run(
                [str(exe_path)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return True, result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return False, "", "Execution timed out", -1
        except Exception as e:
            return False, "", str(e), -1
            
    def run_test(self, test_case: Dict) -> TestResult:
        """Run a single test case"""
        import time
        
        name = test_case["name"]
        source = self.base_dir / test_case["source"]
        language = test_case["language"]
        
        print(f"\nRunning: {name}")
        print(f"  Source: {source}")
        
        if not source.exists():
            return TestResult(
                name=name,
                status=TestStatus.FAILED,
                duration_ms=0,
                checks={"source_exists": False},
                output="",
                error=f"Source file not found: {source}"
            )
            
        start_time = time.time()
        checks = {}
        
        # Determine output path
        output_name = f"test_{name.replace(' ', '_').lower()}.exe"
        output_path = self.temp_dir / output_name
        
        # Compile
        compile_success, compile_stdout, compile_stderr = self.run_compile(
            source, output_path, language
        )
        
        checks["compile_exit_code"] = compile_success
        checks["artifact_exists"] = output_path.exists()
        
        # Run if compilation succeeded and expected
        run_success = False
        run_output = ""
        exit_code = -1
        
        if compile_success and output_path.exists() and test_case.get("expected_run", True):
            run_success, run_output, run_stderr, exit_code = self.run_executable(output_path)
            checks["artifact_runs"] = run_success
            checks["exit_code_correct"] = (exit_code == test_case.get("expected_exit_code", 0))
        else:
            checks["artifact_runs"] = False
            checks["exit_code_correct"] = True  # Not applicable
            
        # Check output
        if "expected_output" in test_case:
            checks["output_matches"] = (run_output == test_case["expected_output"])
        else:
            checks["output_matches"] = True
            
        duration_ms = (time.time() - start_time) * 1000
        
        # Determine overall status
        all_passed = all(checks.values())
        status = TestStatus.PASSED if all_passed else TestStatus.FAILED
        
        # Build output summary
        output_parts = []
        if compile_stdout:
            output_parts.append(f"Compile stdout:\n{compile_stdout}")
        if compile_stderr:
            output_parts.append(f"Compile stderr:\n{compile_stderr}")
        if run_output:
            output_parts.append(f"Run stdout:\n{run_output}")
            
        output = "\n".join(output_parts)
        
        error = ""
        if not checks["compile_exit_code"]:
            error = f"Compilation failed: {compile_stderr}"
        elif not checks["artifact_exists"]:
            error = "Output artifact not created"
        elif test_case.get("expected_run", True) and not checks["artifact_runs"]:
            error = "Artifact failed to run"
        elif not checks["output_matches"]:
            error = f"Output mismatch. Expected: {repr(test_case.get('expected_output', ''))}, Got: {repr(run_output)}"
            
        return TestResult(
            name=name,
            status=status,
            duration_ms=duration_ms,
            checks=checks,
            output=output,
            error=error
        )
        
    def run_all_tests(self) -> bool:
        """Run all test cases"""
        print("=" * 60)
        print("RAWRXD Compiler Smoke Test Suite")
        print("=" * 60)
        
        self.setup()
        
        try:
            passed = 0
            failed = 0
            skipped = 0
            
            for test_case in TEST_CASES:
                result = self.run_test(test_case)
                self.results.append(result)
                
                if result.status == TestStatus.PASSED:
                    passed += 1
                    print(f"  ✅ PASSED ({result.duration_ms:.1f}ms)")
                elif result.status == TestStatus.FAILED:
                    failed += 1
                    print(f"  ❌ FAILED ({result.duration_ms:.1f}ms)")
                    if result.error:
                        print(f"     Error: {result.error}")
                else:
                    skipped += 1
                    print(f"  ⏭️  SKIPPED")
                    
            # Print summary
            print("\n" + "=" * 60)
            print("Test Summary")
            print("=" * 60)
            print(f"Total:  {len(TEST_CASES)}")
            print(f"Passed: {passed}")
            print(f"Failed: {failed}")
            print(f"Skipped: {skipped}")
            
            if failed > 0:
                print("\nFailed Tests:")
                for result in self.results:
                    if result.status == TestStatus.FAILED:
                        print(f"  - {result.name}")
                        print(f"    Checks:")
                        for check, status in result.checks.items():
                            status_str = "✅" if status else "❌"
                            print(f"      {status_str} {check}")
                            
            return failed == 0
            
        finally:
            self.cleanup()
            
    def generate_report(self, output_path: str):
        """Generate JSON test report"""
        report = {
            "timestamp": "2026-07-19T00:00:00Z",
            "total_tests": len(self.results),
            "passed": sum(1 for r in self.results if r.status == TestStatus.PASSED),
            "failed": sum(1 for r in self.results if r.status == TestStatus.FAILED),
            "results": [
                {
                    "name": r.name,
                    "status": r.status.value,
                    "duration_ms": r.duration_ms,
                    "checks": r.checks,
                    "error": r.error
                }
                for r in self.results
            ]
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"\nReport written to: {output_path}")

def main():
    """Main entry point"""
    # Determine base directory
    script_dir = Path(__file__).parent
    base_dir = script_dir.parent.parent  # Go up to rawrxd-ci-bootstrap
    
    # Allow override via command line
    if len(sys.argv) > 1:
        base_dir = Path(sys.argv[1])
        
    print(f"Base directory: {base_dir.absolute()}")
    
    # Run tests
    tester = RAWRXDTester(base_dir)
    success = tester.run_all_tests()
    
    # Generate report
    report_path = base_dir / "tests" / "validation" / "test_report.json"
    tester.generate_report(report_path)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
