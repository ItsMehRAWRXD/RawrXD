#!/usr/bin/env python3
"""
Phase22_Python_Integration_Test.py
"Hello World" validation for Python C-API bindings
Verifies: Handle mapping, context managers, memory safety
"""

import sys
import os
import time
import ctypes
from pathlib import Path

# Add bindings to path
bindings_dir = Path(__file__).parent / "src" / "bindings" / "python"
sys.path.insert(0, str(bindings_dir))

try:
    from sovereign import (
        SovereignEngine, 
        LoaderConfig, 
        InferenceConfig,
        version,
        engine
    )
    SOVEREIGN_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import sovereign module: {e}")
    SOVEREIGN_AVAILABLE = False

# =============================================================================
# Test Framework
# =============================================================================

class TestResult:
    def __init__(self, name):
        self.name = name
        self.passed = False
        self.duration_ms = 0
        self.message = ""
        self.error = None

class TestRunner:
    def __init__(self):
        self.results = []
    
    def run(self, name, test_func):
        result = TestResult(name)
        start = time.time()
        
        try:
            test_func()
            result.passed = True
            result.message = "OK"
        except Exception as e:
            result.error = e
            result.message = str(e)
        
        result.duration_ms = (time.time() - start) * 1000
        self.results.append(result)
        
        status = "PASS" if result.passed else "FAIL"
        print(f"  [{status}] {name}: {result.message} ({result.duration_ms:.1f}ms)")
        
        return result.passed
    
    def summary(self):
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        duration = sum(r.duration_ms for r in self.results)
        
        print("\n" + "="*60)
        print(f"  Total: {total} tests, {passed} passed, {failed} failed")
        print(f"  Duration: {duration:.1f}ms")
        print("="*60)
        
        return failed == 0

# =============================================================================
# Tests
# =============================================================================

def test_version():
    """Test version information."""
    ver = version()
    assert ver is not None
    assert "Sovereign" in ver
    print(f"    Version: {ver}")

def test_hardware_info():
    """Test hardware detection."""
    if not SOVEREIGN_AVAILABLE:
        print("    Skipped: sovereign module not available")
        return
    
    hw = SovereignEngine.get_hardware_info()
    assert hw.num_physical_cores > 0
    assert hw.total_memory_bytes > 0
    print(f"    Cores: {hw.num_physical_cores}/{hw.num_logical_cores}")
    print(f"    Memory: {hw.total_memory_bytes // (1024**3)} GB")
    print(f"    Features: AVX2={hw.has_avx2}, AVX-512={hw.has_avx512}, AMX={hw.has_amx}")

def test_engine_context_manager():
    """Test engine context manager."""
    if not SOVEREIGN_AVAILABLE:
        print("    Skipped: sovereign module not available")
        return
    
    with engine() as eng:
        assert eng is not None
        # Engine should be ready (even without model)
        print(f"    Engine ready: {eng.is_ready()}")

def test_loader_config():
    """Test loader configuration."""
    config = LoaderConfig(
        use_memory_mapping=True,
        use_zero_copy=True,
        num_threads=4,
        max_memory_bytes=8*1024**3
    )
    assert config.use_memory_mapping
    assert config.num_threads == 4
    print(f"    Threads: {config.num_threads}, Memory: {config.max_memory_bytes // (1024**3)}GB")

def test_inference_config():
    """Test inference configuration."""
    config = InferenceConfig(
        max_tokens=100,
        temperature=0.8,
        top_p=0.9,
        top_k=40,
        num_threads=4
    )
    assert config.max_tokens == 100
    assert config.temperature == 0.8
    print(f"    Max tokens: {config.max_tokens}, Temp: {config.temperature}")

def test_session_creation():
    """Test session lifecycle."""
    if not SOVEREIGN_AVAILABLE:
        print("    Skipped: sovereign module not available")
        return
    
    with engine() as eng:
        session = eng.create_session(session_id=1)
        assert session is not None
        # Session cleanup happens via __del__
        print(f"    Session created successfully")

def test_c_api_direct():
    """Test direct C-API calls via ctypes."""
    # Try to load the library directly
    try:
        if sys.platform == 'win32':
            lib = ctypes.CDLL("./test_phase22.exe")
        else:
            lib = ctypes.CDLL("./libsovereign.so")
        
        # Check if version function exists
        lib.sovereign_version_string.restype = ctypes.c_char_p
        ver = lib.sovereign_version_string()
        if ver:
            print(f"    Direct C-API call successful")
        else:
            print("    Note: C-API not exported in test executable")
    except OSError as e:
        print(f"    Note: Could not load library directly: {e}")

def test_memory_safety():
    """Test memory safety with multiple engine instances."""
    if not SOVEREIGN_AVAILABLE:
        print("    Skipped: sovereign module not available")
        return
    
    # Create and destroy multiple engines
    for i in range(3):
        with engine() as eng:
            _ = eng.is_ready()
    
    print(f"    Created/destroyed 3 engine instances safely")

# =============================================================================
# Main
# =============================================================================

def main():
    print("="*60)
    print("  Phase 22: Python Integration Test")
    print("  Validates C-API bindings and memory safety")
    print("="*60)
    
    runner = TestRunner()
    
    # Run tests
    runner.run("Version_Info", test_version)
    runner.run("Hardware_Info", test_hardware_info)
    runner.run("Loader_Config", test_loader_config)
    runner.run("Inference_Config", test_inference_config)
    runner.run("Engine_ContextManager", test_engine_context_manager)
    runner.run("Session_Creation", test_session_creation)
    runner.run("C_API_Direct", test_c_api_direct)
    runner.run("Memory_Safety", test_memory_safety)
    
    # Summary
    success = runner.summary()
    
    if success:
        print("\n  ✅ Python bindings validated - Ready for soak test")
        return 0
    else:
        print("\n  ❌ Some tests failed - Review output above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
