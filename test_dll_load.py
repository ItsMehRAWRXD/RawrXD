#!/usr/bin/env python3
"""
test_dll_load.py
Verify Python can load the sovereign.dll and call C-API functions
"""

import ctypes
import os
import sys
from pathlib import Path

def test_dll_load():
    """Test loading the sovereign.dll"""
    print("=" * 60)
    print("  Sovereign DLL Load Test")
    print("=" * 60)
    
    # Find the DLL
    dll_paths = [
        Path("./build/bindings/sovereign.dll").resolve(),
        Path("./sovereign.dll").resolve(),
        Path("../build/bindings/sovereign.dll").resolve(),
    ]
    
    dll_path = None
    for path in dll_paths:
        if path.exists():
            dll_path = path
            break
    
    if not dll_path:
        print("❌ DLL not found in expected locations:")
        for path in dll_paths:
            print(f"   - {path}")
        return False
    
    print(f"✓ Found DLL: {dll_path}")
    print(f"  Size: {dll_path.stat().st_size / 1024:.2f} KB")
    
    # Load the DLL
    try:
        sovereign = ctypes.CDLL(str(dll_path))
        print(f"✓ DLL loaded successfully")
    except OSError as e:
        print(f"❌ Failed to load DLL: {e}")
        return False
    
    # Test version function
    try:
        sovereign.sovereign_version_string.restype = ctypes.c_char_p
        version = sovereign.sovereign_version_string()
        if version:
            print(f"✓ Version: {version.decode('utf-8')}")
        else:
            print("⚠ Version returned NULL")
    except AttributeError:
        print("⚠ sovereign_version_string not exported")
    except Exception as e:
        print(f"⚠ Version check failed: {e}")
    
    # Test init/shutdown
    try:
        sovereign.sovereign_init.restype = ctypes.c_int
        result = sovereign.sovereign_init()
        if result == 0:
            print(f"✓ Library initialized")
            
            # Cleanup
            sovereign.sovereign_shutdown()
            print(f"✓ Library shutdown")
        else:
            print(f"⚠ Init returned: {result}")
    except AttributeError:
        print("⚠ sovereign_init not exported")
    except Exception as e:
        print(f"⚠ Init test failed: {e}")
    
    # Test hardware info
    try:
        class HardwareInfo(ctypes.Structure):
            _fields_ = [
                ("has_avx2", ctypes.c_int),
                ("has_avx512", ctypes.c_int),
                ("has_amx", ctypes.c_int),
                ("num_physical_cores", ctypes.c_int),
                ("num_logical_cores", ctypes.c_int),
                ("total_memory_bytes", ctypes.c_uint64),
                ("available_memory_bytes", ctypes.c_uint64),
            ]
        
        sovereign.sovereign_get_hardware_info.argtypes = [ctypes.POINTER(HardwareInfo)]
        sovereign.sovereign_get_hardware_info.restype = ctypes.c_int
        
        hw = HardwareInfo()
        result = sovereign.sovereign_get_hardware_info(ctypes.byref(hw))
        
        if result == 0:
            print(f"✓ Hardware detected:")
            print(f"    Cores: {hw.num_physical_cores}/{hw.num_logical_cores}")
            print(f"    Memory: {hw.total_memory_bytes // (1024**3)} GB")
            print(f"    AVX2: {bool(hw.has_avx2)}, AVX-512: {bool(hw.has_avx512)}, AMX: {bool(hw.has_amx)}")
        else:
            print(f"⚠ Hardware info returned: {result}")
    except AttributeError:
        print("⚠ sovereign_get_hardware_info not exported")
    except Exception as e:
        print(f"⚠ Hardware info test failed: {e}")
    
    print("\n" + "=" * 60)
    print("  DLL Load Test Complete")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = test_dll_load()
    sys.exit(0 if success else 1)
