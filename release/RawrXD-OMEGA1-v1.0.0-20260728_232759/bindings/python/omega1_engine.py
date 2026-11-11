#!/usr/bin/env python3
# ═════════════════════════════════════════════════════════════════════════════
# OMEGA-1 Engine Python ctypes Bindings
# Rapid prototyping interface for IAT slots 64-75
# ═════════════════════════════════════════════════════════════════════════════

import ctypes
import ctypes.wintypes
from ctypes import c_void_p, c_uint, c_bool, c_char_p, POINTER, create_string_buffer
from enum import IntEnum, IntFlag
from typing import Optional, List
import os
import sys

# ═════════════════════════════════════════════════════════════════════════════
# Constants
# ═════════════════════════════════════════════════════════════════════════════

OMEGA1_VERSION_MAJOR = 1
OMEGA1_VERSION_MINOR = 0
OMEGA1_VERSION_PATCH = 0

# ═════════════════════════════════════════════════════════════════════════════
# Enums
# ═════════════════════════════════════════════════════════════════════════════

class MutationType(IntEnum):
    NONE = 0
    HOTPATCH = 1
    REFLECTIVE = 2
    GENESIS = 3

class Omega1Status(IntEnum):
    OK = 0
    ERROR = 1
    NOT_INITIALIZED = 2
    MUTATION = 3

class Omega1Flags(IntFlag):
    NONE = 0x00000000
    VERBOSE = 0x00000001
    STRICT = 0x00000002
    MUTANT = 0x00000004

# ═════════════════════════════════════════════════════════════════════════════
# Exceptions
# ═════════════════════════════════════════════════════════════════════════════

class Omega1Error(Exception):
    """Base exception for OMEGA-1 errors"""
    pass

class InitializationError(Omega1Error):
    """Failed to initialize OMEGA-1 engine"""
    pass

class OperationError(Omega1Error):
    """Operation failed"""
    pass

class ModuleNotFoundError(Omega1Error):
    """PowerShell module not found"""
    pass

# ═════════════════════════════════════════════════════════════════════════════
# Low-level FFI
# ═════════════════════════════════════════════════════════════════════════════

class Omega1FFI:
    """Low-level ctypes wrapper for OMEGA-1 DLL"""
    
    _instance = None
    
    def __new__(cls, dll_path: Optional[str] = None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init(dll_path)
        return cls._instance
    
    def _init(self, dll_path: Optional[str] = None):
        """Initialize the DLL"""
        if dll_path is None:
            # Try to find the DLL in common locations
            search_paths = [
                "Omega1Engine.dll",
                "../Omega1Engine.dll",
                "../../build/Omega1Engine.dll",
                "./omega1_modules/Omega1Engine.dll",
            ]
            for path in search_paths:
                if os.path.exists(path):
                    dll_path = path
                    break
        
        if dll_path is None or not os.path.exists(dll_path):
            raise InitializationError(f"Omega1Engine.dll not found. Searched: {search_paths}")
        
        self._dll = ctypes.CDLL(dll_path)
        self._setup_functions()
    
    def _setup_functions(self):
        """Configure function signatures"""
        
        # Slot 64: Initialize
        self.Omega1_Initialize = self._dll.Omega1_Initialize
        self.Omega1_Initialize.argtypes = [POINTER(c_void_p), c_uint]
        self.Omega1_Initialize.restype = c_bool
        
        # Slot 65: Shutdown
        self.Omega1_Shutdown = self._dll.Omega1_Shutdown
        self.Omega1_Shutdown.argtypes = [c_void_p]
        self.Omega1_Shutdown.restype = None
        
        # Slot 66: GetModuleCount
        self.Omega1_GetModuleCount = self._dll.Omega1_GetModuleCount
        self.Omega1_GetModuleCount.argtypes = [c_void_p]
        self.Omega1_GetModuleCount.restype = c_uint
        
        # Slot 67: IsMutant
        self.Omega1_IsMutant = self._dll.Omega1_IsMutant
        self.Omega1_IsMutant.argtypes = [c_void_p]
        self.Omega1_IsMutant.restype = c_bool
        
        # Slot 68: GetMutationCount
        self.Omega1_GetMutationCount = self._dll.Omega1_GetMutationCount
        self.Omega1_GetMutationCount.argtypes = [c_void_p]
        self.Omega1_GetMutationCount.restype = c_uint
        
        # Slot 69: ExecuteReflective
        self.Omega1_ExecuteReflective = self._dll.Omega1_ExecuteReflective
        self.Omega1_ExecuteReflective.argtypes = [c_void_p, c_char_p, c_uint, c_char_p, c_uint]
        self.Omega1_ExecuteReflective.restype = c_bool
        
        # Slot 70: ValidateIntegrity
        self.Omega1_ValidateIntegrity = self._dll.Omega1_ValidateIntegrity
        self.Omega1_ValidateIntegrity.argtypes = [c_void_p, POINTER(c_uint)]
        self.Omega1_ValidateIntegrity.restype = c_bool
        
        # Slot 71: TriggerMutation
        self.Omega1_TriggerMutation = self._dll.Omega1_TriggerMutation
        self.Omega1_TriggerMutation.argtypes = [c_void_p, c_uint]
        self.Omega1_TriggerMutation.restype = c_bool
        
        # Slot 72: GetManifestJson
        self.Omega1_GetManifestJson = self._dll.Omega1_GetManifestJson
        self.Omega1_GetManifestJson.argtypes = [c_void_p, c_char_p, c_uint]
        self.Omega1_GetManifestJson.restype = c_bool
        
        # Slot 73: ExecutePowerShell
        self.Omega1_ExecutePowerShell = self._dll.Omega1_ExecutePowerShell
        self.Omega1_ExecutePowerShell.argtypes = [c_void_p, c_char_p, c_char_p, c_uint]
        self.Omega1_ExecutePowerShell.restype = c_bool
        
        # Slot 74: LoadModule
        self.Omega1_LoadModule = self._dll.Omega1_LoadModule
        self.Omega1_LoadModule.argtypes = [c_void_p, c_char_p]
        self.Omega1_LoadModule.restype = c_void_p
        
        # Slot 75: InvokeModule
        self.Omega1_InvokeModule = self._dll.Omega1_InvokeModule
        self.Omega1_InvokeModule.argtypes = [c_void_p, c_void_p, c_char_p, c_char_p, c_uint]
        self.Omega1_InvokeModule.restype = c_bool
        
        # C API
        self.Omega1_CreateContext = self._dll.Omega1_CreateContext
        self.Omega1_CreateContext.argtypes = []
        self.Omega1_CreateContext.restype = c_void_p
        
        self.Omega1_DestroyContext = self._dll.Omega1_DestroyContext
        self.Omega1_DestroyContext.argtypes = [c_void_p]
        self.Omega1_DestroyContext.restype = None
        
        self.Omega1_GetVersion = self._dll.Omega1_GetVersion
        self.Omega1_GetVersion.argtypes = [c_char_p, c_uint]
        self.Omega1_GetVersion.restype = c_uint
        
        self.Omega1_GetStatus = self._dll.Omega1_GetStatus
        self.Omega1_GetStatus.argtypes = [c_void_p]
        self.Omega1_GetStatus.restype = c_uint

# ═════════════════════════════════════════════════════════════════════════════
# High-level Pythonic API
# ═════════════════════════════════════════════════════════════════════════════

class Omega1Engine:
    """
    High-level Python wrapper for OMEGA-1 Engine
    
    Usage:
        engine = Omega1Engine()
        engine.initialize()
        
        # Execute PowerShell
        result = engine.execute_powershell("Get-Date")
        print(result)
        
        # Get manifest
        manifest = engine.get_manifest_json()
        print(manifest)
    """
    
    def __init__(self, dll_path: Optional[str] = None):
        self._ffi = Omega1FFI(dll_path)
        self._handle: Optional[int] = None
        self._modules: dict = {}
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
    
    def initialize(self, flags: Omega1Flags = Omega1Flags.NONE) -> None:
        """Initialize the OMEGA-1 engine"""
        if self._handle is not None:
            raise InitializationError("Already initialized")
        
        handle = c_void_p()
        result = self._ffi.Omega1_Initialize(ctypes.byref(handle), flags)
        
        if not result or not handle.value:
            raise InitializationError("Omega1_Initialize failed")
        
        self._handle = handle.value
    
    def initialize_simple(self) -> None:
        """Initialize using simple C API"""
        if self._handle is not None:
            raise InitializationError("Already initialized")
        
        handle = self._ffi.Omega1_CreateContext()
        
        if not handle:
            raise InitializationError("Omega1_CreateContext failed")
        
        self._handle = handle
    
    def shutdown(self) -> None:
        """Shutdown and cleanup"""
        if self._handle is not None:
            self._ffi.Omega1_Shutdown(self._handle)
            self._handle = None
            self._modules.clear()
    
    def _ensure_initialized(self):
        """Ensure engine is initialized"""
        if self._handle is None:
            raise OperationError("Engine not initialized")
    
    # ═════════════════════════════════════════════════════════════════
    # Properties
    # ═════════════════════════════════════════════════════════════════
    
    @property
    def module_count(self) -> int:
        """Get number of loaded modules"""
        self._ensure_initialized()
        return self._ffi.Omega1_GetModuleCount(self._handle)
    
    @property
    def is_mutant(self) -> bool:
        """Check if this is a mutant instance"""
        self._ensure_initialized()
        return self._ffi.Omega1_IsMutant(self._handle)
    
    @property
    def mutation_count(self) -> int:
        """Get mutation count"""
        self._ensure_initialized()
        return self._ffi.Omega1_GetMutationCount(self._handle)
    
    @property
    def status(self) -> Omega1Status:
        """Get engine status"""
        self._ensure_initialized()
        return Omega1Status(self._ffi.Omega1_GetStatus(self._handle))
    
    @staticmethod
    def version() -> str:
        """Get OMEGA-1 version"""
        ffi = Omega1FFI()
        buffer = create_string_buffer(256)
        ffi.Omega1_GetVersion(buffer, 256)
        return buffer.value.decode('utf-8', errors='ignore')
    
    # ═════════════════════════════════════════════════════════════════
    # Methods
    # ═════════════════════════════════════════════════════════════════
    
    def execute_reflective(self, payload: str) -> str:
        """Execute a reflective payload"""
        self._ensure_initialized()
        
        output = create_string_buffer(4096)
        payload_bytes = payload.encode('utf-8')
        
        result = self._ffi.Omega1_ExecuteReflective(
            self._handle,
            payload_bytes,
            len(payload_bytes),
            output,
            4096
        )
        
        if not result:
            raise OperationError("ExecuteReflective failed")
        
        return output.value.decode('utf-8', errors='ignore')
    
    def validate_integrity(self) -> int:
        """Validate engine integrity and return checksum"""
        self._ensure_initialized()
        
        checksum = c_uint()
        result = self._ffi.Omega1_ValidateIntegrity(self._handle, ctypes.byref(checksum))
        
        if not result:
            raise OperationError("ValidateIntegrity failed")
        
        return checksum.value
    
    def trigger_mutation(self, mutation_type: MutationType) -> None:
        """Trigger a mutation"""
        self._ensure_initialized()
        
        result = self._ffi.Omega1_TriggerMutation(self._handle, mutation_type)
        
        if not result:
            raise OperationError("TriggerMutation failed")
    
    def get_manifest_json(self) -> str:
        """Get manifest as JSON string"""
        self._ensure_initialized()
        
        buffer = create_string_buffer(8192)
        result = self._ffi.Omega1_GetManifestJson(self._handle, buffer, 8192)
        
        if not result:
            raise OperationError("GetManifestJson failed")
        
        return buffer.value.decode('utf-8', errors='ignore')
    
    def execute_powershell(self, command: str) -> str:
        """Execute PowerShell command"""
        self._ensure_initialized()
        
        output = create_string_buffer(4096)
        command_bytes = command.encode('utf-8')
        
        result = self._ffi.Omega1_ExecutePowerShell(
            self._handle,
            command_bytes,
            output,
            4096
        )
        
        if not result:
            raise OperationError("ExecutePowerShell failed")
        
        return output.value.decode('utf-8', errors='ignore')
    
    def load_module(self, module_name: str) -> int:
        """Load a PowerShell module, returns handle"""
        self._ensure_initialized()
        
        name_bytes = module_name.encode('utf-8')
        handle = self._ffi.Omega1_LoadModule(self._handle, name_bytes)
        
        if not handle:
            raise ModuleNotFoundError(f"Module not found: {module_name}")
        
        self._modules[module_name] = handle
        return handle
    
    def invoke_module(self, module_handle: int, function: str) -> str:
        """Invoke a function from a loaded module"""
        self._ensure_initialized()
        
        output = create_string_buffer(4096)
        function_bytes = function.encode('utf-8')
        
        result = self._ffi.Omega1_InvokeModule(
            self._handle,
            module_handle,
            function_bytes,
            output,
            4096
        )
        
        if not result:
            raise OperationError(f"InvokeModule failed: {function}")
        
        return output.value.decode('utf-8', errors='ignore')
    
    def invoke_module_by_name(self, module_name: str, function: str) -> str:
        """Invoke a function by module name (auto-loads if needed)"""
        if module_name not in self._modules:
            self.load_module(module_name)
        
        return self.invoke_module(self._modules[module_name], function)

# ═════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═════════════════════════════════════════════════════════════════════════════

def quick_powershell(command: str) -> str:
    """Quick one-liner to execute PowerShell"""
    with Omega1Engine() as engine:
        engine.initialize_simple()
        return engine.execute_powershell(command)

def get_manifest() -> str:
    """Quick one-liner to get manifest"""
    with Omega1Engine() as engine:
        engine.initialize_simple()
        return engine.get_manifest_json()

# ═════════════════════════════════════════════════════════════════════════════
# CLI Interface
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="OMEGA-1 Engine Python CLI")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--manifest", action="store_true", help="Get manifest")
    parser.add_argument("--powershell", "-p", metavar="CMD", help="Execute PowerShell")
    parser.add_argument("--module", "-m", metavar="NAME", help="Load module")
    parser.add_argument("--invoke", "-i", metavar="FUNC", help="Invoke function")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"OMEGA-1 Engine Version: {Omega1Engine.version()}")
    
    elif args.manifest:
        print(get_manifest())
    
    elif args.powershell:
        print(quick_powershell(args.powershell))
    
    elif args.module and args.invoke:
        with Omega1Engine() as engine:
            engine.initialize_simple()
            engine.load_module(args.module)
            result = engine.invoke_module_by_name(args.module, args.invoke)
            print(result)
    
    else:
        parser.print_help()
