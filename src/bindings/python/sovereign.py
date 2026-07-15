"""
sovereign.py
Python bindings for the Sovereign Engine C-API
"""

import ctypes
import os
import sys
from typing import List, Optional, Callable, Dict, Any
from dataclasses import dataclass
from contextlib import contextmanager

# =============================================================================
# Load the shared library
# =============================================================================

def _find_library():
    """Find the Sovereign Engine library."""
    if sys.platform == 'win32':
        lib_name = 'sovereign.dll'
    elif sys.platform == 'darwin':
        lib_name = 'libsovereign.dylib'
    else:
        lib_name = 'libsovereign.so'
    
    # Check common locations
    search_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'build', lib_name),
        os.path.join(os.path.dirname(__file__), lib_name),
        lib_name,
    ]
    
    for path in search_paths:
        if os.path.exists(path):
            return path
    
    return lib_name  # Let ctypes try to find it

try:
    _lib = ctypes.CDLL(_find_library())
except OSError as e:
    raise ImportError(f"Could not load Sovereign Engine library: {e}")

# =============================================================================
# Type Definitions
# =============================================================================

class SovereignError(Exception):
    """Base exception for Sovereign Engine errors."""
    
    ERROR_CODES = {
        0: "OK",
        -1: "Invalid argument",
        -2: "Out of memory",
        -3: "Model load failed",
        -4: "Not initialized",
        -5: "Session not found",
        -6: "Generation failed",
        -7: "Tokenization failed",
        -8: "Unsupported operation",
        -9: "Hardware not available",
    }
    
    def __init__(self, code: int):
        self.code = code
        message = self.ERROR_CODES.get(code, f"Unknown error {code}")
        super().__init__(message)

def _check_error(code: int):
    """Check error code and raise exception if needed."""
    if code != 0:
        raise SovereignError(code)

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class LoaderConfig:
    """Configuration for model loading."""
    use_memory_mapping: bool = True
    use_zero_copy: bool = True
    use_prefetch: bool = True
    enable_amx_tiling: bool = True
    num_threads: int = 4
    max_memory_bytes: int = 32 * 1024 * 1024 * 1024  # 32GB

@dataclass
class InferenceConfig:
    """Configuration for inference."""
    max_tokens: int = 100
    temperature: float = 0.8
    top_p: float = 0.9
    top_k: int = 40
    num_threads: int = 4
    use_amx: bool = True
    use_int8: bool = True
    enable_kv_cache: bool = True
    max_memory_bytes: int = 32 * 1024 * 1024 * 1024  # 32GB

@dataclass
class EngineStats:
    """Engine statistics."""
    tokens_generated: int
    total_tokens: int
    avg_tokens_per_second: float
    avg_latency_ms: float
    model_memory_bytes: int
    kv_cache_memory_bytes: int
    load_time_ms: float

@dataclass
class GenerationResult:
    """Result of token generation."""
    token_id: int
    logit: float
    probability: float
    generation_index: int
    generation_time_ms: float
    is_eos: bool

@dataclass
class HardwareInfo:
    """Hardware information."""
    has_avx2: bool
    has_avx512: bool
    has_amx: bool
    num_physical_cores: int
    num_logical_cores: int
    total_memory_bytes: int
    available_memory_bytes: int

# =============================================================================
# C Structures
# =============================================================================

class _LoaderConfigC(ctypes.Structure):
    _fields_ = [
        ("use_memory_mapping", ctypes.c_int),
        ("use_zero_copy", ctypes.c_int),
        ("use_prefetch", ctypes.c_int),
        ("enable_amx_tiling", ctypes.c_int),
        ("num_threads", ctypes.c_uint32),
        ("max_memory_bytes", ctypes.c_uint64),
    ]

class _InferenceConfigC(ctypes.Structure):
    _fields_ = [
        ("max_tokens", ctypes.c_uint32),
        ("temperature", ctypes.c_float),
        ("top_p", ctypes.c_float),
        ("top_k", ctypes.c_uint32),
        ("num_threads", ctypes.c_uint32),
        ("use_amx", ctypes.c_int),
        ("use_int8", ctypes.c_int),
        ("enable_kv_cache", ctypes.c_int),
        ("max_memory_bytes", ctypes.c_uint64),
    ]

class _StatsC(ctypes.Structure):
    _fields_ = [
        ("tokens_generated", ctypes.c_uint64),
        ("total_tokens", ctypes.c_uint64),
        ("avg_tokens_per_second", ctypes.c_double),
        ("avg_latency_ms", ctypes.c_double),
        ("model_memory_bytes", ctypes.c_uint64),
        ("kv_cache_memory_bytes", ctypes.c_uint64),
        ("load_time_ms", ctypes.c_double),
    ]

class _GenerationResultC(ctypes.Structure):
    _fields_ = [
        ("token_id", ctypes.c_uint32),
        ("logit", ctypes.c_float),
        ("probability", ctypes.c_float),
        ("generation_index", ctypes.c_uint32),
        ("generation_time_ms", ctypes.c_double),
        ("is_eos", ctypes.c_int),
    ]

class _HardwareInfoC(ctypes.Structure):
    _fields_ = [
        ("has_avx2", ctypes.c_int),
        ("has_avx512", ctypes.c_int),
        ("has_amx", ctypes.c_int),
        ("num_physical_cores", ctypes.c_int),
        ("num_logical_cores", ctypes.c_int),
        ("total_memory_bytes", ctypes.c_uint64),
        ("available_memory_bytes", ctypes.c_uint64),
    ]

# =============================================================================
# Function Signatures
# =============================================================================

_lib.sovereign_version_string.restype = ctypes.c_char_p
_lib.sovereign_init.restype = ctypes.c_int
_lib.sovereign_shutdown.restype = None

_lib.sovereign_engine_create.argtypes = [
    ctypes.POINTER(_LoaderConfigC),
    ctypes.POINTER(_InferenceConfigC),
    ctypes.POINTER(ctypes.c_void_p)
]
_lib.sovereign_engine_create.restype = ctypes.c_int

_lib.sovereign_engine_destroy.argtypes = [ctypes.c_void_p]
_lib.sovereign_engine_destroy.restype = None

_lib.sovereign_engine_load_model.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_lib.sovereign_engine_load_model.restype = ctypes.c_int

_lib.sovereign_engine_is_ready.argtypes = [ctypes.c_void_p]
_lib.sovereign_engine_is_ready.restype = ctypes.c_int

_lib.sovereign_engine_get_stats.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(_StatsC)
]
_lib.sovereign_engine_get_stats.restype = ctypes.c_int

_lib.sovereign_session_create.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_void_p)
]
_lib.sovereign_session_create.restype = ctypes.c_int

_lib.sovereign_session_destroy.argtypes = [ctypes.c_void_p]
_lib.sovereign_session_destroy.restype = None

_lib.sovereign_generate.argtypes = [
    ctypes.c_void_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_uint32)
]
_lib.sovereign_generate.restype = ctypes.c_int

_lib.sovereign_get_hardware_info.argtypes = [ctypes.POINTER(_HardwareInfoC)]
_lib.soweign_get_hardware_info.restype = ctypes.c_int

# =============================================================================
# Python API
# =============================================================================

class SovereignEngine:
    """High-level Python interface to the Sovereign Engine."""
    
    def __init__(self, 
                 loader_config: Optional[LoaderConfig] = None,
                 inference_config: Optional[InferenceConfig] = None):
        """Initialize the engine."""
        self._loader_config = loader_config or LoaderConfig()
        self._inference_config = inference_config or InferenceConfig()
        self._engine = ctypes.c_void_p()
        
        # Convert to C structures
        loader_c = _LoaderConfigC(
            use_memory_mapping=int(self._loader_config.use_memory_mapping),
            use_zero_copy=int(self._loader_config.use_zero_copy),
            use_prefetch=int(self._loader_config.use_prefetch),
            enable_amx_tiling=int(self._loader_config.enable_amx_tiling),
            num_threads=self._loader_config.num_threads,
            max_memory_bytes=self._loader_config.max_memory_bytes,
        )
        
        inference_c = _InferenceConfigC(
            max_tokens=self._inference_config.max_tokens,
            temperature=self._inference_config.temperature,
            top_p=self._inference_config.top_p,
            top_k=self._inference_config.top_k,
            num_threads=self._inference_config.num_threads,
            use_amx=int(self._inference_config.use_amx),
            use_int8=int(self._inference_config.use_int8),
            enable_kv_cache=int(self._inference_config.enable_kv_cache),
            max_memory_bytes=self._inference_config.max_memory_bytes,
        )
        
        # Initialize library
        _check_error(_lib.sovereign_init())
        
        # Create engine
        _check_error(_lib.sovereign_engine_create(
            ctypes.byref(loader_c),
            ctypes.byref(inference_c),
            ctypes.byref(self._engine)
        ))
    
    def __del__(self):
        """Cleanup."""
        if hasattr(self, '_engine') and self._engine:
            _lib.sovereign_engine_destroy(self._engine)
            _lib.sovereign_shutdown()
    
    def load_model(self, model_path: str) -> None:
        """Load a model from file."""
        _check_error(_lib.sovereign_engine_load_model(
            self._engine, model_path.encode('utf-8')
        ))
    
    def is_ready(self) -> bool:
        """Check if the engine is ready."""
        return bool(_lib.sovereign_engine_is_ready(self._engine))
    
    def get_stats(self) -> EngineStats:
        """Get engine statistics."""
        stats_c = _StatsC()
        _check_error(_lib.sovereign_engine_get_stats(
            self._engine, ctypes.byref(stats_c)
        ))
        return EngineStats(
            tokens_generated=stats_c.tokens_generated,
            total_tokens=stats_c.total_tokens,
            avg_tokens_per_second=stats_c.avg_tokens_per_second,
            avg_latency_ms=stats_c.avg_latency_ms,
            model_memory_bytes=stats_c.model_memory_bytes,
            kv_cache_memory_bytes=stats_c.kv_cache_memory_bytes,
            load_time_ms=stats_c.load_time_ms,
        )
    
    def create_session(self, session_id: int = 0) -> 'SovereignSession':
        """Create a new inference session."""
        return SovereignSession(self, session_id)
    
    @staticmethod
    def get_hardware_info() -> HardwareInfo:
        """Get hardware information."""
        info_c = _HardwareInfoC()
        _check_error(_lib.sovereign_get_hardware_info(ctypes.byref(info_c)))
        return HardwareInfo(
            has_avx2=bool(info_c.has_avx2),
            has_avx512=bool(info_c.has_avx512),
            has_amx=bool(info_c.has_amx),
            num_physical_cores=info_c.num_physical_cores,
            num_logical_cores=info_c.num_logical_cores,
            total_memory_bytes=info_c.total_memory_bytes,
            available_memory_bytes=info_c.available_memory_bytes,
        )


class SovereignSession:
    """Inference session for text generation."""
    
    def __init__(self, engine: SovereignEngine, session_id: int = 0):
        """Create a session."""
        self._engine = engine
        self._session = ctypes.c_void_p()
        _check_error(_lib.sovereign_session_create(
            engine._engine,
            session_id,
            ctypes.byref(self._session)
        ))
    
    def __del__(self):
        """Cleanup."""
        if hasattr(self, '_session') and self._session:
            _lib.sovereign_session_destroy(self._session)
    
    def generate(self, prompt: str, max_length: int = 1024) -> str:
        """Generate text from a prompt."""
        response = ctypes.create_string_buffer(max_length)
        response_len = ctypes.c_size_t(max_length)
        num_tokens = ctypes.c_uint32()
        
        _check_error(_lib.sovereign_generate(
            self._session,
            prompt.encode('utf-8'),
            response,
            ctypes.byref(response_len),
            ctypes.byref(num_tokens)
        ))
        
        return response.value.decode('utf-8')


# =============================================================================
# Convenience Functions
# =============================================================================

def version() -> str:
    """Get the library version string."""
    return _lib.sovereign_version_string().decode('utf-8')


@contextmanager
def engine(loader_config: Optional[LoaderConfig] = None,
           inference_config: Optional[InferenceConfig] = None):
    """Context manager for engine lifecycle."""
    eng = SovereignEngine(loader_config, inference_config)
    try:
        yield eng
    finally:
        del eng


# =============================================================================
# Example Usage
# =============================================================================

if __name__ == '__main__':
    print(f"Sovereign Engine: {version()}")
    
    # Get hardware info
    hw = SovereignEngine.get_hardware_info()
    print(f"Hardware: {hw.num_physical_cores} cores, "
          f"{hw.total_memory_bytes // (1024**3)} GB RAM")
    print(f"Features: AVX2={hw.has_avx2}, AVX-512={hw.has_avx512}, AMX={hw.has_amx}")
    
    # Create engine
    with engine() as eng:
        print(f"Engine ready: {eng.is_ready()}")
        
        # Create session and generate
        with eng.create_session() as sess:
            response = sess.generate("Hello, world!")
            print(f"Generated: {response}")
        
        # Get stats
        stats = eng.get_stats()
        print(f"Tokens generated: {stats.tokens_generated}")
        print(f"Avg latency: {stats.avg_latency_ms:.2f} ms")
