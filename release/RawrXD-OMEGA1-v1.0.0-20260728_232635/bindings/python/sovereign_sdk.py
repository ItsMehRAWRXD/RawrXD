"""Sovereign SDK Python binding (ctypes, additive prototype).

This module intentionally stays thin and ABI-focused.
"""

from __future__ import annotations

import ctypes
from ctypes import c_bool, c_char_p, c_float, c_int, c_size_t, c_uint16, c_uint32, c_uint64, c_void_p
from pathlib import Path


SOVEREIGN_TASK_INFERENCE = 0
SOVEREIGN_TASK_ANALYSIS = 1
SOVEREIGN_TASK_REFACTOR = 2
SOVEREIGN_TASK_COMPLETE = 3
SOVEREIGN_TASK_EXPLAIN = 4

OnProgressCallback = ctypes.CFUNCTYPE(None, c_float, c_void_p)
OnCompleteCallback = ctypes.CFUNCTYPE(None, c_int, c_void_p)


class SovereignNodeConfig(ctypes.Structure):
    _fields_ = [
        ("node_id", c_uint32),
        ("total_nodes", c_uint32),
        ("is_head", c_bool),
        ("enable_gpu", c_bool),
        ("enable_amx", c_bool),
        ("thread_pool_size", c_uint32),
        ("kv_cache_size", c_uint64),
        ("head_node_ip", c_char_p),
        ("router_port", c_uint16),
        ("pub_port", c_uint16),
    ]


class SovereignStatus(ctypes.Structure):
    _fields_ = [
        ("flags", c_uint32),
        ("memory_available", c_uint64),
        ("memory_used", c_uint64),
        ("active_nodes", c_uint32),
        ("tasks_queued", c_uint32),
        ("avg_latency_ms", c_float),
        ("throughput_tps", c_float),
    ]


class SovereignSuperNodeConfig(ctypes.Structure):
    _fields_ = [
        ("worker_threads", c_uint32),
        ("enable_thread_pinning", c_bool),
        ("enable_memory_mapping", c_bool),
        ("enable_numa_locality", c_bool),
        ("enable_deterministic_mode", c_bool),
        ("max_resident_bytes", c_uint64),
        ("reserved", c_uint32),
    ]


class SovereignTaskParams(ctypes.Structure):
    _fields_ = [
        ("type", c_uint32),
        ("input", c_char_p),
        ("input_len", c_size_t),
        ("output", c_char_p),
        ("output_capacity", c_size_t),
        ("output_len", ctypes.POINTER(c_size_t)),
        ("max_tokens", c_uint32),
        ("temperature", c_float),
        ("user_data", c_void_p),
        ("on_progress", OnProgressCallback),
        ("on_complete", OnCompleteCallback),
    ]


class SovereignSDK:
    def __init__(self, dll_path: str | Path):
        self.lib = ctypes.CDLL(str(dll_path))
        self._wire_signatures()
        self.handle = None

    def _wire_signatures(self) -> None:
        self.lib.Sovereign_Init.argtypes = [ctypes.POINTER(SovereignNodeConfig)]
        self.lib.Sovereign_Init.restype = c_void_p

        self.lib.Sovereign_Shutdown.argtypes = [c_void_p]
        self.lib.Sovereign_Shutdown.restype = ctypes.c_int

        self.lib.Sovereign_GetStatus.argtypes = [c_void_p, ctypes.POINTER(SovereignStatus)]
        self.lib.Sovereign_GetStatus.restype = ctypes.c_int

        self.lib.Sovereign_GetVersion.argtypes = []
        self.lib.Sovereign_GetVersion.restype = c_char_p

        self.lib.Sovereign_SubmitTaskWithHandle.argtypes = [
            c_void_p,
            c_void_p,
            ctypes.POINTER(SovereignTaskParams),
            ctypes.POINTER(c_void_p),
        ]
        self.lib.Sovereign_SubmitTaskWithHandle.restype = ctypes.c_int

        self.lib.Sovereign_WaitTaskHandle.argtypes = [c_void_p, c_void_p, c_uint32]
        self.lib.Sovereign_WaitTaskHandle.restype = ctypes.c_int

        self.lib.Sovereign_GetTaskState.argtypes = [c_void_p, c_void_p, ctypes.POINTER(c_uint32)]
        self.lib.Sovereign_GetTaskState.restype = ctypes.c_int

        self.lib.Sovereign_ReleaseTaskHandle.argtypes = [c_void_p, c_void_p]
        self.lib.Sovereign_ReleaseTaskHandle.restype = None

    def init(self, cfg: SovereignNodeConfig) -> None:
        h = self.lib.Sovereign_Init(ctypes.byref(cfg))
        if not h:
            raise RuntimeError("Sovereign_Init failed")
        self.handle = h

    def shutdown(self) -> None:
        if self.handle:
            self.lib.Sovereign_Shutdown(self.handle)
            self.handle = None

    def status(self) -> SovereignStatus:
        if not self.handle:
            raise RuntimeError("SDK not initialized")
        s = SovereignStatus()
        rc = self.lib.Sovereign_GetStatus(self.handle, ctypes.byref(s))
        if rc != 0:
            raise RuntimeError("Sovereign_GetStatus failed")
        return s

    def version(self) -> str:
        return self.lib.Sovereign_GetVersion().decode("utf-8")

    def submit_task_with_handle(self, params: SovereignTaskParams) -> c_void_p:
        if not self.handle:
            raise RuntimeError("SDK not initialized")
        task_handle = c_void_p()
        rc = self.lib.Sovereign_SubmitTaskWithHandle(self.handle, None, ctypes.byref(params), ctypes.byref(task_handle))
        if rc != 0:
            raise RuntimeError("Sovereign_SubmitTaskWithHandle failed")
        return task_handle

    def wait_task_handle(self, task_handle: c_void_p, timeout_ms: int = 0) -> None:
        if self.lib.Sovereign_WaitTaskHandle(self.handle, task_handle, timeout_ms) < 0:
            raise RuntimeError("Sovereign_WaitTaskHandle failed")

    def task_state(self, task_handle: c_void_p) -> int:
        state = c_uint32()
        if self.lib.Sovereign_GetTaskState(self.handle, task_handle, ctypes.byref(state)) != 0:
            raise RuntimeError("Sovereign_GetTaskState failed")
        return int(state.value)

    def release_task_handle(self, task_handle: c_void_p) -> None:
        self.lib.Sovereign_ReleaseTaskHandle(self.handle, task_handle)
