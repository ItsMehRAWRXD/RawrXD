"""
System Spec Detector — Knows what hardware you have and what model size you can run.

Detects:
  - CPU cores, threads, frequency
  - RAM total and available
  - GPU type, name, VRAM (AMD, NVIDIA, Intel, Apple)
  - Platform (Windows, Linux, macOS)

Calculates the optimal model size for YOUR hardware.
No cloud needed. No download needed. It checks what you can handle and becomes that.
"""

import os
import sys
import json
import platform
import subprocess
import shutil
from dataclasses import dataclass, field
from typing import Tuple, Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


@dataclass
class SystemSpecs:
    """Detected hardware specifications."""
    cpu_name: str = ""
    cpu_cores: int = 0
    cpu_threads: int = 0
    cpu_freq_ghz: float = 0.0
    total_ram_gb: float = 0.0
    available_ram_gb: float = 0.0
    usable_ram_gb: float = 0.0
    gpu_name: str = ""
    gpu_vram_gb: float = 0.0
    gpu_available: bool = False
    gpu_type: str = "none"
    os_name: str = ""
    os_version: str = ""
    arch: str = ""
    max_model_size: str = "1B"
    max_model_params: int = 1_000_000_000
    max_model_memory_mb: float = 2000.0
    recommended_quant: str = "Q4_K_M"

    def summary(self) -> str:
        lines = [
            f"OS:        {self.os_name} {self.os_version} ({self.arch})",
            f"CPU:       {self.cpu_name} ({self.cpu_cores}c/{self.cpu_threads}t @ {self.cpu_freq_ghz:.1f}GHz)",
            f"RAM:       {self.total_ram_gb:.1f}GB total, {self.available_ram_gb:.1f}GB available",
        ]
        if self.gpu_available:
            lines.append(f"GPU:       {self.gpu_name} ({self.gpu_vram_gb:.1f}GB VRAM)")
        else:
            lines.append("GPU:       None (CPU-only mode)")
        lines.append(f"Max Model: {self.max_model_size} ({self.max_model_params/1e6:.0f}M params, ~{self.max_model_memory_mb:.0f}MB)")
        lines.append(f"Quant:     {self.recommended_quant}")
        return "\n  ".join(lines)

    def to_dict(self) -> dict:
        return {
            "cpu_name": self.cpu_name,
            "cpu_cores": self.cpu_cores,
            "cpu_threads": self.cpu_threads,
            "cpu_freq_ghz": self.cpu_freq_ghz,
            "total_ram_gb": self.total_ram_gb,
            "available_ram_gb": self.available_ram_gb,
            "usable_ram_gb": self.usable_ram_gb,
            "gpu_name": self.gpu_name,
            "gpu_vram_gb": self.gpu_vram_gb,
            "gpu_available": self.gpu_available,
            "gpu_type": self.gpu_type,
            "os_name": self.os_name,
            "os_version": self.os_version,
            "arch": self.arch,
            "max_model_size": self.max_model_size,
            "max_model_params": self.max_model_params,
            "max_model_memory_mb": self.max_model_memory_mb,
            "recommended_quant": self.recommended_quant,
        }


class SystemDetector:
    """Detects system hardware and calculates optimal model size."""

    SIZE_TABLE = [
        (1.0,   0.0,  "100M",   100_000_000,   80,   "Q4_K_M"),
        (2.0,   0.0,  "250M",   250_000_000,  180,   "Q4_K_M"),
        (4.0,   0.0,  "500M",   500_000_000,  350,   "Q4_K_M"),
        (8.0,   0.0,  "1B",    1_000_000_000,  700,   "Q4_K_M"),
        (8.0,   4.0,  "1B",    1_000_000_000, 2000,  "FP16"),
        (16.0,  0.0,  "3B",    3_000_000_000, 2100,  "Q4_K_M"),
        (16.0,  8.0,  "3B",    3_000_000_000, 6000,  "FP16"),
        (32.0,  0.0,  "7B",    7_000_000_000, 4900,  "Q4_K_M"),
        (32.0, 16.0,  "7B",    7_000_000_000, 14000, "FP16"),
        (64.0,  0.0,  "13B",   13_000_000_000, 9100,  "Q4_K_M"),
        (64.0, 24.0,  "13B",   13_000_000_000, 26000, "FP16"),
        (128.0, 0.0,  "70B",   70_000_000_000, 49000, "Q4_K_M"),
        (128.0, 80.0,  "70B",   70_000_000_000, 140000, "FP16"),
        (256.0, 0.0,  "170B",  170_000_000_000, 119000, "Q4_K_M"),
    ]

    def detect(self) -> SystemSpecs:
        """Detect all system specifications."""
        specs = SystemSpecs()
        specs.os_name = platform.system()
        specs.os_version = self._get_os_version()
        specs.arch = platform.machine()
        self._detect_cpu(specs)
        self._detect_memory(specs)
        self._detect_gpu(specs)
        self._calculate_max_size(specs)
        return specs

    def _get_os_version(self) -> str:
        try:
            if sys.platform == "win32":
                return platform.win32_ver()[1] or platform.version()
            elif sys.platform == "darwin":
                return platform.mac_ver()[0] or ""
            else:
                return platform.version() or ""
        except:
            return ""

    def _detect_cpu(self, specs: SystemSpecs):
        specs.cpu_name = platform.processor() or "Unknown"
        if HAS_PSUTIL:
            specs.cpu_cores = psutil.cpu_count(logical=False) or 1
            specs.cpu_threads = psutil.cpu_count(logical=True) or 1
            try:
                freq = psutil.cpu_freq()
                specs.cpu_freq_ghz = (freq.current / 1000) if freq else 0.0
            except:
                specs.cpu_freq_ghz = 0.0
        else:
            specs.cpu_cores = os.cpu_count() or 1
            specs.cpu_threads = specs.cpu_cores

    def _detect_memory(self, specs: SystemSpecs):
        if HAS_PSUTIL:
            vm = psutil.virtual_memory()
            specs.total_ram_gb = vm.total / (1024**3)
            specs.available_ram_gb = vm.available / (1024**3)
        else:
            if sys.platform == "linux":
                try:
                    with open("/proc/meminfo") as f:
                        for line in f:
                            if "MemTotal" in line:
                                specs.total_ram_gb = int(line.split()[1]) / (1024*1024)
                            if "MemAvailable" in line:
                                specs.available_ram_gb = int(line.split()[1]) / (1024*1024)
                except:
                    specs.total_ram_gb = 8.0
                    specs.available_ram_gb = 4.0
            else:
                specs.total_ram_gb = 8.0
                specs.available_ram_gb = 4.0
        specs.usable_ram_gb = max(specs.available_ram_gb - 2.0, 0.5) * 0.75

    def _detect_gpu(self, specs: SystemSpecs):
        name, vram, gpu_type = self._detect_gpu_raw()
        specs.gpu_name = name
        specs.gpu_vram_gb = vram
        specs.gpu_type = gpu_type
        specs.gpu_available = name != "None" and vram > 0

    def _detect_gpu_raw(self) -> Tuple[str, float, str]:
        # NVIDIA
        nvidia_smi = shutil.which("nvidia-smi")
        if nvidia_smi:
            try:
                result = subprocess.run(
                    [nvidia_smi, "--query-gpu=name,memory.total",
                     "--format=csv,noheader,nounits"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    parts = result.stdout.strip().split(',')
                    name = parts[0].strip()
                    vram_mb = float(parts[1].strip()) if len(parts) > 1 else 0
                    return (name, vram_mb / 1024, "nvidia")
            except:
                pass

        # AMD ROCm (Linux)
        if sys.platform == "linux":
            rocm_paths = ["/opt/rocm", "/opt/rocm-*"]
            for rocm in ["/opt/rocm"]:
                if os.path.exists(rocm):
                    try:
                        result = subprocess.run(
                            [f"{rocm}/bin/rocminfo"],
                            capture_output=True, text=True, timeout=10
                        )
                        if result.returncode == 0:
                            for line in result.stdout.split('\n'):
                                if "Marketing Name:" in line:
                                    name = line.split("Marketing Name:")[1].strip()
                                    if name:
                                        return (name, 16.0, "amd")
                                if "gfx" in line.lower() and "Name:" in line:
                                    gfx = line.split("Name:")[1].strip()
                                    return (f"AMD {gfx}", 16.0, "amd")
                    except:
                        pass

        # Apple Silicon (macOS)
        if sys.platform == "darwin" and platform.machine() in ("arm64", "aarch64"):
            try:
                result = subprocess.run(
                    ["sysctl", "-n", "machdep.cpu.brand_string"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    chip = result.stdout.strip()
                    if HAS_PSUTIL:
                        vm = psutil.virtual_memory()
                        vram = vm.total / (1024**3) * 0.7
                    else:
                        vram = 8.0
                    return (chip, vram, "apple")
            except:
                pass

        # Intel Arc (Linux)
        if sys.platform == "linux":
            try:
                result = subprocess.run(
                    ["lspci", "-nn"], capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if "VGA" in line and "Intel" in line:
                            return ("Intel Arc GPU", 8.0, "intel")
            except:
                pass

        return ("None", 0.0, "none")

    def _calculate_max_size(self, specs: SystemSpecs):
        if specs.gpu_available and specs.gpu_vram_gb > 0:
            available_gb = specs.gpu_vram_gb * 0.85
        else:
            available_gb = specs.usable_ram_gb

        best_size = "100M"
        best_params = 100_000_000
        best_memory = 80
        best_quant = "Q4_K_M"

        for min_ram, min_vram, size_name, params, memory_mb, quant in self.SIZE_TABLE:
            required_gb = memory_mb / 1024
            if specs.gpu_available and specs.gpu_vram_gb > 0:
                if min_vram > 0 and available_gb >= required_gb and params > best_params:
                    best_size = size_name
                    best_params = params
                    best_memory = memory_mb
                    best_quant = quant
            else:
                if min_vram == 0 and available_gb >= required_gb and params > best_params:
                    best_size = size_name
                    best_params = params
                    best_memory = memory_mb
                    best_quant = quant

        specs.max_model_size = best_size
        specs.max_model_params = best_params
        specs.max_model_memory_mb = best_memory
        specs.recommended_quant = best_quant
