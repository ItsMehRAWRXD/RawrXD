# RawrXD Audio Engine + Hotpatching Script Suite

## Overview

This directory contains specialized PowerShell scripts for integrating the Phase V.4 Audio Engine with the 7-Layer Hotpatching System. All scripts are production-ready and designed for autonomous operation.

## Scripts

### 1. AudioEngine_Hotpatch_Integration.ps1
**Purpose**: Real-time integration of audio pipeline with hotpatching system

**Features**:
- Live audio quality monitoring
- Automatic failure detection (buffer underrun, dropouts, quality degradation)
- Real-time hotpatch application
- Named pipe communication with audio pipeline
- Telemetry logging and analysis

**Usage**:
```powershell
.\AudioEngine_Hotpatch_Integration.ps1 -EnableAutoCorrection -BenchmarkMode
```

**Parameters**:
- `-AudioPipelinePath`: Path to AudioPipeline_Integration.exe
- `-EnableAutoCorrection`: Enable automatic hotpatch application
- `-BenchmarkMode`: Run 60-second performance benchmark
- `-MonitorIntervalMs`: Telemetry polling interval (default: 100ms)

---

### 2. Hotpatch_Validation_Suite.ps1
**Purpose**: Comprehensive validation of all 7 hotpatch layers

**Features**:
- Automated testing for each hotpatch layer (0, 1, 2, 3, 5, 6)
- Memory patching with SIMD/TSX RTM support
- Byte-level pattern matching (Boyer-Moore-Horspool)
- Server-layer request/response transforms
- Live binary patching simulation
- Shadow-page detour testing
- Sentinel watchdog integrity checks
- Stress test mode (30-second high-load test)
- JSON report generation

**Usage**:
```powershell
# Test all layers
.\Hotpatch_Validation_Suite.ps1 -TestLayer All -GenerateReport

# Test specific layer
.\Hotpatch_Validation_Suite.ps1 -TestLayer Memory

# Stress test
.\Hotpatch_Validation_Suite.ps1 -StressTest
```

**Parameters**:
- `-TestLayer`: Which layer to test (All, Memory, Byte, Server, LiveBinary, ShadowPage, Sentinel, PTDriver)
- `-Iterations`: Number of test iterations (default: 100)
- `-StressTest`: Enable 30-second stress test
- `-GenerateReport`: Export results to JSON

---

### 3. Autonomous_Audio_Orchestrator.ps1
**Purpose**: Fully autonomous audio pipeline with self-healing capabilities

**Features**:
- Self-monitoring and health checking
- Automatic profile switching (low_latency, balanced, quality, power_save)
- Dynamic buffer size adaptation
- Self-healing for latency, dropout, and CPU issues
- Performance optimization engine
- Learning from corrections
- Headless mode for server deployment

**Usage**:
```powershell
# Interactive mode
.\Autonomous_Audio_Orchestrator.ps1

# Headless mode
.\Autonomous_Audio_Orchestrator.ps1 -Headless -OptimizationInterval 10000
```

**Parameters**:
- `-ConfigPath`: Path to configuration JSON
- `-Headless`: Run without UI
- `-OptimizationInterval`: Optimization cycle interval in ms (default: 5000)
- `-EnableSelfHealing`: Enable automatic healing (default: true)

**Profiles**:
- `low_latency`: 256-sample buffer, high priority, cores 0,2,4,6
- `balanced`: 512-sample buffer, normal priority (default)
- `quality`: 1024-sample buffer, 96kHz sample rate
- `power_save`: 2048-sample buffer, low priority, cores 0,1

---

### 4. MASM_Build_Automation.ps1
**Purpose**: Automated MASM x64 build pipeline with hotpatch integration

**Features**:
- Incremental builds with dependency tracking
- Parallel compilation (configurable job count)
- AVX-512 optimization support
- Automatic hotpatch metadata generation
- Symbol table extraction
- Build benchmarking mode
- JSON manifest generation for hotpatch layers

**Usage**:
```powershell
# Standard build
.\MASM_Build_Automation.ps1 -Parallel

# Clean build
.\MASM_Build_Automation.ps1 -Clean -Parallel

# Benchmark mode
.\MASM_Build_Automation.ps1 -Benchmark

# With hotpatch
.\MASM_Build_Automation.ps1 -EnableHotpatch
```

**Parameters**:
- `-SourceDir`: Source directory (default: ..\src\asm)
- `-OutputDir`: Output directory (default: ..\build)
- `-ML64Path`: Path to ml64.exe
- `-LinkPath`: Path to link.exe
- `-Clean`: Clean before build
- `-Parallel`: Enable parallel compilation
- `-MaxParallelJobs`: Max parallel jobs (default: 4)
- `-EnableHotpatch`: Generate hotpatch metadata
- `-Benchmark`: Run build performance benchmark

---

### 5. Audio_Hotpatch_Demo.ps1
**Purpose**: Interactive demonstration of audio engine hotpatching

**Features**:
- Visual audio pipeline status display
- Real-time hotpatch layer monitoring
- Simulated failure scenarios
- Interactive event injection
- Auto-mode for unattended demos
- Demo results export

**Usage**:
```powershell
# Interactive mode
.\Audio_Hotpatch_Demo.ps1

# Auto mode (60 seconds)
.\Audio_Hotpatch_Demo.ps1 -AutoMode -DemoDuration 60
```

**Parameters**:
- `-AutoMode`: Run without user interaction
- `-DemoDuration`: Duration in seconds (default: 60)
- `-OutputPath`: Results export path

**Interactive Commands**:
- `S`: Simulate random failure event
- `C`: Clear event log
- `Q`: Quit demo

---

## Configuration Files

### audio_hotpatch.json
Configuration for AudioEngine_Hotpatch_Integration.ps1:
```json
{
  "audio_engine": {
    "sample_rate": 48000,
    "buffer_size": 1024,
    "channels": 2
  },
  "hotpatch_policies": [
    {
      "failure_type": "BufferUnderrun",
      "action": "IncreaseBufferSize",
      "threshold": 0.8,
      "max_retries": 3
    }
  ]
}
```

### autonomous_audio.json
Configuration for Autonomous_Audio_Orchestrator.ps1:
```json
{
  "autonomous_mode": {
    "enabled": true,
    "self_healing": true,
    "auto_optimization": true
  },
  "thresholds": {
    "latency_critical_ms": 5,
    "dropout_critical_percent": 1.0
  }
}
```

---

## Requirements

- PowerShell 7.0 or later
- Windows 10/11 or Windows Server 2019+
- Visual Studio 2022 (for MASM builds)
- 4GB RAM minimum (8GB recommended)

---

## Integration

These scripts integrate with:

1. **Phase V.4 Audio Engine**: Real-time audio processing pipeline
2. **7-Layer Hotpatch System**: From PT Driver to Sentinel Watchdog
3. **Agentic Orchestrator**: Autonomous failure detection and correction
4. **MASM x64 Toolchain**: Native assembly compilation

---

## License

Enterprise License Required for:
- Proxy hotpatching features
- Unified hotpatch manager
- Live binary patching
- Sentinel watchdog

Community features (Memory, Byte layers) are freely available.

---

## Support

For issues or questions:
1. Check logs in `logs/` directory
2. Review hotpatch manifest in `build/hotpatch/`
3. Validate with `Hotpatch_Validation_Suite.ps1 -TestLayer All`
