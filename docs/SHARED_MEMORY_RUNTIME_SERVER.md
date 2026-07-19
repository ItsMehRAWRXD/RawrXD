# Sovereign Shared Memory Runtime Server

## Overview

The Shared Memory Runtime Server closes the execution loop between RawrXD IDE and the local AI inference backend. It provides zero-copy IPC for ghost text completions without cloud dependencies.

## Architecture

```
┌─────────────────┐     Shared Memory      ┌──────────────────┐     Deep2 API      ┌─────────────┐
│   RawrXD IDE    │ ◄────────────────────► │ SovereignRuntime │ ◄─────────────────► │   Deep2     │
│  (Win32 Client) │   RawrXD_SharedMem_Alpha│   (Server)       │   (Inference)       │  (Kernels)  │
└─────────────────┘                        └──────────────────┘                     └─────────────┘
       │                                           │
       │ Events: RawrXD_RequestEvent               │
       │        RawrXD_ResponseEvent              │
       └─────────────────────────────────────────┘
```

## Components

### 1. SovereignSharedMemoryServer.hpp/cpp
- **Location**: `d:\RawrXD\src\runtime\`
- **Purpose**: Runtime server implementation
- **Key Features**:
  - Creates shared memory segment (`RawrXD_SharedMem_Alpha`)
  - Worker thread for request processing
  - Event-based synchronization
  - Telemetry collection

### 2. SovereignInferenceBridge_SharedMem.cpp
- **Location**: `d:\RawrXD\src\ide\`
- **Purpose**: IDE-side bridge to runtime
- **Key Features**:
  - Opens shared memory created by runtime
  - Worker thread for async response handling
  - Token callback for streaming UI updates

### 3. Protocol Structures

#### SovereignRequest (12,320 bytes)
```cpp
struct SovereignRequest {
    uint64_t requestId;      // Monotonic sequence
    uint64_t timestamp;      // Request start time
    uint32_t version;        // Protocol version
    uint32_t promptLength;   // Actual prompt bytes
    uint32_t maxTokens;      // Generation limit
    float temperature;         // Sampling temperature
    char prompt[8192];       // Input text
    char context[4096];      // Conversation context
};
```

#### SovereignResponse (16,676 bytes)
```cpp
struct SovereignResponse {
    uint64_t requestId;      // Matches request
    uint64_t timestamp;      // Response time
    uint32_t tokenCount;     // Generated tokens
    uint32_t status;         // 0=success, 1=error
    float confidence;        // Average token probability
    uint32_t latencyMs;      // Generation time
    float tps;               // Tokens per second
    char text[16384];        // Generated completion
    char errorMessage[256];  // Error details if status != 0
};
```

#### SovereignSharedBlock (29,120 bytes total)
- Request section (aligned to 64 bytes)
- Response section (aligned to 64 bytes)
- Atomic flags for synchronization
- Telemetry counters

## Build Instructions

### Prerequisites
- Visual Studio 2022 (or VS2022 Build Tools)
- Windows SDK 10.0.22621.0 or later

### Build Steps

```batch
REM Set up VS2022 environment
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

REM Compile runtime server
cl /c /W4 /EHsc /O2 /nologo /Zi /Fo"SovereignSharedMemoryServer.obj" /I"d:\RawrXD\src" "d:\RawrXD\src\runtime\SovereignSharedMemoryServer.cpp"

cl /c /W4 /EHsc /O2 /nologo /Zi /Fo"SovereignRuntimeMain.obj" /I"d:\RawrXD\src" "d:\RawrXD\src\runtime\SovereignRuntimeMain.cpp"

link /SUBSYSTEM:CONSOLE /OUT:"SovereignRuntime.exe" kernel32.lib user32.lib libcmt.lib SovereignSharedMemoryServer.obj SovereignRuntimeMain.obj
```

Or use the provided build script:
```batch
d:\RawrXD\build_runtime2.bat
```

## Usage

### 1. Start the Runtime Server
```batch
d:\RawrXD\bin\SovereignRuntime.exe
```

Output:
```
========================================
  RawrXD Sovereign Runtime Server
  Version 1.0.0 (Alpha)
========================================

Backend:    Deep2 (Simulated)
Quant:      Q4_K_M
Kernel:     AVX512
IPC:        Shared Memory (Zero-Copy)
Protocol:   Request/Response Events

[SovereignRuntime] Initializing...
[SovereignRuntime] Shared memory initialized: RawrXD_SharedMem_Alpha
[SovereignRuntime] Block size: 29120 bytes
[SovereignRuntime] READY - Waiting for requests
```

### 2. Test with Client
```batch
d:\RawrXD\bin\SovereignRuntimeTestClient.exe
```

### 3. IDE Integration
The IDE automatically connects via `SovereignInferenceBridge_SharedMem.cpp` when:
- Ghost text completion is triggered
- Shared memory is available
- Runtime server is running

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Shared Memory Size | 29,120 bytes |
| Request Buffer | 8,192 bytes (prompt) |
| Response Buffer | 16,384 bytes (completion) |
| Synchronization | Event-based (kernel) |
| Latency (simulated) | 48ms |
| Throughput (simulated) | 333 TPS |

## Telemetry

Press 't' in the runtime console to view:
```
=== Runtime Telemetry ===
Requests Received:  3
Responses Sent:     3
Errors:             0
Total Tokens:       96
Avg Latency:        48.00 ms
Avg TPS:            333.00
=========================
```

## Integration Status

✅ **Completed**:
- Shared memory protocol definition
- Runtime server implementation
- Test client verification
- IDE bridge implementation
- Build scripts

⏭️ **Next Steps**:
- Replace Deep2 placeholder with actual kernel integration
- Add streaming token support (per-token callbacks)
- Implement model loading via shared memory
- Add telemetry rotation to circular buffer

## Files

| File | Purpose |
|------|---------|
| `SovereignSharedMemoryServer.hpp` | Protocol structures and class interface |
| `SovereignSharedMemoryServer.cpp` | Runtime server implementation |
| `SovereignRuntimeMain.cpp` | Standalone executable entry point |
| `SovereignRuntimeTestClient.cpp` | Test/verification client |
| `SovereignInferenceBridge_SharedMem.cpp` | IDE-side integration |
| `build_runtime2.bat` | Build automation script |

## C-Compatible API

```cpp
// Create/Destroy
void* SovereignRuntime_Create();
void SovereignRuntime_Destroy(void* server);

// Lifecycle
int SovereignRuntime_Initialize(void* server, const wchar_t* name);
int SovereignRuntime_Start(void* server);
void SovereignRuntime_Stop(void* server);
int SovereignRuntime_IsRunning(void* server);
```

## Notes

- The runtime server must be started before the IDE attempts to connect
- Shared memory name is `RawrXD_SharedMem_Alpha` (configurable)
- Events are named `RawrXD_RequestEvent` and `RawrXD_ResponseEvent`
- Currently uses simulated Deep2 responses (48ms latency, 333 TPS)
- Production integration will call actual Q4_K_M kernels via Deep2
