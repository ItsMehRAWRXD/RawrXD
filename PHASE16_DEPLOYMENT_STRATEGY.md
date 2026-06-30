# Phase 16: Production Deployment Strategy

## Executive Summary

**Deployment Model:** Hybrid Architecture with Service Migration Path

| Mode | Use Case | Memory | Complexity | Status |
|------|----------|--------|------------|--------|
| **IDE-Managed** (Default) | Development, debugging, single-window | ~1GB per IDE | Low | ✅ Ready |
| **Shared Service** (Optional) | Production, multi-window, enterprise | ~1GB shared | Medium | Phase 16B |
| **Hybrid Auto** (Future) | Auto-switch based on workload | Variable | High | Phase 17 |

---

## Architecture Decision: Why Hybrid?

### The Problem with Pure IDE-Managed

```
Current State (IDE-Managed):
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ IDE Win 1   │     │ IDE Win 2   │     │ IDE Win 3   │
│ ├─Engine    │     │ ├─Engine    │     │ ├─Engine    │
│ │  ~1GB     │     │ │  ~1GB     │     │ │  ~1GB     │
│ └───────────┘     │ └───────────┘     │ └───────────┘
└─────────────┘     └─────────────┘     └─────────────┘
     Total: 3GB resident (even with MMAP sharing)
```

**Issues:**
- Memory waste: Each engine instance loads embeddings + first layers
- Cold start per window: Each IDE window triggers MMAP prefetch
- No shared KV cache: Each window has separate context

### The Solution: Sovereign Service

```
Target State (Shared Service):
                    ┌─────────────────────┐
                    │ Sovereign Service   │
                    │ ├─MMAP'd Model      │
                    │ │  ~1GB resident    │
                    │ ├─Shared KV Cache   │
                    │ │  ~256MB           │
                    │ └─Session Manager   │
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         │                     │                     │
    ┌────┴────┐           ┌────┴────┐           ┌────┴────┐
    │ IDE 1   │◄─────────►│ IDE 2   │◄─────────►│ IDE 3   │
    │ (Client)│   IPC     │ (Client)│   IPC     │ (Client)│
    └─────────┘           └─────────┘           └─────────┘
     Total: ~1.25GB resident (regardless of window count)
```

**Benefits:**
- Single MMAP'd model shared across all windows
- Warm KV cache: Previous completions benefit new windows
- Centralized resource management
- Survives IDE crashes (service keeps running)

---

## Phase 16A: IDE-Managed (Current - Default)

### Implementation

```cpp
// RawrXD IDE Plugin
class SovereignEngineManager {
public:
    void StartEngine() {
        // Spawn Sovereign_Engine.exe as child process
        PROCESS_INFORMATION pi;
        STARTUPINFO si = { sizeof(si) };
        
        CreateProcessA(
            "Sovereign_Engine.exe",
            "--ipc-pipe=SovereignIPC --mode=managed",
            nullptr, nullptr, FALSE, 0, nullptr, nullptr,
            &si, &pi
        );
        
        hEngineProcess = pi.hProcess;
        enginePid = pi.dwProcessId;
    }
    
    void StopEngine() {
        // Clean shutdown on IDE exit
        TerminateProcess(hEngineProcess, 0);
        CloseHandle(hEngineProcess);
    }
    
    bool IsEngineRunning() {
        DWORD exitCode;
        GetExitCodeProcess(hEngineProcess, &exitCode);
        return exitCode == STILL_ACTIVE;
    }
    
    void RestartEngine() {
        // Auto-restart on crash
        StopEngine();
        StartEngine();
    }
};
```

### Configuration

```json
// RawrXDSettings.json
{
  "sovereignEngine": {
    "mode": "managed",  // "managed" | "service" | "auto"
    "autoStart": true,
    "autoRestart": true,
    "maxRestarts": 3,
    "versionCheck": true,
    "minVersion": "1.0.0",
    "telemetry": {
      "enabled": true,
      "async": true,
      "bufferSize": 1000
    }
  }
}
```

### Version Pinning

```cpp
// ABI Version Check
#define SOVEREIGN_ABI_VERSION_MAJOR 1
#define SOVEREIGN_ABI_VERSION_MINOR 0
#define SOVEREIGN_ABI_VERSION_PATCH 0

bool ValidateEngineVersion(const char* enginePath) {
    // Query engine version
    char versionOutput[256];
    ExecuteCommand("%s --version", enginePath, versionOutput, sizeof(versionOutput));
    
    // Parse: "Sovereign Engine v1.0.0 (ABI 1.0)"
    int abiMajor, abiMinor;
    sscanf(versionOutput, "*(ABI %d.%d)", &abiMajor, &abiMinor);
    
    // Validate compatibility
    if (abiMajor != SOVEREIGN_ABI_VERSION_MAJOR) {
        LogError("ABI version mismatch: expected %d.x, got %d.%d",
                 SOVEREIGN_ABI_VERSION_MAJOR, abiMajor, abiMinor);
        return false;
    }
    
    return true;
}
```

### Telemetry Hardening

```cpp
// Async Telemetry Writer
class AsyncTelemetryLogger {
private:
    std::queue<TelemetryEntry> buffer;
    std::mutex bufferMutex;
    std::thread writerThread;
    std::atomic<bool> running;
    
public:
    void Log(TelemetryEntry entry) {
        // Non-blocking: just add to buffer
        std::lock_guard<std::mutex> lock(bufferMutex);
        buffer.push(entry);
        
        // Signal writer thread if buffer getting full
        if (buffer.size() > 100) {
            Flush();
        }
    }
    
    void WriterThread() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            Flush();
        }
    }
    
    void Flush() {
        std::lock_guard<std::mutex> lock(bufferMutex);
        
        FILE* fp = fopen(telemetryPath, "a");
        while (!buffer.empty()) {
            auto entry = buffer.front();
            fprintf(fp, "%s\n", entry.ToJson().c_str());
            buffer.pop();
        }
        fclose(fp);
    }
};
```

---

## Phase 16B: Shared Service (Optional)

### Service Architecture

```cpp
// SovereignService.exe
class SovereignService {
public:
    void Run() {
        // Initialize once
        InitializeMMAP();
        LoadModel();
        WarmupKVCache();
        
        // Accept multiple client connections
        while (running) {
            HANDLE hClient = AcceptClientConnection();
            std::thread clientThread(HandleClient, hClient);
            clientThread.detach();
        }
    }
    
private:
    void HandleClient(HANDLE hClient) {
        // Each IDE window gets its own session
        SessionContext ctx;
        ctx.clientHandle = hClient;
        ctx.kvCache = AllocateKVCacheSlot();
        
        while (connected) {
            IPCMessage msg = ReceiveMessage(hClient);
            ProcessRequest(msg, ctx);
        }
        
        FreeKVCacheSlot(ctx.kvCache);
    }
};
```

### Session Management

```cpp
struct SessionContext {
    uint32_t sessionId;
    HANDLE clientPipe;
    KVCache* kvCache;
    std::string currentFile;
    uint32_t cursorPosition;
    std::chrono::time_point lastActivity;
};

class SessionManager {
private:
    std::unordered_map<uint32_t, SessionContext> sessions;
    std::mutex sessionsMutex;
    
public:
    uint32_t CreateSession(HANDLE clientPipe) {
        std::lock_guard<std::mutex> lock(sessionsMutex);
        
        uint32_t sessionId = GenerateSessionId();
        SessionContext ctx;
        ctx.sessionId = sessionId;
        ctx.clientPipe = clientPipe;
        ctx.kvCache = kvCachePool.Allocate();
        ctx.lastActivity = std::chrono::steady_clock::now();
        
        sessions[sessionId] = ctx;
        return sessionId;
    }
    
    void CleanupInactiveSessions() {
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = sessions.begin(); it != sessions.end();) {
            auto inactive = std::chrono::duration_cast<std::chrono::minutes>(
                now - it->second.lastActivity
            ).count();
            
            if (inactive > 30) {  // 30 minutes idle
                kvCachePool.Free(it->second.kvCache);
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
    }
};
```

### Service Installation

```powershell
# Install-SovereignService.ps1
$serviceName = "SovereignEngineService"
$binaryPath = "D:\RawrXD\SovereignService.exe"

# Create service
New-Service -Name $serviceName `
    -BinaryPathName $binaryPath `
    -DisplayName "Sovereign AI Inference Engine" `
    -StartupType Automatic `
    -Description "Shared inference service for RawrXD IDE"

# Start service
Start-Service -Name $serviceName

# Configure firewall
New-NetFirewallRule -DisplayName "Sovereign Service" `
    -Direction Inbound `
    -LocalPort 9000 `
    -Protocol TCP `
    -Action Allow
```

---

## Phase 16C: Canary Deployment

### Rollout Strategy

```
Week 1: Internal Testing (5 users)
  ├─ IDE developers only
  ├─ Full telemetry collection
  └─ Daily check-ins

Week 2: Beta Channel (50 users)
  ├─ Opt-in via settings
  ├─ Telemetry comparison vs old system
  └─ Crash monitoring

Week 3: Gradual Rollout (10% of users)
  ├─ Random selection
  ├─ A/B testing metrics
  └─ Automatic rollback on error threshold

Week 4: Full Production
  ├─ 100% rollout
  ├─ Continuous monitoring
  └─ Performance regression alerts
```

### Telemetry Dashboard

```cpp
// Key Metrics to Monitor
struct DeploymentMetrics {
    // Latency
    float p50_first_token_ms;
    float p95_first_token_ms;
    float p99_first_token_ms;
    
    // Stability
    uint32_t crashes_per_hour;
    uint32_t restarts_per_hour;
    float uptime_percentage;
    
    // Usage
    uint32_t active_sessions;
    uint32_t completions_per_hour;
    float acceptance_rate;
    
    // Resources
    float avg_memory_mb;
    float peak_memory_mb;
    float cpu_percent;
};

// Alert Thresholds
#define ALERT_FTL_P95_THRESHOLD 300     // ms
#define ALERT_CRASH_THRESHOLD 5         // per hour
#define ALERT_MEMORY_THRESHOLD 2048     // MB
#define ALERT_UPTIME_THRESHOLD 99.5   // percent
```

---

## Phase 16D: 1000-Iteration Stress Test

### Test Specification

```powershell
# stress_test_1000.ps1
param(
    [int]$Iterations = 1000,
    [int]$ConcurrentWindows = 5,
    [int]$DurationMinutes = 60
)

# Simulate real-world usage pattern
$testProfile = @(
    @{ Action = "type"; Duration = 5; Text = "// Calculate fibonacci" },
    @{ Action = "wait"; Duration = 2 },  # Wait for completion
    @{ Action = "accept"; Duration = 0.5 },
    @{ Action = "edit"; Duration = 10 },
    @{ Action = "type"; Duration = 3; Text = "// Implement quicksort" },
    @{ Action = "wait"; Duration = 2 },
    @{ Action = "reject"; Duration = 0.5 },
    @{ Action = "pause"; Duration = 30 }  # Idle time
)

# Run with system stress
Start-Job { while ($true) { Get-Process | Out-Null } }  # CPU load
Start-Job { fsutil file createnew stress.tmp 1GB }       # Disk load

# Execute test
for ($i = 0; $i -lt $Iterations; $i++) {
    foreach ($step in $testProfile) {
        Execute-TestStep $step
        Log-Telemetry
    }
    
    # Check system health
    $memory = Get-MemoryUsage
    $cpu = Get-CpuUsage
    
    if ($memory -gt 4GB -or $cpu -gt 90) {
        Write-Warning "System under stress: Memory=$memory, CPU=$cpu"
    }
}
```

### Success Criteria

| Metric | Target | Measurement |
|--------|--------|-------------|
| FTL P95 | <250ms | Under CPU load |
| Memory Growth | <100MB/hour | No leaks |
| Crash Rate | 0 | 1000 iterations |
| IPC Timeout | 0 | All requests |

---

## Migration Path

### From IDE-Managed to Service

```cpp
// Seamless migration
class SovereignClient {
public:
    void Initialize() {
        // Try service first
        if (ConnectToService()) {
            mode = ServiceMode;
            return;
        }
        
        // Fall back to managed
        if (StartManagedEngine()) {
            mode = ManagedMode;
            return;
        }
        
        // Degraded: disable AI features
        mode = DisabledMode;
        ShowNotification("AI features disabled - engine unavailable");
    }
    
    void Shutdown() {
        if (mode == ManagedMode) {
            StopManagedEngine();  // Clean up
        }
        // Service mode: don't stop (shared resource)
    }
};
```

---

## Recommendation

**Immediate (Phase 16A):** Deploy IDE-Managed mode with:
- ✅ Version pinning
- ✅ Async telemetry
- ✅ Auto-restart on crash

**Short-term (Phase 16B):** Implement Shared Service for:
- Power users with multiple IDE windows
- Enterprise deployments
- CI/CD integration

**Medium-term (Phase 16C):** Canary deployment with:
- 5 → 50 → 10% → 100% rollout
- Telemetry-driven rollback
- A/B performance comparison

**Long-term (Phase 17):** Hybrid Auto mode that intelligently switches based on:
- Number of open IDE windows
- Available system memory
- User preference

---

## Files to Create

1. `SovereignService.exe` - Windows service executable
2. `Install-SovereignService.ps1` - Service installer
3. `deployment_config.json` - Rollout configuration
4. `canary_dashboard.html` - Real-time monitoring

**Status:** Phase 16A ready for deployment. Phase 16B in planning.
