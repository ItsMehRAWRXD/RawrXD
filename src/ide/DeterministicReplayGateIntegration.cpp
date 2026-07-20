/*===========================================================================
 * DeterministicReplayGateIntegration.cpp
 * RawrXD IDE - Deterministic Replay Gate Integration
 * 
 * Implementation of the bridge between the IDE and the Deterministic Replay Gate.
 * This module allows the IDE to inject performance snapshots during replay
 * to isolate the O(n^2) transition point.
 *===========================================================================*/

#include "DeterministicReplayGateIntegration.h"
#include "SovereignTelemetryIntegration.h"
#include <atomic>
#include <mutex>
#include <vector>

/*===========================================================================
 * GATE STATE
 *===========================================================================*/

// Gate active flag - set via environment variable or shared memory
static std::atomic<BOOL> g_GateActive{FALSE};
static std::atomic<uint32_t> g_CurrentSequenceLength{0};

// Snapshot callback for IDE integration
static DRG_SnapshotCallback g_SnapshotCallback = nullptr;
static void* g_SnapshotUserData = nullptr;

// Performance snapshot buffer (circular buffer for efficiency)
static constexpr size_t MAX_SNAPSHOTS = 1024;
static PerformanceSnapshot g_SnapshotBuffer[MAX_SNAPSHOTS];
static std::atomic<size_t> g_SnapshotIndex{0};
static std::mutex g_SnapshotMutex;

// Environment variable to enable gate
static constexpr const char* GATE_ENV_VAR = "RAWRXD_DETERMINISTIC_REPLAY_GATE";

/*===========================================================================
 * INITIALIZATION
 *===========================================================================*/

// Called during IDE startup to check if gate is active
void DRG_Initialize(void) {
    const char* envValue = getenv(GATE_ENV_VAR);
    if (envValue && (strcmp(envValue, "1") == 0 || 
                     _stricmp(envValue, "true") == 0 ||
                     _stricmp(envValue, "yes") == 0)) {
        g_GateActive.store(TRUE);
        OutputDebugStringA("[DRG] Deterministic Replay Gate ACTIVE\n");
    } else {
        g_GateActive.store(FALSE);
    }
}

/*===========================================================================
 * GATE INTEGRATION API
 *===========================================================================*/

BOOL DRG_IsActive(void) {
    return g_GateActive.load();
}

uint32_t DRG_GetCurrentSequenceLength(void) {
    return g_CurrentSequenceLength.load();
}

void DRG_CapturePerformanceSnapshot(const PerformanceSnapshot* snapshot) {
    if (!g_GateActive.load() || !snapshot) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_SnapshotMutex);
    
    // Store in circular buffer
    size_t idx = g_SnapshotIndex.fetch_add(1) % MAX_SNAPSHOTS;
    g_SnapshotBuffer[idx] = *snapshot;
    
    // Also log to telemetry for correlation
    STEL_InferenceEvent event = {};
    event.timestamp = snapshot->timestampUs;
    event.eventType = STEL_EVENT_INFERENCE_COMPLETE; // Reuse for profiling
    event.promptTokens = snapshot->attention.sequenceLength;
    event.generatedTokens = 1; // Single token generation
    event.firstTokenLatencyMs = snapshot->attention.kernelLatencyUs / 1000.0;
    event.generationLatencyMs = snapshot->attention.kernelLatencyUs / 1000.0;
    event.totalLatencyMs = snapshot->attention.kernelLatencyUs / 1000.0;
    event.tokensPerSecond = snapshot->attention.tokensPerSecond;
    event.memoryUsageMB = static_cast<uint32_t>(snapshot->attention.kvCacheBytes / (1024 * 1024));
    event.kvCacheMB = static_cast<uint32_t>(snapshot->attention.kvCacheBytes / (1024 * 1024));
    
    STEL_RecordInference(&event);
    
    // Trigger callback if registered
    if (g_SnapshotCallback) {
        g_SnapshotCallback(snapshot->editorVersion, g_SnapshotUserData);
    }
}

void DRG_CapturePerformanceMarker(uint32_t sequenceLength, uint64_t latencyUs, float tps) {
    if (!g_GateActive.load()) {
        return;
    }
    
    g_CurrentSequenceLength.store(sequenceLength);
    
    // Create lightweight snapshot
    PerformanceSnapshot snapshot = {};
    snapshot.timestampUs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()).count());
    snapshot.sequenceId = sequenceLength;
    snapshot.editorVersion = sequenceLength; // Use sequence as version proxy
    snapshot.attention.sequenceLength = sequenceLength;
    snapshot.attention.kernelLatencyUs = latencyUs;
    snapshot.attention.tokensPerSecond = tps;
    
    DRG_CapturePerformanceSnapshot(&snapshot);
}

void DRG_NotifyCacheEviction(uint32_t tokensEvicted) {
    if (!g_GateActive.load()) {
        return;
    }
    
    // Log cache eviction event
    char msg[256];
    snprintf(msg, sizeof(msg), "[DRG] Cache eviction: %u tokens", tokensEvicted);
    OutputDebugStringA(msg);
    
    // Could also trigger a snapshot here to correlate with TPS drop
}

void DRG_NotifyAttentionComplete(uint32_t sequenceLength, uint64_t latencyUs) {
    if (!g_GateActive.load()) {
        return;
    }
    
    g_CurrentSequenceLength.store(sequenceLength);
    
    // Calculate TPS from latency
    float tps = (latencyUs > 0) ? (1000000.0f / latencyUs) : 0.0f;
    
    // Capture marker
    DRG_CapturePerformanceMarker(sequenceLength, latencyUs, tps);
    
    // Log O(n^2) analysis
    // Theoretical O(n^2) latency: L = k * n^2
    // If latency grows faster than linear, we're hitting the O(n^2) wall
    static uint64_t lastLatency = 0;
    static uint32_t lastSequence = 0;
    
    if (lastSequence > 0 && sequenceLength > lastSequence) {
        float latencyRatio = static_cast<float>(latencyUs) / static_cast<float>(lastLatency);
        float sequenceRatio = static_cast<float>(sequenceLength) / static_cast<float>(lastSequence);
        
        // If latency grows faster than sequence length, we're in O(n^2) territory
        if (latencyRatio > sequenceRatio * 1.5f) {
            char msg[256];
            snprintf(msg, sizeof(msg), 
                "[DRG] O(n^2) detected: n=%u, latency=%llu us, ratio=%.2f", 
                sequenceLength, latencyUs, latencyRatio / sequenceRatio);
            OutputDebugStringA(msg);
        }
    }
    
    lastLatency = latencyUs;
    lastSequence = sequenceLength;
}

/*===========================================================================
 * DEBUG BRIDGE INTEGRATION
 *===========================================================================*/

void DRG_DumpKVCacheState(void) {
    if (!g_GateActive.load()) {
        return;
    }
    
    // This would interface with the actual KV cache implementation
    // For now, just log that a dump was requested
    OutputDebugStringA("[DRG] KV Cache state dump requested\n");
}

void DRG_DumpAttentionMetrics(void) {
    if (!g_GateActive.load()) {
        return;
    }
    
    // Export all captured snapshots
    std::lock_guard<std::mutex> lock(g_SnapshotMutex);
    
    size_t count = g_SnapshotIndex.load();
    if (count > MAX_SNAPSHOTS) {
        count = MAX_SNAPSHOTS;
    }
    
    char msg[256];
    snprintf(msg, sizeof(msg), "[DRG] Attention metrics: %zu snapshots captured", count);
    OutputDebugStringA(msg);
}

void DRG_SetSnapshotCallback(DRG_SnapshotCallback callback, void* userData) {
    g_SnapshotCallback = callback;
    g_SnapshotUserData = userData;
}

/*===========================================================================
 * EXPORTED FUNCTIONS FOR GATE
 *===========================================================================
 * These functions are called by the deterministic_replay_gate.exe
 * when it needs to query IDE state.
 */

// Export function to get snapshot count
extern "C" __declspec(dllexport) size_t DRG_GetSnapshotCount(void) {
    size_t count = g_SnapshotIndex.load();
    return (count > MAX_SNAPSHOTS) ? MAX_SNAPSHOTS : count;
}

// Export function to get a specific snapshot
extern "C" __declspec(dllexport) BOOL DRG_GetSnapshot(size_t index, PerformanceSnapshot* outSnapshot) {
    if (!outSnapshot || index >= MAX_SNAPSHOTS) {
        return FALSE;
    }
    
    std::lock_guard<std::mutex> lock(g_SnapshotMutex);
    size_t count = g_SnapshotIndex.load();
    if (count > MAX_SNAPSHOTS) {
        count = MAX_SNAPSHOTS;
    }
    
    if (index >= count) {
        return FALSE;
    }
    
    *outSnapshot = g_SnapshotBuffer[index];
    return TRUE;
}

// Export function to clear snapshots
extern "C" __declspec(dllexport) void DRG_ClearSnapshots(void) {
    std::lock_guard<std::mutex> lock(g_SnapshotMutex);
    g_SnapshotIndex.store(0);
}
