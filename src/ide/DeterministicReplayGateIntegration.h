/*===========================================================================
 * DeterministicReplayGateIntegration.h
 * RawrXD IDE - Deterministic Replay Gate Integration
 * 
 * Bridges the IDE with the Deterministic Replay Gate for performance profiling.
 * When the gate is active, the IDE can inject performance snapshots at specific
 * sequence intervals to isolate the O(n^2) transition point.
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * PERFORMANCE SNAPSHOT STRUCTURES
 *===========================================================================
 * These mirror the structures in deterministic_replay_gate.cpp
 * to ensure binary compatibility.
 */

typedef struct _AttentionKernelMetrics {
    uint64_t kernelLatencyUs;      // Attention kernel execution time
    uint32_t sequenceLength;       // Current sequence length (n)
    uint32_t kvCacheTokens;        // Number of tokens in KV cache
    size_t   kvCacheBytes;         // KV cache memory usage
    float    tokensPerSecond;      // Instantaneous TPS
    float    memoryBandwidthGBps;  // Memory bandwidth utilization
    uint32_t layerCount;           // Number of transformer layers
    uint32_t headCount;            // Number of attention heads
    uint32_t headDim;              // Dimension per head
} AttentionKernelMetrics;

typedef struct _PerformanceSnapshot {
    uint64_t timestampUs;
    uint32_t sequenceId;
    uint32_t editorVersion;
    AttentionKernelMetrics attention;
    
    // O(n^2) analysis fields
    float theoreticalOps;          // Theoretical FLOPs for attention
    float achievedOps;             // Actual achieved FLOPs
    float efficiency;              // achieved / theoretical
    
    // KV Cache state
    BOOL kvCacheHit;               // Cache hit for this token
    uint32_t cacheEvictions;       // Number of cache entries evicted
    
    // Sliding window analysis
    uint32_t windowSize;           // Current sliding window size
    uint32_t tokensOutsideWindow;  // Tokens not in attention window
} PerformanceSnapshot;

/*===========================================================================
 * GATE INTEGRATION API
 *===========================================================================*/

/* Check if the Deterministic Replay Gate is currently active */
BOOL DRG_IsActive(void);

/* Get the current sequence length being tracked by the gate */
uint32_t DRG_GetCurrentSequenceLength(void);

/* 
 * Capture a performance snapshot from the IDE.
 * Call this at sequence intervals (e.g., every 128 tokens) during inference.
 * Only records if the gate is active.
 */
void DRG_CapturePerformanceSnapshot(const PerformanceSnapshot* snapshot);

/* 
 * Capture a lightweight performance marker.
 * Used for high-frequency sampling without full snapshot overhead.
 */
void DRG_CapturePerformanceMarker(uint32_t sequenceLength, uint64_t latencyUs, float tps);

/* 
 * Notify the gate that a KV cache eviction occurred.
 * Helps correlate TPS drops with cache pressure.
 */
void DRG_NotifyCacheEviction(uint32_t tokensEvicted);

/* 
 * Notify the gate that attention kernel completed.
 * Captures the O(n^2) latency data.
 */
void DRG_NotifyAttentionComplete(uint32_t sequenceLength, uint64_t latencyUs);

/*===========================================================================
 * DEBUG BRIDGE INTEGRATION
 *===========================================================================
 * These functions are called by the DebugBridge when the gate requests
 * high-fidelity telemetry dumps.
 */

/* Trigger a KV cache state dump to the gate */
void DRG_DumpKVCacheState(void);

/* Trigger an attention kernel latency report to the gate */
void DRG_DumpAttentionMetrics(void);

/* 
 * Register a callback for when the gate requests a perf snapshot.
 * The IDE should call this during initialization.
 */
typedef void (*DRG_SnapshotCallback)(uint32_t editorVersion, void* userData);
void DRG_SetSnapshotCallback(DRG_SnapshotCallback callback, void* userData);

#ifdef __cplusplus
}
#endif
