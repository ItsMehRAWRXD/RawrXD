/*===========================================================================
 * flash_attention_telemetry.hpp
 * 
 * Flash Attention Telemetry Extension
 * 
 * Extends Fix4 telemetry with Flash Attention specific metrics:
 *   - Tile processing statistics
 *   - Memory bandwidth utilization
 *   - KV cache access patterns
 *   - Online softmax performance
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <chrono>
#include <atomic>

namespace RawrXD {
namespace Telemetry {

// Flash Attention telemetry data structure
struct FlashAttentionTelemetry {
    // Counters
    std::atomic<uint64_t> tilesProcessed{0};
    std::atomic<uint64_t> kvBytesRead{0};
    std::atomic<uint64_t> qBytesRead{0};
    std::atomic<uint64_t> totalTokens{0};
    
    // Timing (in microseconds)
    std::atomic<uint64_t> attentionTimeUs{0};
    std::atomic<uint64_t> softmaxTimeUs{0};
    std::atomic<uint64_t> totalTimeUs{0};
    
    // Configuration
    std::atomic<uint32_t> tileSize{128};
    std::atomic<uint32_t> headDimension{64};
    std::atomic<uint32_t> numHeads{128};
    
    // Status flags
    std::atomic<bool> avx512Active{false};
    std::atomic<bool> onlineSoftmax{false};
    std::atomic<bool> kernelActive{false};
    
    // Performance metrics
    std::atomic<double> currentTPS{0.0};
    std::atomic<double> peakTPS{0.0};
    std::atomic<double> avgLatencyUs{0.0};
    
    // Cache statistics (if available)
    std::atomic<uint64_t> l2Hits{0};
    std::atomic<uint64_t> l2Misses{0};
    std::atomic<double> l2HitRate{0.0};
    
    // Reset all counters
    void Reset() {
        tilesProcessed = 0;
        kvBytesRead = 0;
        qBytesRead = 0;
        totalTokens = 0;
        attentionTimeUs = 0;
        softmaxTimeUs = 0;
        totalTimeUs = 0;
        currentTPS = 0.0;
        peakTPS = 0.0;
        avgLatencyUs = 0.0;
        l2Hits = 0;
        l2Misses = 0;
        l2HitRate = 0.0;
    }
    
    // Calculate derived metrics
    double GetMemoryBandwidthGBps() const;
    double GetAttentionEfficiency() const;
    double GetSoftmaxOverhead() const;
};

// Global telemetry instance
extern FlashAttentionTelemetry g_flashAttentionTelemetry;

// Telemetry collector class
class FlashAttentionTelemetryCollector {
public:
    FlashAttentionTelemetryCollector();
    ~FlashAttentionTelemetryCollector();
    
    // Start/stop collection
    void StartCollection();
    void StopCollection();
    
    // Record tile processed
    void RecordTile(uint32_t tokensInTile, uint64_t elapsedUs);
    
    // Record memory access
    void RecordMemoryAccess(uint64_t kvBytes, uint64_t qBytes);
    
    // Update TPS
    void UpdateTPS(double tps);
    
    // Get current snapshot
    FlashAttentionTelemetry GetSnapshot() const;
    
    // Export to JSON
    void ExportJSON(const std::string& path) const;
    
    // Real-time monitoring
    void StartRealtimeMonitor(uint32_t intervalMs = 1000);
    void StopRealtimeMonitor();
    
private:
    bool m_collecting = false;
    std::chrono::steady_clock::time_point m_startTime;
    
    // Real-time monitoring
    bool m_monitoring = false;
    void MonitorThread();
};

// C API exports
extern "C" {
    __declspec(dllexport) void RawrXD_FATelemetry_Reset();
    __declspec(dllexport) uint64_t RawrXD_FATelemetry_GetTilesProcessed();
    __declspec(dllexport) double RawrXD_FATelemetry_GetCurrentTPS();
    __declspec(dllexport) double RawrXD_FATelemetry_GetPeakTPS();
    __declspec(dllexport) double RawrXD_FATelemetry_GetMemoryBandwidthGBps();
    __declspec(dllexport) bool RawrXD_FATelemetry_IsAVX512Active();
}

} // namespace Telemetry
} // namespace RawrXD
