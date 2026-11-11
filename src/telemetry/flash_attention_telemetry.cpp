/*===========================================================================
 * flash_attention_telemetry.cpp
 * 
 * Flash Attention Telemetry Implementation
 *===========================================================================*/

#include "flash_attention_telemetry.hpp"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <iostream>

namespace RawrXD {
namespace Telemetry {

// Global telemetry instance
FlashAttentionTelemetry g_flashAttentionTelemetry;

// FlashAttentionTelemetry implementation
double FlashAttentionTelemetry::GetMemoryBandwidthGBps() const {
    double totalBytes = static_cast<double>(kvBytesRead.load() + qBytesRead.load());
    double totalTimeS = totalTimeUs.load() / 1e6;
    
    if (totalTimeS <= 0) return 0.0;
    return (totalBytes / totalTimeS) / 1e9;  // GB/s
}

double FlashAttentionTelemetry::GetAttentionEfficiency() const {
    double attnTime = attentionTimeUs.load();
    double totalTime = totalTimeUs.load();
    
    if (totalTime <= 0) return 0.0;
    return attnTime / totalTime;  // Fraction of time in attention
}

double FlashAttentionTelemetry::GetSoftmaxOverhead() const {
    double smTime = softmaxTimeUs.load();
    double attnTime = attentionTimeUs.load();
    
    if (attnTime <= 0) return 0.0;
    return smTime / attnTime;  // Softmax as fraction of attention time
}

// FlashAttentionTelemetryCollector implementation
FlashAttentionTelemetryCollector::FlashAttentionTelemetryCollector() = default;
FlashAttentionTelemetryCollector::~FlashAttentionTelemetryCollector() {
    StopCollection();
    StopRealtimeMonitor();
}

void FlashAttentionTelemetryCollector::StartCollection() {
    g_flashAttentionTelemetry.Reset();
    g_flashAttentionTelemetry.kernelActive = true;
    m_startTime = std::chrono::steady_clock::now();
    m_collecting = true;
}

void FlashAttentionTelemetryCollector::StopCollection() {
    if (!m_collecting) return;
    
    auto endTime = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(endTime - m_startTime);
    g_flashAttentionTelemetry.totalTimeUs = elapsed.count();
    g_flashAttentionTelemetry.kernelActive = false;
    m_collecting = false;
}

void FlashAttentionTelemetryCollector::RecordTile(uint32_t tokensInTile, uint64_t elapsedUs) {
    g_flashAttentionTelemetry.tilesProcessed++;
    g_flashAttentionTelemetry.totalTokens += tokensInTile;
    g_flashAttentionTelemetry.attentionTimeUs += elapsedUs;
    
    // Update current TPS
    double tps = tokensInTile / (elapsedUs / 1e6);
    g_flashAttentionTelemetry.currentTPS = tps;
    
    // Update peak TPS
    double peak = g_flashAttentionTelemetry.peakTPS.load();
    while (tps > peak && !g_flashAttentionTelemetry.peakTPS.compare_exchange_weak(peak, tps)) {
        // Retry if another thread updated peak
    }
}

void FlashAttentionTelemetryCollector::RecordMemoryAccess(uint64_t kvBytes, uint64_t qBytes) {
    g_flashAttentionTelemetry.kvBytesRead += kvBytes;
    g_flashAttentionTelemetry.qBytesRead += qBytes;
}

void FlashAttentionTelemetryCollector::UpdateTPS(double tps) {
    g_flashAttentionTelemetry.currentTPS = tps;
    
    double peak = g_flashAttentionTelemetry.peakTPS.load();
    while (tps > peak && !g_flashAttentionTelemetry.peakTPS.compare_exchange_weak(peak, tps)) {
        // Retry
    }
}

FlashAttentionTelemetry FlashAttentionTelemetryCollector::GetSnapshot() const {
    return g_flashAttentionTelemetry;
}

void FlashAttentionTelemetryCollector::ExportJSON(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return;
    
    auto telem = GetSnapshot();
    
    file << "{\n";
    file << "  \"flash_attention_telemetry\": {\n";
    file << "    \"counters\": {\n";
    file << "      \"tiles_processed\": " << telem.tilesProcessed.load() << ",\n";
    file << "      \"kv_bytes_read\": " << telem.kvBytesRead.load() << ",\n";
    file << "      \"q_bytes_read\": " << telem.qBytesRead.load() << ",\n";
    file << "      \"total_tokens\": " << telem.totalTokens.load() << "\n";
    file << "    },\n";
    file << "    \"timing_us\": {\n";
    file << "      \"attention\": " << telem.attentionTimeUs.load() << ",\n";
    file << "      \"softmax\": " << telem.softmaxTimeUs.load() << ",\n";
    file << "      \"total\": " << telem.totalTimeUs.load() << "\n";
    file << "    },\n";
    file << "    \"configuration\": {\n";
    file << "      \"tile_size\": " << telem.tileSize.load() << ",\n";
    file << "      \"head_dimension\": " << telem.headDimension.load() << ",\n";
    file << "      \"num_heads\": " << telem.numHeads.load() << "\n";
    file << "    },\n";
    file << "    \"status\": {\n";
    file << "      \"avx512_active\": " << (telem.avx512Active.load() ? "true" : "false") << ",\n";
    file << "      \"online_softmax\": " << (telem.onlineSoftmax.load() ? "true" : "false") << ",\n";
    file << "      \"kernel_active\": " << (telem.kernelActive.load() ? "true" : "false") << "\n";
    file << "    },\n";
    file << "    \"performance\": {\n";
    file << "      \"current_tps\": " << std::fixed << std::setprecision(2) << telem.currentTPS.load() << ",\n";
    file << "      \"peak_tps\": " << telem.peakTPS.load() << ",\n";
    file << "      \"avg_latency_us\": " << telem.avgLatencyUs.load() << ",\n";
    file << "      \"memory_bandwidth_gbps\": " << telem.GetMemoryBandwidthGBps() << ",\n";
    file << "      \"attention_efficiency\": " << telem.GetAttentionEfficiency() << ",\n";
    file << "      \"softmax_overhead\": " << telem.GetSoftmaxOverhead() << "\n";
    file << "    },\n";
    file << "    \"cache\": {\n";
    file << "      \"l2_hits\": " << telem.l2Hits.load() << ",\n";
    file << "      \"l2_misses\": " << telem.l2Misses.load() << ",\n";
    file << "      \"l2_hit_rate\": " << telem.l2HitRate.load() << "\n";
    file << "    }\n";
    file << "  }\n";
    file << "}\n";
}

void FlashAttentionTelemetryCollector::StartRealtimeMonitor(uint32_t intervalMs) {
    if (m_monitoring) return;
    m_monitoring = true;
    
    std::thread monitorThread([this, intervalMs]() {
        while (m_monitoring) {
            auto telem = GetSnapshot();
            
            std::cout << "\r[FA Telemetry] "
                      << "TPS: " << std::fixed << std::setprecision(1) << telem.currentTPS.load()
                      << " | Peak: " << telem.peakTPS.load()
                      << " | Tiles: " << telem.tilesProcessed.load()
                      << " | BW: " << std::setprecision(2) << telem.GetMemoryBandwidthGBps() << " GB/s"
                      << " | L2: " << std::setprecision(1) << (telem.l2HitRate.load() * 100) << "%"
                      << std::flush;
            
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
    });
    
    monitorThread.detach();
}

void FlashAttentionTelemetryCollector::StopRealtimeMonitor() {
    m_monitoring = false;
    std::cout << std::endl;  // New line after monitor stops
}

// C API exports
extern "C" {

__declspec(dllexport) void RawrXD_FATelemetry_Reset() {
    RawrXD::Telemetry::g_flashAttentionTelemetry.Reset();
}

__declspec(dllexport) uint64_t RawrXD_FATelemetry_GetTilesProcessed() {
    return RawrXD::Telemetry::g_flashAttentionTelemetry.tilesProcessed.load();
}

__declspec(dllexport) double RawrXD_FATelemetry_GetCurrentTPS() {
    return RawrXD::Telemetry::g_flashAttentionTelemetry.currentTPS.load();
}

__declspec(dllexport) double RawrXD_FATelemetry_GetPeakTPS() {
    return RawrXD::Telemetry::g_flashAttentionTelemetry.peakTPS.load();
}

__declspec(dllexport) double RawrXD_FATelemetry_GetMemoryBandwidthGBps() {
    return RawrXD::Telemetry::g_flashAttentionTelemetry.GetMemoryBandwidthGBps();
}

__declspec(dllexport) bool RawrXD_FATelemetry_IsAVX512Active() {
    return RawrXD::Telemetry::g_flashAttentionTelemetry.avx512Active.load();
}

} // extern "C"

} // namespace Telemetry
} // namespace RawrXD
