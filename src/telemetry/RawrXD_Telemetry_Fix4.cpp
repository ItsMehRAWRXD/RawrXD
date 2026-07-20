//=============================================================================
// Fix #4 Telemetry Implementation
// Connects Fused Q4_0 Kernel to Performance Profiling
//=============================================================================

#include "RawrXD_Telemetry_Fix4.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

namespace RawrXD {
namespace Telemetry {

// Static member definitions
Fix4Metrics Fix4TelemetryCollector::s_last_metrics = {};
std::chrono::high_resolution_clock::time_point Fix4TelemetryCollector::s_start_time;
bool Fix4TelemetryCollector::s_collecting = false;

//=============================================================================
// Begin Kernel Execution
//=============================================================================
void Fix4TelemetryCollector::BeginKernelExecution(
    int M, int K, int N,
    const char* kernel_name
) {
    s_collecting = true;
    s_start_time = std::chrono::high_resolution_clock::now();
    
    // Reset metrics
    s_last_metrics = {};
    s_last_metrics.tps_target = 650.0;  // Target TPS
}

//=============================================================================
// End Kernel Execution
//=============================================================================
Fix4Metrics Fix4TelemetryCollector::EndKernelExecution() {
    if (!s_collecting) {
        return s_last_metrics;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - s_start_time
    );
    
    s_last_metrics.kernel_execution_ms = duration.count() / 1000.0;
    s_collecting = false;
    
    return s_last_metrics;
}

//=============================================================================
// Report Checkpoint
//=============================================================================
void Fix4TelemetryCollector::ReportCheckpoint(const char* stage) {
    // Placeholder for intermediate reporting
    // Could be used for multi-stage kernels
}

//=============================================================================
// Export to JSON
//=============================================================================
void Fix4TelemetryCollector::ExportToJSON(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return;
    }
    
    file << "{\n";
    file << "  \"fix_version\": \"Fix #4\",\n";
    file << "  \"kernel\": \"FusedQ4_0_MatMul\",\n";
    file << "  \"target_tps\": " << s_last_metrics.tps_target << ",\n";
    file << "  \"achieved_tps\": " << s_last_metrics.tps_achieved << ",\n";
    file << "  \"efficiency_percent\": " << s_last_metrics.efficiency_percent << ",\n";
    file << "  \"execution_time_ms\": " << s_last_metrics.kernel_execution_ms << ",\n";
    file << "  \"cache_performance\": {\n";
    file << "    \"l1_misses\": " << s_last_metrics.l1_misses << ",\n";
    file << "    \"l3_misses\": " << s_last_metrics.l3_misses << ",\n";
    file << "    \"hit_rate\": " << s_last_metrics.cache_hit_rate << "\n";
    file << "  },\n";
    file << "  \"instruction_mix\": {\n";
    file << "    \"avx512\": " << s_last_metrics.avx512_instructions << ",\n";
    file << "    \"gather\": " << s_last_metrics.gather_instructions << ",\n";
    file << "    \"total\": " << s_last_metrics.total_instructions << "\n";
    file << "  },\n";
    file << "  \"memory\": {\n";
    file << "    \"bandwidth_gbps\": " << s_last_metrics.memory_bandwidth_gbps << ",\n";
    file << "    \"bytes_read\": " << s_last_metrics.bytes_read << ",\n";
    file << "    \"bytes_written\": " << s_last_metrics.bytes_written << "\n";
    file << "  }\n";
    file << "}\n";
    
    file.close();
}

//=============================================================================
// Replay Integration
//=============================================================================

// Static storage for performance history
static std::vector<std::pair<uint64_t, double>> s_tps_history;

void Fix4ReplayIntegration::OnPerformanceSnapshot(
    uint64_t sequence_length,
    const Fix4Metrics& metrics
) {
    // Store TPS at this sequence length
    s_tps_history.push_back({sequence_length, metrics.tps_achieved});
    
    // Check for degradation
    if (IsTPSDegradationDetected(sequence_length, metrics.tps_achieved)) {
        // Log degradation event
        // This could trigger the replay gate to isolate the issue
    }
}

bool Fix4ReplayIntegration::IsTPSDegradationDetected(
    uint64_t sequence_length,
    double current_tps
) {
    // Simple threshold-based detection
    if (current_tps < TPS_DEGRADATION_THRESHOLD) {
        return true;
    }
    
    // Trend analysis: check if TPS is dropping significantly
    if (s_tps_history.size() >= 3) {
        // Get last 3 measurements
        double tps_n = s_tps_history[s_tps_history.size() - 1].second;
        double tps_n1 = s_tps_history[s_tps_history.size() - 2].second;
        double tps_n2 = s_tps_history[s_tps_history.size() - 3].second;
        
        // Check for consistent downward trend
        if (tps_n < tps_n1 && tps_n1 < tps_n2) {
            double drop_rate = (tps_n2 - tps_n) / tps_n2;
            if (drop_rate > 0.15) {  // 15% drop
                return true;
            }
        }
    }
    
    return false;
}

uint32_t Fix4ReplayIntegration::GetRecommendedWindowSize() {
    // Analyze TPS history to find optimal window size
    if (s_tps_history.empty()) {
        return 2048;  // Default
    }
    
    // Find sequence length where TPS starts degrading
    uint64_t degradation_point = 0;
    for (size_t i = 1; i < s_tps_history.size(); ++i) {
        if (s_tps_history[i].second < TPS_DEGRADATION_THRESHOLD) {
            degradation_point = s_tps_history[i].first;
            break;
        }
    }
    
    if (degradation_point == 0) {
        return 2048;  // No degradation detected, use max
    }
    
    // Recommend window size slightly before degradation
    uint32_t recommended = static_cast<uint32_t>(degradation_point * 0.8);
    
    // Round to granularity
    recommended = (recommended / WINDOW_SIZE_GRANULARITY) * WINDOW_SIZE_GRANULARITY;
    
    // Clamp to reasonable bounds
    if (recommended < 512) recommended = 512;
    if (recommended > 4096) recommended = 4096;
    
    return recommended;
}

void Fix4ReplayIntegration::ExportPerformanceProfile(const char* filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return;
    }
    
    file << "{\n";
    file << "  \"profile_type\": \"Fix4_Performance\",\n";
    file << "  \"data_points\": [\n";
    
    for (size_t i = 0; i < s_tps_history.size(); ++i) {
        file << "    {\n";
        file << "      \"sequence_length\": " << s_tps_history[i].first << ",\n";
        file << "      \"tps\": " << s_tps_history[i].second << "\n";
        file << "    }";
        if (i < s_tps_history.size() - 1) {
            file << ",";
        }
        file << "\n";
    }
    
    file << "  ],\n";
    file << "  \"recommended_window_size\": " << GetRecommendedWindowSize() << "\n";
    file << "}\n";
    
    file.close();
}

} // namespace Telemetry
} // namespace RawrXD
