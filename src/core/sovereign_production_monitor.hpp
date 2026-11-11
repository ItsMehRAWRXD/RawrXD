// ============================================================================
// sovereign_production_monitor.hpp - Phase 10: Production Hardening
// Monitoring, metrics, logging, and production-ready features
// ============================================================================

#ifndef SOVEREIGN_PRODUCTION_MONITOR_HPP
#define SOVEREIGN_PRODUCTION_MONITOR_HPP

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>

namespace Sovereign {

// ============================================================================
// Metrics Types
// ============================================================================
struct DecodeMetrics {
    uint64_t total_requests = 0;
    uint64_t successful_requests = 0;
    uint64_t failed_requests = 0;
    uint64_t total_tokens_processed = 0;
    uint64_t total_tokens_generated = 0;
    double avg_latency_ms = 0.0;
    double p95_latency_ms = 0.0;
    double p99_latency_ms = 0.0;
    uint64_t active_requests = 0;
    uint64_t peak_concurrent = 0;
};

struct SystemMetrics {
    uint64_t memory_used_mb = 0;
    uint64_t memory_available_mb = 0;
    double cpu_percent = 0.0;
    uint64_t uptime_seconds = 0;
    uint32_t active_threads = 0;
    uint32_t thread_pool_size = 0;
};

struct EpochMetrics {
    uint32_t current_epoch = 0;
    uint64_t epoch_switches = 0;
    uint64_t epoch_switch_time_us = 0;
    std::string current_model_id;
    bool model_loaded = false;
};

// ============================================================================
// Production Monitor
// ============================================================================
class ProductionMonitor {
public:
    ProductionMonitor();
    ~ProductionMonitor();

    // Initialize monitoring system
    bool Initialize(const std::string& log_path = "");
    void Shutdown();

    // Request tracking
    void BeginRequest();
    void EndRequest(bool success, uint64_t latency_ms, 
                    uint32_t tokens_in, uint32_t tokens_out);

    // Token tracking
    void RecordTokensProcessed(uint32_t count);
    void RecordTokensGenerated(uint32_t count);

    // Epoch tracking
    void RecordEpochSwitch(uint32_t new_epoch, const std::string& model_id);
    void SetModelLoaded(bool loaded, const std::string& model_id);

    // System metrics
    void UpdateSystemMetrics();
    
    // Getters
    DecodeMetrics GetDecodeMetrics() const;
    SystemMetrics GetSystemMetrics() const;
    EpochMetrics GetEpochMetrics() const;

    // Health check
    bool IsHealthy() const;
    std::string GetHealthStatus() const;

    // Logging
    void LogInfo(const std::string& message);
    void LogWarning(const std::string& message);
    void LogError(const std::string& message);
    void LogMetric(const std::string& name, double value);

    // JSON export for monitoring endpoints
    std::string ExportMetricsJSON() const;
    std::string ExportHealthJSON() const;

    // Singleton access
    static ProductionMonitor* GetInstance();

private:
    bool initialized_;
    std::string log_path_;
    HANDLE log_file_;
    HANDLE metrics_mutex_;
    
    // Metrics storage
    DecodeMetrics decode_metrics_;
    SystemMetrics system_metrics_;
    EpochMetrics epoch_metrics_;
    
    // Latency histogram for percentile calculation
    std::vector<double> latency_history_;
    static constexpr size_t MAX_LATENCY_HISTORY = 10000;
    
    // Start time for uptime calculation
    uint64_t start_time_ms_;
    
    // Internal helpers
    void WriteLog(const std::string& level, const std::string& message);
    void CalculatePercentiles();
    uint64_t GetCurrentTimeMs() const;
    void UpdateMemoryMetrics();
    void UpdateCpuMetrics();
};

// ============================================================================
// Signal Handler for Graceful Shutdown
// ============================================================================
class GracefulShutdownHandler {
public:
    using ShutdownCallback = void(*)();

    static bool Install(ShutdownCallback callback);
    static void TriggerShutdown();
    static bool IsShuttingDown();
    static void WaitForShutdown();

private:
    static ShutdownCallback callback_;
    static std::atomic<bool> shutdown_requested_;
    static HANDLE shutdown_event_;
    
    static BOOL WINAPI ConsoleHandler(DWORD signal);
};

// ============================================================================
// Performance Telemetry
// ============================================================================
class PerformanceTelemetry {
public:
    struct Timer {
        const char* name;
        uint64_t start_ticks;
        uint64_t end_ticks;
        
        Timer(const char* n) : name(n), start_ticks(GetTickCount64()), end_ticks(0) {}
        ~Timer() { End(); }
        
        void End() {
            if (end_ticks == 0) {
                end_ticks = GetTickCount64();
                PerformanceTelemetry::Record(name, end_ticks - start_ticks);
            }
        }
        
        uint64_t ElapsedMs() const {
            return end_ticks ? (end_ticks - start_ticks) : (GetTickCount64() - start_ticks);
        }
    };
    
    static void Record(const char* operation, uint64_t duration_ms);
    static std::string GetReport();
    static void Reset();

private:
    struct OperationStats {
        uint64_t count = 0;
        uint64_t total_ms = 0;
        uint64_t min_ms = UINT64_MAX;
        uint64_t max_ms = 0;
    };
    
    static std::vector<std::pair<std::string, OperationStats>> stats_;
    static CRITICAL_SECTION cs_;
    static bool initialized_;
};

// Convenience macro for timing
#define TIME_OPERATION(name) Sovereign::PerformanceTelemetry::Timer _timer(name)

} // namespace Sovereign

#endif // SOVEREIGN_PRODUCTION_MONITOR_HPP
