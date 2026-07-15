// ============================================================================
// sovereign_production_monitor.cpp - Phase 10: Production Hardening
// Monitoring, metrics, logging, and production-ready features
// ============================================================================

#include "sovereign_production_monitor.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <time.h>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace Sovereign {

// ============================================================================
// Singleton Instance
// ============================================================================
static ProductionMonitor* g_monitor = nullptr;

ProductionMonitor* ProductionMonitor::GetInstance() {
    if (!g_monitor) {
        g_monitor = new ProductionMonitor();
    }
    return g_monitor;
}

// ============================================================================
// Constructor/Destructor
// ============================================================================
ProductionMonitor::ProductionMonitor() 
    : initialized_(false), log_file_(INVALID_HANDLE_VALUE), start_time_ms_(0) {
    metrics_mutex_ = CreateMutexA(NULL, FALSE, NULL);
    latency_history_.reserve(MAX_LATENCY_HISTORY);
}

ProductionMonitor::~ProductionMonitor() {
    Shutdown();
    if (metrics_mutex_) {
        CloseHandle(metrics_mutex_);
    }
}

// ============================================================================
// Initialization
// ============================================================================
bool ProductionMonitor::Initialize(const std::string& log_path) {
    if (initialized_) {
        return true;
    }

    log_path_ = log_path.empty() ? "sovereign_monitor.log" : log_path;
    start_time_ms_ = GetCurrentTimeMs();

    // Open log file
    log_file_ = CreateFileA(
        log_path_.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (log_file_ == INVALID_HANDLE_VALUE) {
        // Log to stderr if file can't be opened
        fprintf(stderr, "[Monitor] Warning: Could not open log file: %s\n", log_path_.c_str());
    } else {
        // Move to end of file for appending
        SetFilePointer(log_file_, 0, NULL, FILE_END);
    }

    initialized_ = true;
    LogInfo("Production monitor initialized");
    
    return true;
}

void ProductionMonitor::Shutdown() {
    if (!initialized_) {
        return;
    }

    LogInfo("Production monitor shutting down");

    if (log_file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(log_file_);
        log_file_ = INVALID_HANDLE_VALUE;
    }

    initialized_ = false;
}

// ============================================================================
// Request Tracking
// ============================================================================
void ProductionMonitor::BeginRequest() {
    if (!initialized_) return;

    WaitForSingleObject(metrics_mutex_, INFINITE);
    
    decode_metrics_.total_requests++;
    decode_metrics_.active_requests++;
    
    if (decode_metrics_.active_requests > decode_metrics_.peak_concurrent) {
        decode_metrics_.peak_concurrent = decode_metrics_.active_requests;
    }

    ReleaseMutex(metrics_mutex_);
}

void ProductionMonitor::EndRequest(bool success, uint64_t latency_ms, 
                                   uint32_t tokens_in, uint32_t tokens_out) {
    if (!initialized_) return;

    WaitForSingleObject(metrics_mutex_, INFINITE);

    decode_metrics_.active_requests--;
    
    if (success) {
        decode_metrics_.successful_requests++;
    } else {
        decode_metrics_.failed_requests++;
    }

    decode_metrics_.total_tokens_processed += tokens_in;
    decode_metrics_.total_tokens_generated += tokens_out;

    // Update latency history
    latency_history_.push_back(static_cast<double>(latency_ms));
    if (latency_history_.size() > MAX_LATENCY_HISTORY) {
        latency_history_.erase(latency_history_.begin());
    }

    // Recalculate percentiles
    CalculatePercentiles();

    ReleaseMutex(metrics_mutex_);
}

// ============================================================================
// Token Tracking
// ============================================================================
void ProductionMonitor::RecordTokensProcessed(uint32_t count) {
    if (!initialized_) return;
    
    WaitForSingleObject(metrics_mutex_, INFINITE);
    decode_metrics_.total_tokens_processed += count;
    ReleaseMutex(metrics_mutex_);
}

void ProductionMonitor::RecordTokensGenerated(uint32_t count) {
    if (!initialized_) return;
    
    WaitForSingleObject(metrics_mutex_, INFINITE);
    decode_metrics_.total_tokens_generated += count;
    ReleaseMutex(metrics_mutex_);
}

// ============================================================================
// Epoch Tracking
// ============================================================================
void ProductionMonitor::RecordEpochSwitch(uint32_t new_epoch, const std::string& model_id) {
    if (!initialized_) return;

    WaitForSingleObject(metrics_mutex_, INFINITE);
    
    uint64_t switch_start = GetTickCount64();
    epoch_metrics_.current_epoch = new_epoch;
    epoch_metrics_.epoch_switches++;
    epoch_metrics_.current_model_id = model_id;
    epoch_metrics_.epoch_switch_time_us = (GetTickCount64() - switch_start) * 1000;

    ReleaseMutex(metrics_mutex_);

    char msg[256];
    snprintf(msg, sizeof(msg), "Epoch switch: %u -> %u, model: %s", 
             new_epoch - 1, new_epoch, model_id.c_str());
    LogInfo(msg);
}

void ProductionMonitor::SetModelLoaded(bool loaded, const std::string& model_id) {
    if (!initialized_) return;

    WaitForSingleObject(metrics_mutex_, INFINITE);
    epoch_metrics_.model_loaded = loaded;
    epoch_metrics_.current_model_id = model_id;
    ReleaseMutex(metrics_mutex_);

    char msg[256];
    snprintf(msg, sizeof(msg), "Model %s: %s", 
             loaded ? "loaded" : "unloaded", model_id.c_str());
    LogInfo(msg);
}

// ============================================================================
// System Metrics
// ============================================================================
void ProductionMonitor::UpdateSystemMetrics() {
    if (!initialized_) return;

    WaitForSingleObject(metrics_mutex_, INFINITE);

    UpdateMemoryMetrics();
    UpdateCpuMetrics();

    system_metrics_.uptime_seconds = (GetCurrentTimeMs() - start_time_ms_) / 1000;

    ReleaseMutex(metrics_mutex_);
}

void ProductionMonitor::UpdateMemoryMetrics() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        system_metrics_.memory_used_mb = pmc.WorkingSetSize / (1024 * 1024);
    }

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        system_metrics_.memory_available_mb = memStatus.ullAvailPhys / (1024 * 1024);
    }
}

void ProductionMonitor::UpdateCpuMetrics() {
    // Simplified CPU calculation - in production, use performance counters
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime)) {
        // Convert to 100-nanosecond intervals
        ULARGE_INTEGER kernel, user;
        kernel.LowPart = kernelTime.dwLowDateTime;
        kernel.HighPart = kernelTime.dwHighDateTime;
        user.LowPart = userTime.dwLowDateTime;
        user.HighPart = userTime.dwHighDateTime;
        
        // This is simplified - real implementation would track over time
        system_metrics_.cpu_percent = 0.0;
    }
}

// ============================================================================
// Getters
// ============================================================================
DecodeMetrics ProductionMonitor::GetDecodeMetrics() const {
    WaitForSingleObject(metrics_mutex_, INFINITE);
    DecodeMetrics metrics = decode_metrics_;
    ReleaseMutex(metrics_mutex_);
    return metrics;
}

SystemMetrics ProductionMonitor::GetSystemMetrics() const {
    WaitForSingleObject(metrics_mutex_, INFINITE);
    SystemMetrics metrics = system_metrics_;
    ReleaseMutex(metrics_mutex_);
    return metrics;
}

EpochMetrics ProductionMonitor::GetEpochMetrics() const {
    WaitForSingleObject(metrics_mutex_, INFINITE);
    EpochMetrics metrics = epoch_metrics_;
    ReleaseMutex(metrics_mutex_);
    return metrics;
}

// ============================================================================
// Health Check
// ============================================================================
bool ProductionMonitor::IsHealthy() const {
    if (!initialized_) return false;

    WaitForSingleObject(metrics_mutex_, INFINITE);
    
    // Health criteria:
    // - Less than 50% failure rate
    // - Memory usage under 90%
    // - Model is loaded
    bool healthy = true;
    
    if (decode_metrics_.total_requests > 0) {
        double failure_rate = (double)decode_metrics_.failed_requests / decode_metrics_.total_requests;
        if (failure_rate > 0.5) healthy = false;
    }
    
    if (system_metrics_.memory_available_mb > 0) {
        double memory_usage = (double)system_metrics_.memory_used_mb / 
                             (system_metrics_.memory_used_mb + system_metrics_.memory_available_mb);
        if (memory_usage > 0.9) healthy = false;
    }
    
    if (!epoch_metrics_.model_loaded) healthy = false;

    ReleaseMutex(metrics_mutex_);
    return healthy;
}

std::string ProductionMonitor::GetHealthStatus() const {
    if (!initialized_) return "not_initialized";
    return IsHealthy() ? "healthy" : "degraded";
}

// ============================================================================
// Logging
// ============================================================================
void ProductionMonitor::LogInfo(const std::string& message) {
    WriteLog("INFO", message);
}

void ProductionMonitor::LogWarning(const std::string& message) {
    WriteLog("WARN", message);
}

void ProductionMonitor::LogError(const std::string& message) {
    WriteLog("ERROR", message);
}

void ProductionMonitor::LogMetric(const std::string& name, double value) {
    char msg[256];
    snprintf(msg, sizeof(msg), "METRIC %s=%.3f", name.c_str(), value);
    WriteLog("METRIC", msg);
}

void ProductionMonitor::WriteLog(const std::string& level, const std::string& message) {
    // Get timestamp
    time_t now = time(NULL);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &timeinfo);

    // Format log line
    char log_line[1024];
    snprintf(log_line, sizeof(log_line), "[%s] [%s] %s\r\n", 
             timestamp, level.c_str(), message.c_str());

    // Write to file
    if (log_file_ != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(log_file_, log_line, (DWORD)strlen(log_line), &written, NULL);
        FlushFileBuffers(log_file_);
    }

    // Also print to stderr for visibility
    fprintf(stderr, "%s", log_line);
}

// ============================================================================
// JSON Export
// ============================================================================
std::string ProductionMonitor::ExportMetricsJSON() const {
    WaitForSingleObject(metrics_mutex_, INFINITE);

    char json[4096];
    int pos = 0;

    pos += snprintf(json + pos, sizeof(json) - pos, "{");
    
    // Decode metrics
    pos += snprintf(json + pos, sizeof(json) - pos, "\"decode\":{");
    pos += snprintf(json + pos, sizeof(json) - pos, "\"total_requests\":%llu,", decode_metrics_.total_requests);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"successful\":%llu,", decode_metrics_.successful_requests);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"failed\":%llu,", decode_metrics_.failed_requests);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"tokens_processed\":%llu,", decode_metrics_.total_tokens_processed);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"tokens_generated\":%llu,", decode_metrics_.total_tokens_generated);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"avg_latency_ms\":%.2f,", decode_metrics_.avg_latency_ms);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"p95_latency_ms\":%.2f,", decode_metrics_.p95_latency_ms);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"p99_latency_ms\":%.2f,", decode_metrics_.p99_latency_ms);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"active_requests\":%llu,", decode_metrics_.active_requests);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"peak_concurrent\":%llu", decode_metrics_.peak_concurrent);
    pos += snprintf(json + pos, sizeof(json) - pos, "},");

    // System metrics
    pos += snprintf(json + pos, sizeof(json) - pos, "\"system\":{");
    pos += snprintf(json + pos, sizeof(json) - pos, "\"memory_used_mb\":%llu,", system_metrics_.memory_used_mb);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"memory_available_mb\":%llu,", system_metrics_.memory_available_mb);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"cpu_percent\":%.1f,", system_metrics_.cpu_percent);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"uptime_seconds\":%llu", system_metrics_.uptime_seconds);
    pos += snprintf(json + pos, sizeof(json) - pos, "},");

    // Epoch metrics
    pos += snprintf(json + pos, sizeof(json) - pos, "\"epoch\":{");
    pos += snprintf(json + pos, sizeof(json) - pos, "\"current_epoch\":%u,", epoch_metrics_.current_epoch);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"epoch_switches\":%llu,", epoch_metrics_.epoch_switches);
    pos += snprintf(json + pos, sizeof(json) - pos, "\"model_loaded\":%s,", epoch_metrics_.model_loaded ? "true" : "false");
    pos += snprintf(json + pos, sizeof(json) - pos, "\"model_id\":\"%s\"", epoch_metrics_.current_model_id.c_str());
    pos += snprintf(json + pos, sizeof(json) - pos, "}");

    pos += snprintf(json + pos, sizeof(json) - pos, "}");

    ReleaseMutex(metrics_mutex_);
    return std::string(json);
}

std::string ProductionMonitor::ExportHealthJSON() const {
    char json[512];
    snprintf(json, sizeof(json), 
        "{\"status\":\"%s\",\"healthy\":%s,\"timestamp\":%llu}",
        GetHealthStatus().c_str(),
        IsHealthy() ? "true" : "false",
        GetCurrentTimeMs());
    return std::string(json);
}

// ============================================================================
// Internal Helpers
// ============================================================================
void ProductionMonitor::CalculatePercentiles() {
    if (latency_history_.empty()) return;

    // Calculate average
    double sum = 0;
    for (double lat : latency_history_) {
        sum += lat;
    }
    decode_metrics_.avg_latency_ms = sum / latency_history_.size();

    // Sort for percentile calculation
    std::vector<double> sorted = latency_history_;
    std::sort(sorted.begin(), sorted.end());

    // P95
    size_t p95_idx = (size_t)(sorted.size() * 0.95);
    if (p95_idx < sorted.size()) {
        decode_metrics_.p95_latency_ms = sorted[p95_idx];
    }

    // P99
    size_t p99_idx = (size_t)(sorted.size() * 0.99);
    if (p99_idx < sorted.size()) {
        decode_metrics_.p99_latency_ms = sorted[p99_idx];
    }
}

uint64_t ProductionMonitor::GetCurrentTimeMs() const {
    return GetTickCount64();
}

// ============================================================================
// Graceful Shutdown Handler
// ============================================================================
GracefulShutdownHandler::ShutdownCallback GracefulShutdownHandler::callback_ = nullptr;
std::atomic<bool> GracefulShutdownHandler::shutdown_requested_(false);
HANDLE GracefulShutdownHandler::shutdown_event_ = NULL;

bool GracefulShutdownHandler::Install(ShutdownCallback callback) {
    callback_ = callback;
    shutdown_event_ = CreateEventA(NULL, TRUE, FALSE, NULL);
    
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        return false;
    }
    
    return true;
}

void GracefulShutdownHandler::TriggerShutdown() {
    shutdown_requested_.store(true);
    if (shutdown_event_) {
        SetEvent(shutdown_event_);
    }
    if (callback_) {
        callback_();
    }
}

bool GracefulShutdownHandler::IsShuttingDown() {
    return shutdown_requested_.load();
}

void GracefulShutdownHandler::WaitForShutdown() {
    if (shutdown_event_) {
        WaitForSingleObject(shutdown_event_, INFINITE);
    }
}

BOOL WINAPI GracefulShutdownHandler::ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        TriggerShutdown();
        return TRUE;
    }
    return FALSE;
}

// ============================================================================
// Performance Telemetry
// ============================================================================
std::vector<std::pair<std::string, PerformanceTelemetry::OperationStats>> PerformanceTelemetry::stats_;
CRITICAL_SECTION PerformanceTelemetry::cs_;
bool PerformanceTelemetry::initialized_ = false;

void PerformanceTelemetry::Record(const char* operation, uint64_t duration_ms) {
    if (!initialized_) {
        InitializeCriticalSection(&cs_);
        initialized_ = true;
    }

    EnterCriticalSection(&cs_);

    // Find or create stats entry
    auto it = std::find_if(stats_.begin(), stats_.end(),
        [operation](const auto& pair) { return pair.first == operation; });

    if (it == stats_.end()) {
        stats_.emplace_back(operation, OperationStats{});
        it = stats_.end() - 1;
    }

    OperationStats& stats = it->second;
    stats.count++;
    stats.total_ms += duration_ms;
    if (duration_ms < stats.min_ms) stats.min_ms = duration_ms;
    if (duration_ms > stats.max_ms) stats.max_ms = duration_ms;

    LeaveCriticalSection(&cs_);
}

std::string PerformanceTelemetry::GetReport() {
    if (!initialized_) return "{}";

    EnterCriticalSection(&cs_);

    char report[4096];
    int pos = 0;
    pos += snprintf(report + pos, sizeof(report) - pos, "{\"operations\":[");

    for (size_t i = 0; i < stats_.size(); i++) {
        const auto& [name, stats] = stats_[i];
        if (i > 0) pos += snprintf(report + pos, sizeof(report) - pos, ",");
        
        uint64_t avg_ms = stats.count > 0 ? stats.total_ms / stats.count : 0;
        pos += snprintf(report + pos, sizeof(report) - pos, 
            "{\"name\":\"%s\",\"count\":%llu,\"avg_ms\":%llu,\"min_ms\":%llu,\"max_ms\":%llu}",
            name.c_str(), stats.count, avg_ms, 
            stats.min_ms == UINT64_MAX ? 0 : stats.min_ms, stats.max_ms);
    }

    pos += snprintf(report + pos, sizeof(report) - pos, "]}");

    LeaveCriticalSection(&cs_);
    return std::string(report);
}

void PerformanceTelemetry::Reset() {
    if (!initialized_) return;
    
    EnterCriticalSection(&cs_);
    stats_.clear();
    LeaveCriticalSection(&cs_);
}

} // namespace Sovereign
