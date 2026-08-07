// ============================================================================
// RawrXD Validation Framework - Common Types and Structures
// ============================================================================

#ifndef RAWRXD_VALIDATION_TYPES_HPP
#define RAWRXD_VALIDATION_TYPES_HPP

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Validation Status Codes
// ============================================================================
enum class ValidationStatus {
    NOT_STARTED,
    IN_PROGRESS,
    PASSED,
    FAILED,
    ERROR,
    SKIPPED
};

// ============================================================================
// Performance Targets (Production Certification)
// ============================================================================
struct PerformanceTargets {
    // Boot sequence
    static constexpr int MAX_BOOT_TIME_MS = 5000;
    
    // Inference performance
    static constexpr double MIN_TPS = 100.0;
    static constexpr double MAX_LATENCY_MS = 5000.0;
    static constexpr double MAX_TTFT_MS = 250.0;
    
    // Reliability
    static constexpr double MIN_SUCCESS_RATE = 0.95;  // 95%
    
    // Resource utilization
    static constexpr double MAX_GPU_TEMP_C = 85.0;
    static constexpr double MAX_GPU_UTILIZATION = 95.0;
};

// ============================================================================
// GPU Information
// ============================================================================
struct GPUInfo {
    std::string name;
    std::string deviceId;
    std::string driverVersion;
    
    uint64_t vramTotalBytes;
    uint64_t vramUsedBytes;
    uint64_t vramFreeBytes;
    
    float utilizationPercent;
    float memoryUtilizationPercent;
    float temperatureC;
    float powerDrawWatts;
    
    uint32_t coreClockMHz;
    uint32_t memoryClockMHz;
    
    bool isR9700;
    bool isRX7800XT;
    bool isPrimary;
    bool isAvailable;
};

// ============================================================================
// Inference Metrics
// ============================================================================
struct InferenceMetrics {
    std::string requestId;
    std::string modelName;
    std::string gpuAssignment;
    
    uint32_t promptTokens;
    uint32_t generatedTokens;
    uint32_t totalTokens;
    
    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point firstTokenTime;
    std::chrono::system_clock::time_point endTime;
    
    double ttftMs;           // Time to first token
    double totalLatencyMs;   // Total request latency
    double tps;              // Tokens per second
    
    bool success;
    std::string errorMessage;
};

// ============================================================================
// Boot Phase Timing
// ============================================================================
struct BootPhase {
    std::string name;
    std::string status;
    int64_t elapsedMs;
    std::chrono::system_clock::time_point timestamp;
};

struct BootMetrics {
    std::vector<BootPhase> phases;
    int64_t totalBootTimeMs;
    bool passed;
    std::string errorMessage;
};

// ============================================================================
// Gateway Endpoint Results
// ============================================================================
struct EndpointResult {
    std::string endpoint;
    bool passed;
    int64_t latencyMs;
    std::string response;
    std::string errorMessage;
};

struct GatewayValidation {
    EndpointResult health;
    EndpointResult inference;
    EndpointResult streaming;
    bool allPassed;
};

// ============================================================================
// Validation Report
// ============================================================================
struct ValidationReport {
    std::string validationId;
    std::string timestamp;
    std::string targetUrl;
    
    // Overall status
    ValidationStatus status;
    bool passed;
    
    // Component results
    BootMetrics boot;
    GatewayValidation gateway;
    std::vector<InferenceMetrics> inferenceRuns;
    std::vector<GPUInfo> gpuInfo;
    
    // Statistics
    double avgTps;
    double minTps;
    double maxTps;
    double avgLatencyMs;
    double avgTtftMs;
    double successRate;
    
    // Certification
    bool bootCertified;
    bool tpsCertified;
    bool latencyCertified;
    bool ttftCertified;
    bool multiGpuCertified;
    
    std::vector<std::string> artifactsGenerated;
};

// ============================================================================
// Utility Functions
// ============================================================================
inline std::string StatusToString(ValidationStatus status) {
    switch (status) {
        case ValidationStatus::NOT_STARTED: return "NOT_STARTED";
        case ValidationStatus::IN_PROGRESS: return "IN_PROGRESS";
        case ValidationStatus::PASSED: return "PASSED";
        case ValidationStatus::FAILED: return "FAILED";
        case ValidationStatus::ERROR: return "ERROR";
        case ValidationStatus::SKIPPED: return "SKIPPED";
        default: return "UNKNOWN";
    }
}

inline bool IsCertified(const InferenceMetrics& metrics) {
    return metrics.tps >= PerformanceTargets::MIN_TPS &&
           metrics.totalLatencyMs < PerformanceTargets::MAX_LATENCY_MS &&
           metrics.ttftMs < PerformanceTargets::MAX_TTFT_MS;
}

} // namespace Validation
} // namespace RawrXD

#endif // RAWRXD_VALIDATION_TYPES_HPP
