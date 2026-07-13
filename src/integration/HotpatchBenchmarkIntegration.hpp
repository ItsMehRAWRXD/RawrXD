// Phase G.1 Batch 3/5: Hotpatch MASM Benchmark Integration
// Zero-downtime kernel replacement with TPS improvement measurement
//
// This header provides C++ integration between the native x64 MASM hotpatch
// system and benchmark execution, enabling:
// - Atomic kernel replacement (2-5ms deployment)
// - Real-time TPS improvement measurement
// - Hotpatch safety validation
// - Rollback verification
//
// Dependencies: Phase G.1 Batch 1 (Stability), Batch 2 (Intelligent Ops)

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <memory>
#include <chrono>

// Forward declarations
namespace RawrXD {
    namespace Stability {
        class StabilityEnvelope;
    }
    namespace Intelligence {
        class AnomalyDetector;
        class PerformanceAnalytics;
    }
}

namespace RawrXD {
namespace Hotpatch {

// ============================================================================
// Type Definitions
// ============================================================================

/// Hotpatch operation result codes
enum class HotpatchResult : int32_t {
    SUCCESS = 0,
    ERROR_INVALID_PATCH = -1,
    ERROR_DEPLOYMENT_FAILED = -2,
    ERROR_ROLLBACK_FAILED = -3,
    ERROR_SAFETY_CHECK_FAILED = -4,
    ERROR_ATOMIC_SWAP_FAILED = -5,
    ERROR_VERSION_MISMATCH = -6,
    ERROR_ALREADY_PATCHED = -7,
    ERROR_NOT_PATCHED = -8,
    ERROR_TIMEOUT = -9
};

/// Kernel types that can be hotpatched
enum class KernelType : uint8_t {
    GEMM = 0,           // Matrix multiplication
    ATTENTION = 1,      // Self-attention
    RMSNORM = 2,        // RMS normalization
    SILU = 3,           // SiLU activation
    ROPE = 4,           // Rotary positional embedding
    SOFTMAX = 5,        // Softmax
    LAYERNORM = 6,      // Layer normalization
    EMBEDDING = 7,      // Token embedding
    COUNT = 8
};

/// Patch safety status
enum class SafetyStatus : uint8_t {
    UNKNOWN = 0,
    SAFE = 1,
    WARNING = 2,
    CRITICAL = 3,
    BLOCKED = 4
};

/// Deployment metrics
struct DeploymentMetrics {
    std::chrono::microseconds preparation_time;
    std::chrono::microseconds atomic_swap_time;
    std::chrono::microseconds validation_time;
    std::chrono::microseconds total_time;
    uint32_t bytes_patched;
    uint32_t pages_modified;
    bool zero_downtime_achieved;
};

/// Performance delta metrics
struct PerformanceDelta {
    double baseline_tps;
    double patched_tps;
    double tps_improvement_percent;
    double baseline_latency_us;
    double patched_latency_us;
    double latency_reduction_percent;
    double confidence_interval_95;
    bool statistically_significant;
};

/// Patch metadata
struct PatchMetadata {
    uint32_t patch_id;
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t version_patch;
    KernelType kernel_type;
    std::string name;
    std::string description;
    std::string author;
    std::string checksum;
    uint64_t timestamp;
    SafetyStatus safety_status;
    std::vector<std::string> dependencies;
    std::vector<std::string> conflicts;
};

/// Rollback point for recovery
struct RollbackPoint {
    uint32_t patch_id;
    uint64_t original_function_ptr;
    uint64_t backup_code_ptr;
    uint32_t backup_size;
    uint64_t timestamp;
    std::string original_version;
};

/// Hotpatch event for telemetry
struct HotpatchEvent {
    uint64_t timestamp;
    uint32_t patch_id;
    std::string event_type;  // "deploy_start", "deploy_complete", "rollback", "validation"
    HotpatchResult result;
    DeploymentMetrics metrics;
    std::string details;
};

// ============================================================================
// Hotpatch Manager
// ============================================================================

/// Manages hotpatch lifecycle and safety
class HotpatchManager {
public:
    HotpatchManager();
    ~HotpatchManager();

    // Non-copyable, non-movable
    HotpatchManager(const HotpatchManager&) = delete;
    HotpatchManager& operator=(const HotpatchManager&) = delete;
    HotpatchManager(HotpatchManager&&) = delete;
    HotpatchManager& operator=(HotpatchManager&&) = delete;

    /// Initialize hotpatch subsystem
    bool Initialize();

    /// Shutdown and cleanup
    void Shutdown();

    /// Apply a hotpatch to a kernel
    HotpatchResult ApplyPatch(
        const PatchMetadata& metadata,
        const void* patch_code,
        size_t patch_size,
        DeploymentMetrics* out_metrics = nullptr
    );

    /// Rollback to previous version
    HotpatchResult Rollback(uint32_t patch_id, DeploymentMetrics* out_metrics = nullptr);

    /// Rollback all patches for a kernel type
    HotpatchResult RollbackAll(KernelType kernel_type);

    /// Validate patch safety before deployment
    SafetyStatus ValidateSafety(const PatchMetadata& metadata);

    /// Check if a kernel is currently patched
    bool IsPatched(KernelType kernel_type) const;

    /// Get current patch version for a kernel
    bool GetCurrentVersion(KernelType kernel_type, PatchMetadata* out_metadata) const;

    /// Get rollback history
    std::vector<RollbackPoint> GetRollbackHistory() const;

    /// Get event log
    std::vector<HotpatchEvent> GetEventLog(uint32_t max_events = 100) const;

    /// Clear event log
    void ClearEventLog();

    /// Set safety threshold (0.0-1.0)
    void SetSafetyThreshold(double threshold);

    /// Get safety threshold
    double GetSafetyThreshold() const;

    /// Enable/disable automatic rollback on failure
    void SetAutoRollback(bool enabled);

    /// Check if auto-rollback is enabled
    bool IsAutoRollbackEnabled() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Benchmark Integration
// ============================================================================

/// Integrates hotpatch with benchmark execution
class HotpatchBenchmarkIntegration {
public:
    HotpatchBenchmarkIntegration();
    ~HotpatchBenchmarkIntegration();

    /// Initialize integration
    bool Initialize(
        RawrXD::Stability::StabilityEnvelope* stability = nullptr,
        RawrXD::Intelligence::AnomalyDetector* anomaly_detector = nullptr,
        RawrXD::Intelligence::PerformanceAnalytics* analytics = nullptr
    );

    /// Shutdown
    void Shutdown();

    /// Execute benchmark with hotpatch application
    struct BenchmarkConfig {
        KernelType kernel_type;
        uint32_t patch_count;
        uint32_t samples_per_patch;
        bool measure_overhead;
        bool verify_rollback;
        bool enable_telemetry;
        double tps_improvement_target_percent;
        double deployment_time_target_ms;
    };

    struct BenchmarkResults {
        PerformanceDelta performance_delta;
        std::vector<DeploymentMetrics> deployment_metrics;
        std::vector<HotpatchEvent> events;
        bool tps_target_met;
        bool deployment_time_target_met;
        bool rollback_verified;
        double overall_score;
    };

    bool RunBenchmark(const BenchmarkConfig& config, BenchmarkResults* out_results);

    /// Get baseline performance (pre-patch)
    bool MeasureBaseline(KernelType kernel_type, uint32_t sample_count, double* out_tps, double* out_latency);

    /// Measure performance with patch applied
    bool MeasurePatched(KernelType kernel_type, uint32_t patch_id, uint32_t sample_count, 
                        double* out_tps, double* out_latency);

    /// Calculate statistical significance
    bool CalculateSignificance(const std::vector<double>& baseline_samples,
                               const std::vector<double>& patched_samples,
                               double* out_p_value,
                               double* out_effect_size);

    /// Generate performance report
    std::string GenerateReport(const BenchmarkResults& results) const;

    /// Export results to JSON
    bool ExportToJson(const BenchmarkResults& results, const std::string& filepath) const;

    /// Set progress callback
    void SetProgressCallback(std::function<void(uint32_t current, uint32_t total, const std::string& phase)> callback);

    /// Get hotpatch manager
    HotpatchManager* GetManager() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Safety Validator
// ============================================================================

/// Validates hotpatch safety
class HotpatchSafetyValidator {
public:
    HotpatchSafetyValidator();
    ~HotpatchSafetyValidator();

    /// Validate patch against safety criteria
    SafetyStatus Validate(const PatchMetadata& metadata);

    /// Check code signature
    bool VerifySignature(const void* code, size_t size, const std::string& expected_checksum);

    /// Check for conflicts with existing patches
    bool CheckConflicts(const PatchMetadata& metadata, 
                        const std::vector<PatchMetadata>& active_patches);

    /// Validate memory safety
    bool ValidateMemorySafety(const void* patch_code, size_t patch_size);

    /// Check compatibility with current runtime
    bool CheckCompatibility(const PatchMetadata& metadata);

    /// Set validation strictness (0.0-1.0)
    void SetStrictness(double strictness);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert kernel type to string
const char* KernelTypeToString(KernelType type);

/// Convert string to kernel type
KernelType StringToKernelType(const std::string& str);

/// Convert result code to string
const char* HotpatchResultToString(HotpatchResult result);

/// Convert safety status to string
const char* SafetyStatusToString(SafetyStatus status);

/// Calculate TPS improvement percentage
double CalculateTpsImprovement(double baseline, double patched);

/// Calculate latency reduction percentage
double CalculateLatencyReduction(double baseline, double patched);

/// Check if improvement meets target
bool MeetsImprovementTarget(const PerformanceDelta& delta, double target_percent);

/// Format deployment metrics as string
std::string FormatDeploymentMetrics(const DeploymentMetrics& metrics);

// ============================================================================
// Constants
// ============================================================================

constexpr uint32_t MAX_PATCHES_PER_KERNEL = 256;
constexpr uint32_t MAX_ROLLBACK_HISTORY = 1024;
constexpr uint32_t MAX_EVENT_LOG_SIZE = 10000;
constexpr double DEFAULT_SAFETY_THRESHOLD = 0.95;
constexpr double DEFAULT_TPS_IMPROVEMENT_TARGET = 15.0;
constexpr double DEFAULT_DEPLOYMENT_TIME_TARGET_MS = 5.0;
constexpr uint32_t MIN_SAMPLES_FOR_SIGNIFICANCE = 30;

} // namespace Hotpatch
} // namespace RawrXD