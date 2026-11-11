/**
 * SEGHistoricalPerformanceStore.hpp
 * 
 * Phase C.0 Batch 3/5: Historical Performance Store
 * 
 * SQLite-backed persistent storage for performance metrics:
 * - Execution history with temporal indexing
 * - Component trend analysis
 * - Regression detection
 * - Performance prediction for scheduler
 * 
 * Enables adaptive scheduling with historical intelligence
 */

#pragma once

#include "SEGPerformanceBridge.hpp"
#include "SEGRuntimeCostProfiler.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <optional>

// Forward declaration for SQLite
struct sqlite3;
struct sqlite3_stmt;

namespace Sovereign {
namespace SEG {

/**
 * Performance record for database storage
 */
struct PerformanceRecord {
    int64_t id{0};                    // Database ID
    std::string executionId;          // Execution identifier
    std::string component;            // Component name
    std::string operation;            // Operation type
    std::string componentType;        // Component type (EngineCycle, SwarmTask, etc.)
    
    int64_t timestamp{0};             // Unix timestamp (ms)
    
    // Performance metrics
    double durationMs{0.0};           // Execution duration
    double throughputTps{0.0};        // Throughput in tokens/sec
    double convergenceScore{0.0};     // Convergence metric (0-1)
    double convergenceGain{0.0};      // Convergence improvement
    
    // Resource metrics
    size_t memoryBytes{0};            // Memory usage
    int cpuCoresUsed{0};              // CPU cores
    double cpuUtilization{0.0};       // CPU utilization (0-1)
    
    // Status
    bool success{false};              // Execution success
    std::string errorMessage;         // Error if failed
    int retryCount{0};                // Retry attempts
    
    // Context
    int batchNumber{0};               // Batch number (243-256)
    std::string cycleName;            // Cycle name if applicable
    std::string taskCategory;         // Task category if applicable
    
    PerformanceRecord() = default;
    
    // Convert to/from JSON
    std::string ToJson() const;
    static std::optional<PerformanceRecord> FromJson(const std::string& json);
};

/**
 * Component trend analysis result
 */
struct ComponentTrend {
    std::string component;
    std::string componentType;
    int sampleCount{0};
    
    // Timing statistics
    double avgDurationMs{0.0};
    double minDurationMs{0.0};
    double maxDurationMs{0.0};
    double p95DurationMs{0.0};
    double p99DurationMs{0.0};
    double stdDevDurationMs{0.0};
    
    // Throughput statistics
    double avgThroughputTps{0.0};
    double p95ThroughputTps{0.0};
    
    // Convergence statistics
    double avgConvergenceScore{0.0};
    double avgConvergenceGain{0.0};
    
    // Success rate
    double successRate{0.0};
    int successCount{0};
    int failureCount{0};
    
    // Trend direction
    enum class TrendDirection {
        Improving,
        Stable,
        Degrading,
        Unknown
    };
    TrendDirection trend{TrendDirection::Unknown};
    double trendSlope{0.0};           // Linear regression slope
    
    // Time range
    int64_t earliestTimestamp{0};
    int64_t latestTimestamp{0};
    
    std::string ToJson() const;
};

/**
 * Regression event
 */
struct RegressionEvent {
    std::string component;
    std::string componentType;
    int64_t detectedAt{0};
    
    double previousAverageMs{0.0};
    double currentAverageMs{0.0};
    double degradationPercent{0.0};
    
    enum class Severity {
        None,
        Warning,      // 10-25%
        High,         // 25-50%
        Critical      // >50%
    };
    Severity severity{Severity::None};
    
    std::string ToJson() const;
    std::string GetSeverityString() const;
};

/**
 * Performance prediction for scheduler
 */
struct PerformancePrediction {
    std::string component;
    std::string componentType;
    
    double expectedDurationMs{0.0};
    double confidence{0.0};            // 0-1 based on sample count
    int historicalSamples{0};
    
    // Prediction intervals
    double minExpectedMs{0.0};         // P10
    double maxExpectedMs{0.0};         // P90
    
    // Risk assessment
    double failureProbability{0.0};   // Based on historical rate
    double regressionProbability{0.0};  // Based on recent trend
    
    std::string ToJson() const;
};

/**
 * Query filters for historical data
 */
struct HistoryQuery {
    std::optional<std::string> componentFilter;
    std::optional<std::string> componentTypeFilter;
    std::optional<std::string> operationFilter;
    std::optional<int> batchNumberFilter;
    std::optional<bool> successFilter;
    
    int64_t startTime{0};              // Inclusive
    int64_t endTime{0};                // Inclusive (0 = now)
    int limit{100};                    // Max records
    int offset{0};                     // For pagination
    
    std::string ToSqlWhere() const;
};

/**
 * Historical Performance Store
 * 
 * SQLite-backed persistent storage for performance analysis
 */
class SEGHistoricalPerformanceStore {
public:
    SEGHistoricalPerformanceStore();
    ~SEGHistoricalPerformanceStore();
    
    // Lifecycle
    bool Initialize(const std::string& dbPath = "seg_performance.db");
    void Shutdown();
    bool IsInitialized() const { return db_ != nullptr; }
    
    // Configuration
    void SetMaxRecordsPerComponent(size_t max);
    void SetRetentionDays(int days);
    void EnableAutoPruning(bool enable);
    
    // Record storage
    bool StoreRecord(const PerformanceRecord& record);
    bool StoreRecords(const std::vector<PerformanceRecord>& records);
    
    // Retrieval
    std::vector<PerformanceRecord> QueryRecords(const HistoryQuery& query) const;
    std::optional<PerformanceRecord> GetRecordById(int64_t id) const;
    
    // Component analysis
    ComponentTrend GetComponentTrend(
        const std::string& component, 
        int sampleCount = 100
    ) const;
    
    std::vector<ComponentTrend> GetAllComponentTrends(int sampleCount = 100) const;
    
    // Regression detection
    std::vector<RegressionEvent> DetectRegressions(
        const std::string& component,
        int lookbackSamples = 10
    ) const;
    
    std::vector<RegressionEvent> DetectAllRegressions() const;
    
    // Performance prediction
    PerformancePrediction PredictPerformance(
        const std::string& component,
        const std::map<std::string, std::string>& context = {}
    ) const;
    
    // Maintenance
    bool PruneOldRecords(int retentionDays);
    bool PruneByComponentLimit(size_t maxPerComponent);
    size_t GetTotalRecordCount() const;
    size_t GetComponentRecordCount(const std::string& component) const;
    
    // Export
    std::string ExportToJson(const HistoryQuery& query) const;
    bool ExportToFile(const std::string& filepath, const HistoryQuery& query) const;
    
    // Statistics
    std::map<std::string, size_t> GetComponentCounts() const;
    std::map<std::string, double> GetAverageDurationsByComponent() const;
    
    // Scheduler integration
    std::vector<PerformancePrediction> GetPredictionsForExecutionPlan(
        const std::vector<std::string>& components
    ) const;
    
private:
    mutable std::mutex mutex_;
    sqlite3* db_{nullptr};
    
    // Configuration
    size_t maxRecordsPerComponent_{10000};
    int retentionDays_{30};
    bool autoPruningEnabled_{true};
    
    // Schema management
    bool CreateSchema();
    bool CreateIndexes();
    
    // SQL helpers
    bool ExecuteSql(const std::string& sql);
    bool PrepareStatement(const std::string& sql, sqlite3_stmt** stmt);
    PerformanceRecord RowToRecord(sqlite3_stmt* stmt) const;
    
    // Trend calculation
    ComponentTrend::TrendDirection CalculateTrendDirection(
        const std::vector<PerformanceRecord>& records
    ) const;
    double CalculateTrendSlope(const std::vector<PerformanceRecord>& records) const;
    double CalculatePercentile(const std::vector<double>& values, double percentile) const;
    double CalculateStdDev(const std::vector<double>& values, double mean) const;
    
    // Pruning
    void MaybePrune();
};

/**
 * Quick validation
 */
bool ValidateHistoricalPerformanceStore();

/**
 * Export store statistics
 */
std::string ExportStoreStatistics(const SEGHistoricalPerformanceStore& store);

} // namespace SEG
} // namespace Sovereign
