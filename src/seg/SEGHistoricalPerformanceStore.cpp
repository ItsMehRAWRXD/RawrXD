/**
 * SEGHistoricalPerformanceStore.cpp
 * 
 * Phase C.0 Batch 3/5: Historical Performance Store Implementation
 */

#include "SEGHistoricalPerformanceStore.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <chrono>
#include <cmath>
#include <cstdio>

// SQLite stub for Phase C.0 Batch 3/5 testing
// In production, link against sqlite3.lib
#include "sqlite3_stub.h"

namespace Sovereign {
namespace SEG {

// ============================================================================
// PerformanceRecord Implementation
// ============================================================================

std::string PerformanceRecord::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"id\": " << id << ",\n";
    json << "  \"execution_id\": \"" << executionId << "\",\n";
    json << "  \"component\": \"" << component << "\",\n";
    json << "  \"operation\": \"" << operation << "\",\n";
    json << "  \"component_type\": \"" << componentType << "\",\n";
    json << "  \"timestamp\": " << timestamp << ",\n";
    json << "  \"duration_ms\": " << durationMs << ",\n";
    json << "  \"throughput_tps\": " << throughputTps << ",\n";
    json << "  \"convergence_score\": " << convergenceScore << ",\n";
    json << "  \"convergence_gain\": " << convergenceGain << ",\n";
    json << "  \"memory_bytes\": " << memoryBytes << ",\n";
    json << "  \"cpu_cores_used\": " << cpuCoresUsed << ",\n";
    json << "  \"cpu_utilization\": " << cpuUtilization << ",\n";
    json << "  \"success\": " << (success ? "true" : "false") << ",\n";
    json << "  \"error_message\": \"" << errorMessage << "\",\n";
    json << "  \"retry_count\": " << retryCount << ",\n";
    json << "  \"batch_number\": " << batchNumber << ",\n";
    json << "  \"cycle_name\": \"" << cycleName << "\",\n";
    json << "  \"task_category\": \"" << taskCategory << "\"\n";
    json << "}\n";
    return json.str();
}

// ============================================================================
// ComponentTrend Implementation
// ============================================================================

std::string ComponentTrend::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"component\": \"" << component << "\",\n";
    json << "  \"component_type\": \"" << componentType << "\",\n";
    json << "  \"sample_count\": " << sampleCount << ",\n";
    json << "  \"avg_duration_ms\": " << avgDurationMs << ",\n";
    json << "  \"min_duration_ms\": " << minDurationMs << ",\n";
    json << "  \"max_duration_ms\": " << maxDurationMs << ",\n";
    json << "  \"p95_duration_ms\": " << p95DurationMs << ",\n";
    json << "  \"p99_duration_ms\": " << p99DurationMs << ",\n";
    json << "  \"std_dev_duration_ms\": " << stdDevDurationMs << ",\n";
    json << "  \"avg_throughput_tps\": " << avgThroughputTps << ",\n";
    json << "  \"p95_throughput_tps\": " << p95ThroughputTps << ",\n";
    json << "  \"avg_convergence_score\": " << avgConvergenceScore << ",\n";
    json << "  \"avg_convergence_gain\": " << avgConvergenceGain << ",\n";
    json << "  \"success_rate\": " << successRate << ",\n";
    json << "  \"success_count\": " << successCount << ",\n";
    json << "  \"failure_count\": " << failureCount << ",\n";
    json << "  \"trend\": \"";
    switch (trend) {
        case TrendDirection::Improving: json << "improving"; break;
        case TrendDirection::Stable: json << "stable"; break;
        case TrendDirection::Degrading: json << "degrading"; break;
        default: json << "unknown"; break;
    }
    json << "\",\n";
    json << "  \"trend_slope\": " << trendSlope << ",\n";
    json << "  \"earliest_timestamp\": " << earliestTimestamp << ",\n";
    json << "  \"latest_timestamp\": " << latestTimestamp << "\n";
    json << "}\n";
    return json.str();
}

// ============================================================================
// RegressionEvent Implementation
// ============================================================================

std::string RegressionEvent::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"component\": \"" << component << "\",\n";
    json << "  \"component_type\": \"" << componentType << "\",\n";
    json << "  \"detected_at\": " << detectedAt << ",\n";
    json << "  \"previous_average_ms\": " << previousAverageMs << ",\n";
    json << "  \"current_average_ms\": " << currentAverageMs << ",\n";
    json << "  \"degradation_percent\": " << degradationPercent << ",\n";
    json << "  \"severity\": \"" << GetSeverityString() << "\"\n";
    json << "}\n";
    return json.str();
}

std::string RegressionEvent::GetSeverityString() const {
    switch (severity) {
        case Severity::Warning: return "WARNING";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
        default: return "NONE";
    }
}

// ============================================================================
// PerformancePrediction Implementation
// ============================================================================

std::string PerformancePrediction::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"component\": \"" << component << "\",\n";
    json << "  \"component_type\": \"" << componentType << "\",\n";
    json << "  \"expected_duration_ms\": " << expectedDurationMs << ",\n";
    json << "  \"confidence\": " << confidence << ",\n";
    json << "  \"historical_samples\": " << historicalSamples << ",\n";
    json << "  \"min_expected_ms\": " << minExpectedMs << ",\n";
    json << "  \"max_expected_ms\": " << maxExpectedMs << ",\n";
    json << "  \"failure_probability\": " << failureProbability << ",\n";
    json << "  \"regression_probability\": " << regressionProbability << "\n";
    json << "}\n";
    return json.str();
}

// ============================================================================
// HistoryQuery Implementation
// ============================================================================

std::string HistoryQuery::ToSqlWhere() const {
    std::vector<std::string> conditions;
    
    if (componentFilter) {
        conditions.push_back("component = '" + *componentFilter + "'");
    }
    if (componentTypeFilter) {
        conditions.push_back("component_type = '" + *componentTypeFilter + "'");
    }
    if (operationFilter) {
        conditions.push_back("operation = '" + *operationFilter + "'");
    }
    if (batchNumberFilter) {
        conditions.push_back("batch_number = " + std::to_string(*batchNumberFilter));
    }
    if (successFilter) {
        conditions.push_back("success = " + std::to_string(*successFilter ? 1 : 0));
    }
    if (startTime > 0) {
        conditions.push_back("timestamp >= " + std::to_string(startTime));
    }
    if (endTime > 0) {
        conditions.push_back("timestamp <= " + std::to_string(endTime));
    }
    
    if (conditions.empty()) {
        return "";
    }
    
    std::string result = "WHERE ";
    for (size_t i = 0; i < conditions.size(); ++i) {
        if (i > 0) result += " AND ";
        result += conditions[i];
    }
    return result;
}

// ============================================================================
// SEGHistoricalPerformanceStore Implementation
// ============================================================================

SEGHistoricalPerformanceStore::SEGHistoricalPerformanceStore() = default;

SEGHistoricalPerformanceStore::~SEGHistoricalPerformanceStore() {
    Shutdown();
}

bool SEGHistoricalPerformanceStore::Initialize(const std::string& dbPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (db_) {
        return true; // Already initialized
    }
    
    int rc = sqlite3_open(dbPath.c_str(), &db_);
    if (rc != SQLITE_OK) {
        db_ = nullptr;
        return false;
    }
    
    // Enable WAL mode for better concurrency
    ExecuteSql("PRAGMA journal_mode=WAL;");
    ExecuteSql("PRAGMA synchronous=NORMAL;");
    
    if (!CreateSchema()) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    if (!CreateIndexes()) {
        sqlite3_close(db_);
        db_ = nullptr;
        return false;
    }
    
    return true;
}

void SEGHistoricalPerformanceStore::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void SEGHistoricalPerformanceStore::SetMaxRecordsPerComponent(size_t max) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxRecordsPerComponent_ = max;
}

void SEGHistoricalPerformanceStore::SetRetentionDays(int days) {
    std::lock_guard<std::mutex> lock(mutex_);
    retentionDays_ = days;
}

void SEGHistoricalPerformanceStore::EnableAutoPruning(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);
    autoPruningEnabled_ = enable;
}

// ============================================================================
// Schema Management
// ============================================================================

bool SEGHistoricalPerformanceStore::CreateSchema() {
    const char* createTableSql = R"(
        CREATE TABLE IF NOT EXISTS execution_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id TEXT NOT NULL,
            component TEXT NOT NULL,
            operation TEXT,
            component_type TEXT,
            timestamp INTEGER NOT NULL,
            duration_ms REAL NOT NULL,
            throughput_tps REAL,
            convergence_score REAL,
            convergence_gain REAL,
            memory_bytes INTEGER,
            cpu_cores_used INTEGER,
            cpu_utilization REAL,
            success INTEGER NOT NULL,
            error_message TEXT,
            retry_count INTEGER DEFAULT 0,
            batch_number INTEGER,
            cycle_name TEXT,
            task_category TEXT
        );
    )";
    
    return ExecuteSql(createTableSql);
}

bool SEGHistoricalPerformanceStore::CreateIndexes() {
    bool success = true;
    
    success &= ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_component_time ON execution_history(component, timestamp);"
    );
    
    success &= ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_component_type ON execution_history(component_type);"
    );
    
    success &= ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_success ON execution_history(success);"
    );
    
    success &= ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_batch ON execution_history(batch_number);"
    );
    
    success &= ExecuteSql(
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON execution_history(timestamp);"
    );
    
    return success;
}

// ============================================================================
// Record Storage
// ============================================================================

bool SEGHistoricalPerformanceStore::StoreRecord(const PerformanceRecord& record) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!db_) return false;
    
    const char* insertSql = R"(
        INSERT INTO execution_history (
            execution_id, component, operation, component_type, timestamp,
            duration_ms, throughput_tps, convergence_score, convergence_gain,
            memory_bytes, cpu_cores_used, cpu_utilization, success,
            error_message, retry_count, batch_number, cycle_name, task_category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, insertSql, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    // Bind parameters
    sqlite3_bind_text(stmt, 1, record.executionId.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, record.component.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, record.operation.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, record.componentType.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, record.timestamp);
    sqlite3_bind_double(stmt, 6, record.durationMs);
    sqlite3_bind_double(stmt, 7, record.throughputTps);
    sqlite3_bind_double(stmt, 8, record.convergenceScore);
    sqlite3_bind_double(stmt, 9, record.convergenceGain);
    sqlite3_bind_int64(stmt, 10, static_cast<sqlite3_int64>(record.memoryBytes));
    sqlite3_bind_int(stmt, 11, record.cpuCoresUsed);
    sqlite3_bind_double(stmt, 12, record.cpuUtilization);
    sqlite3_bind_int(stmt, 13, record.success ? 1 : 0);
    sqlite3_bind_text(stmt, 14, record.errorMessage.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 15, record.retryCount);
    sqlite3_bind_int(stmt, 16, record.batchNumber);
    sqlite3_bind_text(stmt, 17, record.cycleName.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 18, record.taskCategory.c_str(), -1, SQLITE_STATIC);
    
    int stepResult = sqlite3_step(stmt);
    fprintf(stderr, "[STORE] sqlite3_step returned %d\n", stepResult);
    bool success = (stepResult == SQLITE_DONE);
    fprintf(stderr, "[STORE] success=%d\n", success);
    sqlite3_finalize(stmt);
    fprintf(stderr, "[STORE] finalize done\n");
    
    if (success && autoPruningEnabled_) {
        MaybePrune();
    }
    
    fprintf(stderr, "[STORE] returning %d\n", success);
    if (success && autoPruningEnabled_) {
        MaybePrune();
    }
    
    fprintf(stderr, "[STORE] returning %d\n", success);
    if (success && autoPruningEnabled_) {
        MaybePrune();
    }
    
    fprintf(stderr, "[STORE] returning %d\n", success);
    if (success && autoPruningEnabled_) {
        MaybePrune();
    }
    
    fprintf(stderr, "[STORE] returning %d\n", success);
    return success;
}

bool SEGHistoricalPerformanceStore::StoreRecords(const std::vector<PerformanceRecord>& records) {
    if (!db_) return false;
    
    // Begin transaction
    ExecuteSql("BEGIN TRANSACTION;");
    
    bool allSuccess = true;
    for (const auto& record : records) {
        if (!StoreRecord(record)) {
            allSuccess = false;
            break;
        }
    }
    
    if (allSuccess) {
        ExecuteSql("COMMIT;");
    } else {
        ExecuteSql("ROLLBACK;");
    }
    
    return allSuccess;
}

// ============================================================================
// Retrieval
// ============================================================================

std::vector<PerformanceRecord> SEGHistoricalPerformanceStore::QueryRecords(
    const HistoryQuery& query
) const {
    fprintf(stderr, "[STORE] QueryRecords ENTER\n"); fflush(stderr);
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PerformanceRecord> results;
    
    if (!db_) {
        fprintf(stderr, "[STORE] QueryRecords: db_ is null\n"); fflush(stderr);
        return results;
    }
    
    std::string sql = "SELECT * FROM execution_history " + query.ToSqlWhere() +
                      " ORDER BY timestamp DESC LIMIT " + std::to_string(query.limit) +
                      " OFFSET " + std::to_string(query.offset) + ";";
    
    fprintf(stderr, "[STORE] QueryRecords SQL: %s\n", sql.c_str()); fflush(stderr);
    
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    fprintf(stderr, "[STORE] prepare_v2 returned %d\n", rc); fflush(stderr);
    if (rc != SQLITE_OK) {
        return results;
    }
    
    fprintf(stderr, "[STORE] About to call sqlite3_step\n"); fflush(stderr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(RowToRecord(stmt));
    }
    
    sqlite3_finalize(stmt);
    return results;
}

std::optional<PerformanceRecord> SEGHistoricalPerformanceStore::GetRecordById(int64_t id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!db_) return std::nullopt;
    
    std::string sql = "SELECT * FROM execution_history WHERE id = ?;";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    
    sqlite3_bind_int64(stmt, 1, id);
    
    PerformanceRecord record;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        record = RowToRecord(stmt);
    } else {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }
    
    sqlite3_finalize(stmt);
    return record;
}

// ============================================================================
// Component Analysis
// ============================================================================

ComponentTrend SEGHistoricalPerformanceStore::GetComponentTrend(
    const std::string& component,
    int sampleCount
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    ComponentTrend trend;
    trend.component = component;
    
    if (!db_) return trend;
    
    // Query recent samples for this component
    std::string sql = 
        "SELECT * FROM execution_history WHERE component = ? "
        "ORDER BY timestamp DESC LIMIT ?;";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return trend;
    }
    
    sqlite3_bind_text(stmt, 1, component.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, sampleCount);
    
    std::vector<PerformanceRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        records.push_back(RowToRecord(stmt));
    }
    sqlite3_finalize(stmt);
    
    if (records.empty()) {
        return trend;
    }
    
    // Calculate statistics
    trend.sampleCount = static_cast<int>(records.size());
    trend.componentType = records[0].componentType;
    trend.earliestTimestamp = records.back().timestamp;
    trend.latestTimestamp = records[0].timestamp;
    
    std::vector<double> durations;
    std::vector<double> throughputs;
    std::vector<double> convergenceScores;
    std::vector<double> convergenceGains;
    
    int successCount = 0;
    for (const auto& r : records) {
        durations.push_back(r.durationMs);
        throughputs.push_back(r.throughputTps);
        convergenceScores.push_back(r.convergenceScore);
        convergenceGains.push_back(r.convergenceGain);
        if (r.success) successCount++;
    }
    
    // Timing statistics
    trend.avgDurationMs = std::accumulate(durations.begin(), durations.end(), 0.0) / durations.size();
    trend.minDurationMs = *std::min_element(durations.begin(), durations.end());
    trend.maxDurationMs = *std::max_element(durations.begin(), durations.end());
    trend.p95DurationMs = CalculatePercentile(durations, 0.95);
    trend.p99DurationMs = CalculatePercentile(durations, 0.99);
    trend.stdDevDurationMs = CalculateStdDev(durations, trend.avgDurationMs);
    
    // Throughput statistics
    trend.avgThroughputTps = std::accumulate(throughputs.begin(), throughputs.end(), 0.0) / throughputs.size();
    trend.p95ThroughputTps = CalculatePercentile(throughputs, 0.95);
    
    // Convergence statistics
    trend.avgConvergenceScore = std::accumulate(convergenceScores.begin(), convergenceScores.end(), 0.0) / convergenceScores.size();
    trend.avgConvergenceGain = std::accumulate(convergenceGains.begin(), convergenceGains.end(), 0.0) / convergenceGains.size();
    
    // Success rate
    trend.successCount = successCount;
    trend.failureCount = trend.sampleCount - successCount;
    trend.successRate = static_cast<double>(successCount) / trend.sampleCount;
    
    // Trend direction
    trend.trend = CalculateTrendDirection(records);
    trend.trendSlope = CalculateTrendSlope(records);
    
    return trend;
}

std::vector<ComponentTrend> SEGHistoricalPerformanceStore::GetAllComponentTrends(
    int sampleCount
) const {
    std::vector<ComponentTrend> trends;
    
    // Get all unique components
    std::vector<std::string> components;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!db_) return trends;
        
        const char* sql = "SELECT DISTINCT component FROM execution_history;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                components.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Get trend for each component
    for (const auto& component : components) {
        trends.push_back(GetComponentTrend(component, sampleCount));
    }
    
    return trends;
}

// ============================================================================
// Regression Detection
// ============================================================================

std::vector<RegressionEvent> SEGHistoricalPerformanceStore::DetectRegressions(
    const std::string& component,
    int lookbackSamples
) const {
    std::vector<RegressionEvent> events;
    
    // Get trend which includes slope calculation
    auto trend = GetComponentTrend(component, lookbackSamples * 2);
    
    if (trend.sampleCount < lookbackSamples * 2) {
        return events; // Not enough data
    }
    
    // Check if degrading
    if (trend.trend == ComponentTrend::TrendDirection::Degrading) {
        RegressionEvent event;
        event.component = component;
        event.componentType = trend.componentType;
        event.detectedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        // Calculate degradation
        // Simplified: use trend slope to estimate degradation
        double slopePercent = std::abs(trend.trendSlope) * 100.0;
        event.degradationPercent = slopePercent;
        
        // Determine severity
        if (slopePercent > 50.0) {
            event.severity = RegressionEvent::Severity::Critical;
        } else if (slopePercent > 25.0) {
            event.severity = RegressionEvent::Severity::High;
        } else if (slopePercent > 10.0) {
            event.severity = RegressionEvent::Severity::Warning;
        } else {
            event.severity = RegressionEvent::Severity::None;
        }
        
        event.previousAverageMs = trend.avgDurationMs * (1.0 - trend.trendSlope);
        event.currentAverageMs = trend.avgDurationMs;
        
        if (event.severity != RegressionEvent::Severity::None) {
            events.push_back(event);
        }
    }
    
    return events;
}

std::vector<RegressionEvent> SEGHistoricalPerformanceStore::DetectAllRegressions() const {
    std::vector<RegressionEvent> allEvents;
    
    // Get all components
    std::vector<std::string> components;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!db_) return allEvents;
        
        const char* sql = "SELECT DISTINCT component FROM execution_history;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                components.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            }
            sqlite3_finalize(stmt);
        }
    }
    
    // Detect regressions for each component
    for (const auto& component : components) {
        auto events = DetectRegressions(component, 10);
        allEvents.insert(allEvents.end(), events.begin(), events.end());
    }
    
    return allEvents;
}

// ============================================================================
// Performance Prediction
// ============================================================================

PerformancePrediction SEGHistoricalPerformanceStore::PredictPerformance(
    const std::string& component,
    const std::map<std::string, std::string>& context
) const {
    (void)context; // Context not used in basic implementation
    
    PerformancePrediction prediction;
    prediction.component = component;
    
    // Get component trend
    auto trend = GetComponentTrend(component, 100);
    
    if (trend.sampleCount == 0) {
        return prediction; // No data
    }
    
    prediction.componentType = trend.componentType;
    prediction.expectedDurationMs = trend.avgDurationMs;
    prediction.historicalSamples = trend.sampleCount;
    prediction.confidence = std::min(1.0, std::sqrt(trend.sampleCount) / 10.0); // Confidence increases with samples
    
    // Prediction intervals (P10-P90)
    prediction.minExpectedMs = trend.avgDurationMs - 1.28 * trend.stdDevDurationMs; // ~P10
    prediction.maxExpectedMs = trend.avgDurationMs + 1.28 * trend.stdDevDurationMs; // ~P90
    if (prediction.minExpectedMs < 0) prediction.minExpectedMs = 0;
    
    // Risk assessment
    prediction.failureProbability = 1.0 - trend.successRate;
    prediction.regressionProbability = (trend.trend == ComponentTrend::TrendDirection::Degrading) ? 0.5 : 0.1;
    
    return prediction;
}

std::vector<PerformancePrediction> SEGHistoricalPerformanceStore::GetPredictionsForExecutionPlan(
    const std::vector<std::string>& components
) const {
    std::vector<PerformancePrediction> predictions;
    
    for (const auto& component : components) {
        predictions.push_back(PredictPerformance(component));
    }
    
    return predictions;
}

// ============================================================================
// Maintenance
// ============================================================================

bool SEGHistoricalPerformanceStore::PruneOldRecords(int retentionDays) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!db_) return false;
    
    auto now = std::chrono::steady_clock::now();
    auto cutoff = now - std::chrono::hours(24 * retentionDays);
    int64_t cutoffMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        cutoff.time_since_epoch()).count();
    
    std::string sql = "DELETE FROM execution_history WHERE timestamp < ?;";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int64(stmt, 1, cutoffMs);
    
    bool success = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return success;
}

bool SEGHistoricalPerformanceStore::PruneByComponentLimit(size_t maxPerComponent) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!db_) return false;
    
    // Get all components
    std::vector<std::string> components;
    const char* sql = "SELECT DISTINCT component FROM execution_history;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            components.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        }
        sqlite3_finalize(stmt);
    }
    
    // Prune each component
    for (const auto& component : components) {
        std::string pruneSql = 
            "DELETE FROM execution_history WHERE id IN ("
            "SELECT id FROM execution_history WHERE component = ? "
            "ORDER BY timestamp DESC LIMIT -1 OFFSET ?);";
        
        sqlite3_stmt* pruneStmt = nullptr;
        if (sqlite3_prepare_v2(db_, pruneSql.c_str(), -1, &pruneStmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(pruneStmt, 1, component.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_int64(pruneStmt, 2, static_cast<sqlite3_int64>(maxPerComponent));
            sqlite3_step(pruneStmt);
            sqlite3_finalize(pruneStmt);
        }
    }
    
    return true;
}

size_t SEGHistoricalPerformanceStore::GetTotalRecordCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!db_) return 0;
    
    const char* sql = "SELECT COUNT(*) FROM execution_history;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return count;
}

size_t SEGHistoricalPerformanceStore::GetComponentRecordCount(const std::string& component) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!db_) return 0;
    
    std::string sql = "SELECT COUNT(*) FROM execution_history WHERE component = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, component.c_str(), -1, SQLITE_STATIC);
    
    size_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = static_cast<size_t>(sqlite3_column_int64(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return count;
}

void SEGHistoricalPerformanceStore::MaybePrune() {
    if (!autoPruningEnabled_) return;
    
    // Prune old records
    if (retentionDays_ > 0) {
        PruneOldRecords(retentionDays_);
    }
    
    // Prune by component limit
    if (maxRecordsPerComponent_ > 0) {
        PruneByComponentLimit(maxRecordsPerComponent_);
    }
}

// ============================================================================
// Export
// ============================================================================

std::string SEGHistoricalPerformanceStore::ExportToJson(const HistoryQuery& query) const {
    auto records = QueryRecords(query);
    
    std::ostringstream json;
    json << "{\n";
    json << "  \"records\": [\n";
    
    for (size_t i = 0; i < records.size(); ++i) {
        json << "    " << records[i].ToJson();
        if (i + 1 < records.size()) json << ",";
        json << "\n";
    }
    
    json << "  ],\n";
    json << "  \"count\": " << records.size() << "\n";
    json << "}\n";
    
    return json.str();
}

bool SEGHistoricalPerformanceStore::ExportToFile(
    const std::string& filepath,
    const HistoryQuery& query
) const {
    std::ofstream file(filepath);
    if (!file) return false;
    
    file << ExportToJson(query);
    return file.good();
}

// ============================================================================
// Statistics
// ============================================================================

std::map<std::string, size_t> SEGHistoricalPerformanceStore::GetComponentCounts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, size_t> counts;
    
    if (!db_) return counts;
    
    const char* sql = "SELECT component, COUNT(*) FROM execution_history GROUP BY component;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string component = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            size_t count = static_cast<size_t>(sqlite3_column_int64(stmt, 1));
            counts[component] = count;
        }
        sqlite3_finalize(stmt);
    }
    
    return counts;
}

std::map<std::string, double> SEGHistoricalPerformanceStore::GetAverageDurationsByComponent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::map<std::string, double> averages;
    
    if (!db_) return averages;
    
    const char* sql = "SELECT component, AVG(duration_ms) FROM execution_history GROUP BY component;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string component = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            double avg = sqlite3_column_double(stmt, 1);
            averages[component] = avg;
        }
        sqlite3_finalize(stmt);
    }
    
    return averages;
}

// ============================================================================
// Helper Functions
// ============================================================================

bool SEGHistoricalPerformanceStore::ExecuteSql(const std::string& sql) {
    if (!db_) return false;
    
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        if (errMsg) {
            sqlite3_free(errMsg);
        }
        return false;
    }
    
    return true;
}

PerformanceRecord SEGHistoricalPerformanceStore::RowToRecord(sqlite3_stmt* stmt) const {
    PerformanceRecord record;
    
    record.id = sqlite3_column_int64(stmt, 0);
    record.executionId = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    record.component = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    record.operation = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    record.componentType = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    record.timestamp = sqlite3_column_int64(stmt, 5);
    record.durationMs = sqlite3_column_double(stmt, 6);
    record.throughputTps = sqlite3_column_double(stmt, 7);
    record.convergenceScore = sqlite3_column_double(stmt, 8);
    record.convergenceGain = sqlite3_column_double(stmt, 9);
    record.memoryBytes = static_cast<size_t>(sqlite3_column_int64(stmt, 10));
    record.cpuCoresUsed = sqlite3_column_int(stmt, 11);
    record.cpuUtilization = sqlite3_column_double(stmt, 12);
    record.success = sqlite3_column_int(stmt, 13) != 0;
    
    const char* errorMsg = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 14));
    if (errorMsg) record.errorMessage = errorMsg;
    
    record.retryCount = sqlite3_column_int(stmt, 15);
    record.batchNumber = sqlite3_column_int(stmt, 16);
    
    const char* cycleName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 17));
    if (cycleName) record.cycleName = cycleName;
    
    const char* taskCategory = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 18));
    if (taskCategory) record.taskCategory = taskCategory;
    
    return record;
}

ComponentTrend::TrendDirection SEGHistoricalPerformanceStore::CalculateTrendDirection(
    const std::vector<PerformanceRecord>& records
) const {
    if (records.size() < 10) {
        return ComponentTrend::TrendDirection::Unknown;
    }
    
    // Split into two halves and compare
    size_t half = records.size() / 2;
    double firstHalfAvg = 0.0, secondHalfAvg = 0.0;
    
    for (size_t i = 0; i < half; ++i) {
        firstHalfAvg += records[i].durationMs;
    }
    for (size_t i = half; i < records.size(); ++i) {
        secondHalfAvg += records[i].durationMs;
    }
    
    firstHalfAvg /= half;
    secondHalfAvg /= (records.size() - half);
    
    double change = (secondHalfAvg - firstHalfAvg) / firstHalfAvg;
    
    if (change > 0.1) {
        return ComponentTrend::TrendDirection::Degrading;
    } else if (change < -0.1) {
        return ComponentTrend::TrendDirection::Improving;
    } else {
        return ComponentTrend::TrendDirection::Stable;
    }
}

double SEGHistoricalPerformanceStore::CalculateTrendSlope(
    const std::vector<PerformanceRecord>& records
) const {
    if (records.size() < 2) return 0.0;
    
    // Simple linear regression slope
    double sumX = 0.0, sumY = 0.0, sumXY = 0.0, sumX2 = 0.0;
    size_t n = records.size();
    
    for (size_t i = 0; i < n; ++i) {
        double x = static_cast<double>(i);
        double y = records[i].durationMs;
        sumX += x;
        sumY += y;
        sumXY += x * y;
        sumX2 += x * x;
    }
    
    double denominator = n * sumX2 - sumX * sumX;
    if (denominator == 0.0) return 0.0;
    
    double slope = (n * sumXY - sumX * sumY) / denominator;
    return slope / (sumY / n); // Normalize by average
}

double SEGHistoricalPerformanceStore::CalculatePercentile(
    const std::vector<double>& values,
    double percentile
) const {
    if (values.empty()) return 0.0;
    
    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    
    size_t index = static_cast<size_t>(percentile * (sorted.size() - 1));
    return sorted[index];
}

double SEGHistoricalPerformanceStore::CalculateStdDev(
    const std::vector<double>& values,
    double mean
) const {
    if (values.size() < 2) return 0.0;
    
    double sumSquaredDiff = 0.0;
    for (double value : values) {
        double diff = value - mean;
        sumSquaredDiff += diff * diff;
    }
    
    return std::sqrt(sumSquaredDiff / (values.size() - 1));
}

// ============================================================================
// Global Functions
// ============================================================================

bool ValidateHistoricalPerformanceStore() {
    SEGHistoricalPerformanceStore store;
    
    // Initialize in-memory database
    if (!store.Initialize(":memory:")) {
        return false;
    }
    
    // Create a test record
    PerformanceRecord record;
    record.executionId = "test-execution";
    record.component = "RunUnityCycle";
    record.componentType = "EngineCycle";
    record.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    record.durationMs = 14.0;
    record.throughputTps = 100.0;
    record.convergenceScore = 0.85;
    record.success = true;
    
    // Store record
    if (!store.StoreRecord(record)) {
        return false;
    }
    
    // Query record
    HistoryQuery query;
    query.componentFilter = "RunUnityCycle";
    auto records = store.QueryRecords(query);
    
    if (records.size() != 1) {
        return false;
    }
    
    // Get trend
    auto trend = store.GetComponentTrend("RunUnityCycle", 100);
    if (trend.sampleCount != 1) {
        return false;
    }
    
    return true;
}

std::string ExportStoreStatistics(const SEGHistoricalPerformanceStore& store) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"store_statistics\": {\n";
    json << "    \"total_records\": " << store.GetTotalRecordCount() << ",\n";
    json << "    \"component_counts\": {\n";
    
    auto counts = store.GetComponentCounts();
    size_t i = 0;
    for (const auto& [component, count] : counts) {
        json << "      \"" << component << "\": " << count;
        if (++i < counts.size()) json << ",";
        json << "\n";
    }
    
    json << "    }\n";
    json << "  }\n";
    json << "}\n";
    return json.str();
}

} // namespace SEG
} // namespace Sovereign
