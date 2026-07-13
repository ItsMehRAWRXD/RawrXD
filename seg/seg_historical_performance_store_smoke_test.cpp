/**
 * seg_historical_performance_store_smoke_test.cpp
 * 
 * Phase C.0 Batch 3/5: Historical Performance Store Validation
 * 
 * Tests SQLite-backed performance storage:
 * - Record storage and retrieval
 * - Component trend analysis
 * - Regression detection
 * - Performance prediction
 * - Export functionality
 */

#include "../src/seg/SEGHistoricalPerformanceStore.hpp"
#include <iostream>
#include <sstream>
#include <fstream>
#include <chrono>

using namespace Sovereign::SEG;

// Test framework
int testsPassed = 0;
int testsFailed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "  Running " << #name << "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED" << std::endl; \
        testsPassed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        testsFailed++; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        testsFailed++; \
    } \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: " << #expr; \
        throw std::runtime_error(oss.str()); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))
#define ASSERT_GT(a, b) ASSERT_TRUE((a) > (b))
#define ASSERT_LT(a, b) ASSERT_TRUE((a) < (b))

// ============================================================================
// Test: Data structure validation
// ============================================================================

TEST(performance_record_json) {
    PerformanceRecord record;
    record.id = 1;
    record.executionId = "test-exec-1";
    record.component = "RunUnityCycle";
    record.componentType = "EngineCycle";
    record.timestamp = 1234567890;
    record.durationMs = 14.5;
    record.throughputTps = 182.03;
    record.convergenceScore = 0.85;
    record.convergenceGain = 0.07;
    record.memoryBytes = 1024000;
    record.cpuCoresUsed = 4;
    record.cpuUtilization = 0.75;
    record.success = true;
    record.retryCount = 0;
    record.batchNumber = 243;
    record.cycleName = "RunUnityCycle";
    
    std::string json = record.ToJson();
    
    ASSERT_TRUE(json.find("test-exec-1") != std::string::npos);
    ASSERT_TRUE(json.find("RunUnityCycle") != std::string::npos);
    ASSERT_TRUE(json.find("14.5") != std::string::npos);
    ASSERT_TRUE(json.find("0.85") != std::string::npos);
}

TEST(component_trend_json) {
    ComponentTrend trend;
    trend.component = "RunUnityCycle";
    trend.componentType = "EngineCycle";
    trend.sampleCount = 100;
    trend.avgDurationMs = 14.5;
    trend.minDurationMs = 10.0;
    trend.maxDurationMs = 25.0;
    trend.p95DurationMs = 20.0;
    trend.p99DurationMs = 23.0;
    trend.stdDevDurationMs = 2.5;
    trend.avgThroughputTps = 182.0;
    trend.avgConvergenceScore = 0.85;
    trend.avgConvergenceGain = 0.07;
    trend.successRate = 0.98;
    trend.successCount = 98;
    trend.failureCount = 2;
    trend.trend = ComponentTrend::TrendDirection::Improving;
    trend.trendSlope = -0.05;
    
    std::string json = trend.ToJson();
    
    ASSERT_TRUE(json.find("RunUnityCycle") != std::string::npos);
    ASSERT_TRUE(json.find("improving") != std::string::npos);
    ASSERT_TRUE(json.find("100") != std::string::npos);
}

TEST(regression_event_json) {
    RegressionEvent event;
    event.component = "RunHarmonyCycle";
    event.componentType = "EngineCycle";
    event.detectedAt = 1234567890;
    event.previousAverageMs = 12.0;
    event.currentAverageMs = 18.0;
    event.degradationPercent = 50.0;
    event.severity = RegressionEvent::Severity::High;
    
    std::string json = event.ToJson();
    
    ASSERT_TRUE(json.find("RunHarmonyCycle") != std::string::npos);
    ASSERT_TRUE(json.find("HIGH") != std::string::npos);
    ASSERT_TRUE(json.find("50") != std::string::npos);
}

TEST(performance_prediction_json) {
    PerformancePrediction pred;
    pred.component = "RunUnityCycle";
    pred.componentType = "EngineCycle";
    pred.expectedDurationMs = 14.5;
    pred.confidence = 0.91;
    pred.historicalSamples = 842;
    pred.minExpectedMs = 12.0;
    pred.maxExpectedMs = 18.0;
    pred.failureProbability = 0.02;
    pred.regressionProbability = 0.1;
    
    std::string json = pred.ToJson();
    
    ASSERT_TRUE(json.find("RunUnityCycle") != std::string::npos);
    ASSERT_TRUE(json.find("14.5") != std::string::npos);
    ASSERT_TRUE(json.find("0.91") != std::string::npos);
    ASSERT_TRUE(json.find("842") != std::string::npos);
}

// ============================================================================
// Test: History query
// ============================================================================

TEST(history_query_sql_generation) {
    HistoryQuery query;
    query.componentFilter = "RunUnityCycle";
    query.componentTypeFilter = "EngineCycle";
    query.successFilter = true;
    query.startTime = 1000;
    query.endTime = 2000;
    query.limit = 50;
    
    std::string sql = query.ToSqlWhere();
    
    ASSERT_TRUE(sql.find("RunUnityCycle") != std::string::npos);
    ASSERT_TRUE(sql.find("EngineCycle") != std::string::npos);
    ASSERT_TRUE(sql.find("success") != std::string::npos);
    ASSERT_TRUE(sql.find("timestamp") != std::string::npos);
}

TEST(history_query_empty) {
    HistoryQuery query;
    std::string sql = query.ToSqlWhere();
    ASSERT_TRUE(sql.empty());
}

// ============================================================================
// Test: Trend direction enum
// ============================================================================

TEST(trend_direction_values) {
    ComponentTrend trend;
    
    trend.trend = ComponentTrend::TrendDirection::Improving;
    ASSERT_TRUE(trend.trend == ComponentTrend::TrendDirection::Improving);
    
    trend.trend = ComponentTrend::TrendDirection::Stable;
    ASSERT_TRUE(trend.trend == ComponentTrend::TrendDirection::Stable);
    
    trend.trend = ComponentTrend::TrendDirection::Degrading;
    ASSERT_TRUE(trend.trend == ComponentTrend::TrendDirection::Degrading);
    
    trend.trend = ComponentTrend::TrendDirection::Unknown;
    ASSERT_TRUE(trend.trend == ComponentTrend::TrendDirection::Unknown);
}

// ============================================================================
// Test: Regression severity enum
// ============================================================================

TEST(regression_severity_values) {
    RegressionEvent event;
    
    event.severity = RegressionEvent::Severity::None;
    ASSERT_EQ(event.GetSeverityString(), "NONE");
    
    event.severity = RegressionEvent::Severity::Warning;
    ASSERT_EQ(event.GetSeverityString(), "WARNING");
    
    event.severity = RegressionEvent::Severity::High;
    ASSERT_EQ(event.GetSeverityString(), "HIGH");
    
    event.severity = RegressionEvent::Severity::Critical;
    ASSERT_EQ(event.GetSeverityString(), "CRITICAL");
}

// ============================================================================
// Test: Store initialization (SQLite in-memory)
// ============================================================================

TEST(store_initialization) {
    SEGHistoricalPerformanceStore store;
    
    // Initialize with in-memory database
    bool initialized = store.Initialize(":memory:");
    ASSERT_TRUE(initialized);
    ASSERT_TRUE(store.IsInitialized());
    
    store.Shutdown();
    ASSERT_FALSE(store.IsInitialized());
}

// ============================================================================
// Test: Record storage and retrieval
// ============================================================================

TEST(store_and_retrieve_record) {
    SEGHistoricalPerformanceStore store;
    store.Initialize(":memory:");
    
    PerformanceRecord record;
    record.executionId = "test-exec-1";
    record.component = "RunUnityCycle";
    record.componentType = "EngineCycle";
    record.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    record.durationMs = 14.5;
    record.throughputTps = 182.0;
    record.convergenceScore = 0.85;
    record.success = true;
    record.batchNumber = 243;
    
    bool stored = store.StoreRecord(record);
    ASSERT_TRUE(stored);
    
    // Query the record
    HistoryQuery query;
    query.componentFilter = "RunUnityCycle";
    auto records = store.QueryRecords(query);
    
    ASSERT_EQ(records.size(), 1u);
    ASSERT_EQ(records[0].component, "RunUnityCycle");
    ASSERT_EQ(records[0].durationMs, 14.5);
    
    store.Shutdown();
}

// ============================================================================
// Test: Component trend analysis
// ============================================================================

TEST(component_trend_analysis) {
    SEGHistoricalPerformanceStore store;
    store.Initialize(":memory:");
    
    // Store multiple records for trend analysis
    for (int i = 0; i < 20; i++) {
        PerformanceRecord record;
        record.executionId = "test-exec-" + std::to_string(i);
        record.component = "RunUnityCycle";
        record.componentType = "EngineCycle";
        record.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count() + i;
        record.durationMs = 15.0 - i * 0.1; // Improving trend
        record.throughputTps = 180.0 + i;
        record.convergenceScore = 0.8 + i * 0.01;
        record.success = true;
        record.batchNumber = 243;
        
        store.StoreRecord(record);
    }
    
    auto trend = store.GetComponentTrend("RunUnityCycle", 20);
    
    ASSERT_EQ(trend.component, "RunUnityCycle");
    ASSERT_EQ(trend.componentType, "EngineCycle");
    ASSERT_EQ(trend.sampleCount, 20);
    ASSERT_GT(trend.avgDurationMs, 0.0);
    ASSERT_GT(trend.successRate, 0.0);
    
    store.Shutdown();
}

// ============================================================================
// Test: Statistics
// ============================================================================

TEST(store_statistics) {
    SEGHistoricalPerformanceStore store;
    store.Initialize(":memory:");
    
    // Store records for different components
    for (int i = 0; i < 5; i++) {
        PerformanceRecord record1;
        record1.component = "RunUnityCycle";
        record1.durationMs = 14.0 + i;
        record1.success = true;
        store.StoreRecord(record1);
        
        PerformanceRecord record2;
        record2.component = "RunHarmonyCycle";
        record2.durationMs = 20.0 + i;
        record2.success = true;
        store.StoreRecord(record2);
    }
    
    auto counts = store.GetComponentCounts();
    ASSERT_EQ(counts.size(), 2u);
    ASSERT_EQ(counts["RunUnityCycle"], 5u);
    ASSERT_EQ(counts["RunHarmonyCycle"], 5u);
    
    auto averages = store.GetAverageDurationsByComponent();
    ASSERT_EQ(averages.size(), 2u);
    ASSERT_GT(averages["RunUnityCycle"], 0.0);
    ASSERT_GT(averages["RunHarmonyCycle"], 0.0);
    
    store.Shutdown();
}

// ============================================================================
// Test: Export functionality
// ============================================================================

TEST(json_export) {
    SEGHistoricalPerformanceStore store;
    store.Initialize(":memory:");
    
    PerformanceRecord record;
    record.component = "RunUnityCycle";
    record.durationMs = 14.5;
    record.success = true;
    store.StoreRecord(record);
    
    HistoryQuery query;
    std::string json = store.ExportToJson(query);
    
    ASSERT_TRUE(json.find("records") != std::string::npos);
    ASSERT_TRUE(json.find("count") != std::string::npos);
    
    store.Shutdown();
}

// ============================================================================
// Test: Global validation
// ============================================================================

TEST(validate_historical_store) {
    bool result = ValidateHistoricalPerformanceStore();
    ASSERT_TRUE(result);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG Historical Performance Store Tests" << std::endl;
    std::cout << "Phase C.0 Batch 3/5: Historical Store" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Data Structure Tests
    std::cout << "Data Structure Tests:" << std::endl;
    RUN_TEST(performance_record_json);
    RUN_TEST(component_trend_json);
    RUN_TEST(regression_event_json);
    RUN_TEST(performance_prediction_json);
    std::cout << std::endl;
    
    // Query Tests
    std::cout << "Query Tests:" << std::endl;
    RUN_TEST(history_query_sql_generation);
    RUN_TEST(history_query_empty);
    std::cout << std::endl;
    
    // Enum Tests
    std::cout << "Enum Tests:" << std::endl;
    RUN_TEST(trend_direction_values);
    RUN_TEST(regression_severity_values);
    std::cout << std::endl;
    
    // Store Tests
    std::cout << "Store Tests:" << std::endl;
    RUN_TEST(store_initialization);
    RUN_TEST(store_and_retrieve_record);
    RUN_TEST(component_trend_analysis);
    RUN_TEST(store_statistics);
    RUN_TEST(json_export);
    std::cout << std::endl;
    
    // Validation Tests
    std::cout << "Validation Tests:" << std::endl;
    RUN_TEST(validate_historical_store);
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << testsPassed << " passed, " << testsFailed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (testsFailed == 0) {
        std::cout << "\n✓ Phase C.0 Batch 3/5 Complete" << std::endl;
        std::cout << "✓ Historical Performance Store validated" << std::endl;
        std::cout << "✓ Ready for Phase C.0 Batch 4/5: Benchmark Replay Engine" << std::endl;
    }
    
    return testsFailed > 0 ? 1 : 0;
}
