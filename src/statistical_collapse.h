#pragma once
#ifndef RAWRXD_STATISTICAL_COLLAPSE_H
#define RAWRXD_STATISTICAL_COLLAPSE_H

#include <vector>
#include <map>
#include <string>
#include <chrono>

namespace RawrXD {

// ============================================================================
// STATISTICAL COLLAPSE SEMANTICS
//
// Upgrade from simple counts to rich statistical distributions
// A collapsed node becomes a statistical micro-model of execution behavior
// ============================================================================

struct LatencyHistogram {
    // Buckets in milliseconds: [0-10, 10-50, 50-100, 100-500, 500-1000, 1000+]
    std::array<uint32_t, 6> buckets = {0, 0, 0, 0, 0, 0};
    uint64_t totalSamples = 0;
    double meanMs = 0.0;
    double p50Ms = 0.0;
    double p95Ms = 0.0;
    double p99Ms = 0.0;
    
    void addSample(int64_t latencyMs);
    void merge(const LatencyHistogram& other);
    std::string toString() const;
};

struct FailureDistribution {
    std::map<std::string, uint32_t> failureClasses;  // error_type -> count
    uint32_t totalFailures = 0;
    double failureRate = 0.0;
    
    void recordFailure(const std::string& errorClass);
    void merge(const FailureDistribution& other);
    std::string toString() const;
};

struct BackendRoutingDistribution {
    std::map<std::string, uint32_t> backendUsage;  // backend_id -> count
    uint32_t totalCalls = 0;
    std::string dominantBackend;
    double backendEntropy = 0.0;  // Shannon entropy of distribution
    
    void recordBackend(const std::string& backendId);
    void merge(const BackendRoutingDistribution& other);
    std::string toString() const;
};

struct RetryPattern {
    uint32_t immediateSuccess = 0;      // 0 retries
    uint32_t singleRetry = 0;          // 1 retry
    uint32_t multipleRetries = 0;        // 2+ retries
    uint32_t ultimateFailure = 0;      // Failed after all retries
    
    double averageRetries = 0.0;
    double retrySuccessRate = 0.0;
    
    void recordAttempt(uint32_t retryCount, bool success);
    void merge(const RetryPattern& other);
    std::string toString() const;
};

// ============================================================================
// Statistical Node Model - Rich collapsed representation
// ============================================================================
struct StatisticalNodeModel {
    // Identity
    std::string nodeType;
    std::string intentPattern;  // Generalized intent (not specific instance)
    
    // Temporal
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    uint64_t totalExecutions = 0;
    
    // Performance
    LatencyHistogram latency;
    
    // Reliability
    FailureDistribution failures;
    RetryPattern retries;
    
    // Routing
    BackendRoutingDistribution routing;
    
    // Child aggregation (if children were collapsed)
    uint32_t collapsedChildCount = 0;
    std::map<std::string, StatisticalNodeModel> childModels;  // by type
    
    // Methods
    void recordExecution(const AgenticTaskNode& node);
    void merge(const StatisticalNodeModel& other);
    std::string toJson() const;
    static StatisticalNodeModel fromCollapsedNode(const AgenticTaskNode& node);
};

// ============================================================================
// Statistical Aggregator - Builds models from execution history
// ============================================================================
class StatisticalAggregator {
public:
    static StatisticalAggregator& instance();
    
    // Record execution for pattern learning
    void recordExecution(const AgenticTaskNode& node);
    
    // Get statistical model for a node type
    StatisticalNodeModel getModel(const std::string& nodeType) const;
    
    // Predict behavior
    double predictLatency(const std::string& nodeType, double percentile = 0.95) const;
    double predictFailureRate(const std::string& nodeType) const;
    std::string predictOptimalBackend(const std::string& nodeType) const;
    
    // Anomaly detection
    bool isAnomalous(const AgenticTaskNode& node) const;
    std::vector<std::string> getAnomalyReasons(const AgenticTaskNode& node) const;
    
    // Export for policy tuning
    std::string exportModels() const;
    void clearHistory();

private:
    mutable std::mutex m_mutex;
    std::map<std::string, StatisticalNodeModel> m_models;
    std::vector<AgenticTaskNode> m_recentExecutions;
    static constexpr size_t MAX_HISTORY = 10000;
};

// ============================================================================
// Adaptive Policy Tuning - Use statistics to optimize
// ============================================================================
class AdaptivePolicyTuner {
public:
    // Tune policy based on statistical models
    static RuntimeMode recommendRuntimeMode(const std::string& nodeType);
    static int recommendTimeoutMs(const std::string& nodeType, double confidence = 0.95);
    static int recommendRetryCount(const std::string& nodeType);
    static std::string recommendBackend(const std::string& nodeType);
    
    // Detect hot paths for optimization
    static std::vector<std::string> identifyHotPaths(int topN = 10);
    
    // Detect problematic patterns
    static std::vector<std::string> identifyFailureClusters();
};

} // namespace RawrXD

#endif // RAWRXD_STATISTICAL_COLLAPSE_H
