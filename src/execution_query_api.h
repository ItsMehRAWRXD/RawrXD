#pragma once
#ifndef RAWRXD_EXECUTION_QUERY_API_H
#define RAWRXD_EXECUTION_QUERY_API_H

#include "agentic_task_graph.h"
#include "execution_graph_hash.h"
#include "statistical_collapse.h"
#include <functional>
#include <future>

namespace RawrXD {

// ============================================================================
// EXECUTION QUERY API - First-class introspection surface
// 
// Transforms internal query capabilities into exposed API for:
// - Execution debugging
// - Performance introspection  
// - Adaptive routing control
// - Model behavior analytics
// ============================================================================

// ============================================================================
// Query Results
// ============================================================================
struct PathAnalysisResult {
    std::string pathSignature;
    uint64_t executionCount;
    double totalLatencyMs;
    double avgLatencyMs;
    double p95LatencyMs;
    uint32_t successCount;
    uint32_t failureCount;
    std::vector<std::string> backendDistribution;
};

struct AnomalyDetectionResult {
    std::string nodeId;
    std::string nodeType;
    std::string anomalyType;  // "latency_spike", "failure_cluster", "routing_divergence"
    double severity;  // 0.0 - 1.0
    std::string description;
    std::vector<std::string> contributingFactors;
};

struct PerformanceInsight {
    std::string metric;
    double currentValue;
    double baselineValue;
    double changePercent;
    std::string trend;  // "improving", "degrading", "stable"
    std::vector<std::string> recommendations;
};

struct ExecutionComparison {
    std::string executionIdA;
    std::string executionIdB;
    GraphHash hashA;
    GraphHash hashB;
    bool isomorphic;
    std::vector<std::string> structuralDifferences;
    std::vector<std::string> outcomeDifferences;
    double latencyDeltaPercent;
    double successRateDelta;
};

// ============================================================================
// Execution Query API - Main introspection interface
// ============================================================================
class ExecutionQueryAPI {
public:
    static ExecutionQueryAPI& instance();

    // ====================================================================
    // DEBUGGING API
    // ====================================================================
    
    // Get full execution graph for debugging
    std::optional<AgenticTaskNode> getExecutionGraph(const std::string& executionId);
    
    // Get execution trace (step-by-step)
    std::vector<std::string> getExecutionTrace(const std::string& executionId);
    
    // Get current state of active execution
    struct ActiveExecutionState {
        std::string executionId;
        std::string currentNodeId;
        std::string currentState;
        std::chrono::milliseconds elapsedTime;
        uint32_t completedNodes;
        uint32_t pendingNodes;
        std::vector<std::string> activeBackends;
    };
    std::vector<ActiveExecutionState> getActiveExecutions();
    
    // Pause/resume execution (for debugging)
    bool pauseExecution(const std::string& executionId);
    bool resumeExecution(const std::string& executionId);
    bool stepExecution(const std::string& executionId);  // Step-by-step

    // ====================================================================
    // PERFORMANCE INTROSPECTION API
    // ====================================================================
    
    // Hot path analysis
    std::vector<PathAnalysisResult> getHotPaths(int topN = 10);
    
    // Bottleneck identification
    std::vector<std::string> identifyBottlenecks(const std::string& executionId);
    
    // Latency distribution analysis
    struct LatencyDistribution {
        double p50, p95, p99, p99_9;
        std::vector<std::pair<std::string, double>> breakdownByBackend;
    };
    LatencyDistribution getLatencyDistribution(const std::string& nodeType = "all");
    
    // Performance insights
    std::vector<PerformanceInsight> getPerformanceInsights();
    
    // Compare executions
    ExecutionComparison compareExecutions(const std::string& executionIdA, 
                                          const std::string& executionIdB);

    // ====================================================================
    // ADAPTIVE ROUTING CONTROL API
    // ====================================================================
    
    // Get current routing policy
    struct RoutingPolicy {
        RuntimeMode mode;
        std::map<std::string, double> backendWeights;
        std::map<std::string, int> timeoutOverrides;
        std::map<std::string, int> retryOverrides;
    };
    RoutingPolicy getRoutingPolicy();
    
    // Update routing policy
    bool updateRoutingPolicy(const RoutingPolicy& policy);
    
    // Get recommended policy (from statistical learning)
    RoutingPolicy getRecommendedPolicy();
    
    // Apply recommended policy
    bool applyRecommendedPolicy();
    
    // A/B test routing strategies
    std::string startRoutingExperiment(const std::string& strategyA,
                                       const std::string& strategyB,
                                       double trafficSplit);
    ExperimentResult getExperimentResults(const std::string& experimentId);
    bool stopExperiment(const std::string& experimentId);

    // ====================================================================
    // MODEL BEHAVIOR ANALYTICS API
    // ====================================================================
    
    // Anomaly detection
    std::vector<AnomalyDetectionResult> detectAnomalies();
    std::vector<AnomalyDetectionResult> detectAnomaliesInExecution(const std::string& executionId);
    
    // Failure cluster analysis
    struct FailureCluster {
        std::string errorPattern;
        uint32_t occurrenceCount;
        std::vector<std::string> affectedNodeTypes;
        std::vector<std::string> correlatedBackends;
        std::string suggestedMitigation;
    };
    std::vector<FailureCluster> analyzeFailureClusters();
    
    // Model behavior patterns
    struct BehaviorPattern {
        std::string patternId;
        std::string description;
        double frequency;
        double avgLatency;
        double successRate;
        std::vector<std::string> commonPreconditions;
    };
    std::vector<BehaviorPattern> discoverBehaviorPatterns();
    
    // Predictive analytics
    struct Prediction {
        std::string metric;
        double predictedValue;
        double confidence;
        std::chrono::time_point<std::chrono::system_clock> predictedTime;
    };
    std::vector<Prediction> getPredictions(const std::string& horizon = "1h");

    // ====================================================================
    // REAL-TIME STREAMING API
    // ====================================================================
    
    // Subscribe to execution events
    using ExecutionEventCallback = std::function<void(const std::string& eventType,
                                                       const std::string& executionId,
                                                       const std::string& data)>;
    
    int subscribeToEvents(ExecutionEventCallback callback);
    void unsubscribeFromEvents(int subscriptionId);
    
    // Subscribe to anomalies
    using AnomalyCallback = std::function<void(const AnomalyDetectionResult& anomaly)>;
    int subscribeToAnomalies(AnomalyCallback callback);
    void unsubscribeFromAnomalies(int subscriptionId);

    // ====================================================================
    // EXPORT API
    // ====================================================================
    
    // Export execution data
    std::string exportExecutionData(const std::string& executionId, 
                                      const std::string& format = "json");
    
    // Export statistical models
    std::string exportStatisticalModels(const std::string& nodeType = "all");
    
    // Export lineage graph
    std::string exportLineageGraph(const std::string& format = "dot");

private:
    ExecutionQueryAPI() = default;
    
    mutable std::mutex m_mutex;
    std::map<int, ExecutionEventCallback> m_eventCallbacks;
    std::map<int, AnomalyCallback> m_anomalyCallbacks;
    int m_nextSubscriptionId = 1;
};

// ============================================================================
// Higher-Level Agent Interface
// Simplified API for agent consumption
// ============================================================================
class AgentExecutionInterface {
public:
    // Ask questions about execution
    struct QueryResult {
        bool found;
        std::string answer;
        std::vector<std::string> evidence;
        double confidence;
    };
    
    QueryResult ask(const std::string& naturalLanguageQuery);
    
    // Get actionable recommendations
    std::vector<std::string> getRecommendations();
    
    // Request execution with specific constraints
    struct ExecutionRequest {
        std::string intent;
        std::map<std::string, std::string> constraints;
        bool requireExplanation = false;
    };
    
    struct ExecutionResponse {
        std::string executionId;
        std::string result;
        std::string explanation;
        std::vector<std::string> alternativePaths;
    };
    
    ExecutionResponse executeWithConstraints(const ExecutionRequest& request);
};

} // namespace RawrXD

#endif // RAWRXD_EXECUTION_QUERY_API_H
