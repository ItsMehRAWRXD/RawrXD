#include "execution_query_api.h"
#include "execution_graph_hash.h"
#include "statistical_collapse.h"
#include "token_lineage.h"
#include <sstream>
#include <iomanip>

namespace RawrXD {

// ============================================================================
// ExecutionQueryAPI Implementation
// ============================================================================

ExecutionQueryAPI& ExecutionQueryAPI::instance() {
    static ExecutionQueryAPI api;
    return api;
}

// ====================================================================
// DEBUGGING API
// ====================================================================

std::optional<AgenticTaskNode> ExecutionQueryAPI::getExecutionGraph(const std::string& executionId) {
    // Query from execution registry
    // TODO: Implement actual storage lookup
    return std::nullopt;
}

std::vector<std::string> ExecutionQueryAPI::getExecutionTrace(const std::string& executionId) {
    std::vector<std::string> trace;
    auto graph = getExecutionGraph(executionId);
    if (!graph) return trace;
    
    // Build trace from root
    std::function<void(const AgenticTaskNode&)> traverse = [&](const AgenticTaskNode& node) {
        std::stringstream ss;
        ss << "[" << node.nodeId << "] " << node.nodeType 
           << " -> " << node.state;
        if (!node.result.empty()) {
            ss << " (result: " << node.result.substr(0, 50) << "...)";
        }
        trace.push_back(ss.str());
        
        for (const auto& child : node.children) {
            traverse(child);
        }
    };
    
    traverse(*graph);
    return trace;
}

std::vector<ExecutionQueryAPI::ActiveExecutionState> ExecutionQueryAPI::getActiveExecutions() {
    std::vector<ActiveExecutionState> active;
    // TODO: Query active execution registry
    return active;
}

bool ExecutionQueryAPI::pauseExecution(const std::string& executionId) {
    // TODO: Signal execution to pause
    fprintf(stderr, "[QueryAPI] Pausing execution: %s\n", executionId.c_str());
    return true;
}

bool ExecutionQueryAPI::resumeExecution(const std::string& executionId) {
    fprintf(stderr, "[QueryAPI] Resuming execution: %s\n", executionId.c_str());
    return true;
}

bool ExecutionQueryAPI::stepExecution(const std::string& executionId) {
    fprintf(stderr, "[QueryAPI] Stepping execution: %s\n", executionId.c_str());
    return true;
}

// ====================================================================
// PERFORMANCE INTROSPECTION API
// ====================================================================

std::vector<PathAnalysisResult> ExecutionQueryAPI::getHotPaths(int topN) {
    std::vector<PathAnalysisResult> results;
    
    // Query statistical aggregator for hot paths
    auto& agg = StatisticalAggregator::instance();
    
    // Get all node types
    std::vector<std::string> nodeTypes = {"inference", "agent", "task", "tool"};
    
    for (const auto& nodeType : nodeTypes) {
        auto model = agg.getModel(nodeType);
        if (model.totalExecutions == 0) continue;
        
        PathAnalysisResult result;
        result.pathSignature = nodeType;
        result.executionCount = model.totalExecutions;
        result.avgLatencyMs = model.latency.meanMs;
        result.p95LatencyMs = model.latency.p95Ms;
        result.successCount = model.totalExecutions - model.failures.totalFailures;
        result.failureCount = model.failures.totalFailures;
        
        for (const auto& [backend, count] : model.routing.backendUsage) {
            result.backendDistribution.push_back(backend + ":" + std::to_string(count));
        }
        
        results.push_back(result);
    }
    
    // Sort by execution count
    std::sort(results.begin(), results.end(), 
        [](const auto& a, const auto& b) { return a.executionCount > b.executionCount; });
    
    if (results.size() > static_cast<size_t>(topN)) {
        results.resize(topN);
    }
    
    return results;
}

std::vector<std::string> ExecutionQueryAPI::identifyBottlenecks(const std::string& executionId) {
    std::vector<std::string> bottlenecks;
    
    // Analyze execution graph for high-latency nodes
    auto graph = getExecutionGraph(executionId);
    if (!graph) return bottlenecks;
    
    std::function<void(const AgenticTaskNode&)> findBottlenecks = [&](const AgenticTaskNode& node) {
        // Check if node is a bottleneck (high latency relative to siblings)
        if (node.latencyMs > 1000) {  // Threshold: 1 second
            bottlenecks.push_back(node.nodeId + " (" + std::to_string(node.latencyMs) + "ms)");
        }
        
        for (const auto& child : node.children) {
            findBottlenecks(child);
        }
    };
    
    findBottlenecks(*graph);
    return bottlenecks;
}

ExecutionQueryAPI::LatencyDistribution ExecutionQueryAPI::getLatencyDistribution(const std::string& nodeType) {
    LatencyDistribution dist;
    
    auto& agg = StatisticalAggregator::instance();
    auto model = agg.getModel(nodeType == "all" ? "inference" : nodeType);
    
    dist.p50 = model.latency.p50Ms;
    dist.p95 = model.latency.p95Ms;
    dist.p99 = model.latency.p99Ms;
    dist.p99_9 = model.latency.p99Ms * 1.5;  // Estimate
    
    for (const auto& [backend, count] : model.routing.backendUsage) {
        dist.breakdownByBackend.push_back({backend, static_cast<double>(count)});
    }
    
    return dist;
}

std::vector<PerformanceInsight> ExecutionQueryAPI::getPerformanceInsights() {
    std::vector<PerformanceInsight> insights;
    
    // Compare current vs baseline
    auto hotPaths = getHotPaths(5);
    
    for (const auto& path : hotPaths) {
        PerformanceInsight insight;
        insight.metric = path.pathSignature + "_latency";
        insight.currentValue = path.avgLatencyMs;
        insight.baselineValue = path.avgLatencyMs * 0.9;  // Simulated baseline
        insight.changePercent = ((insight.currentValue - insight.baselineValue) / insight.baselineValue) * 100.0;
        
        if (insight.changePercent > 10) {
            insight.trend = "degrading";
            insight.recommendations.push_back("Consider backend scaling for " + path.pathSignature);
        } else if (insight.changePercent < -10) {
            insight.trend = "improving";
        } else {
            insight.trend = "stable";
        }
        
        insights.push_back(insight);
    }
    
    return insights;
}

ExecutionComparison ExecutionQueryAPI::compareExecutions(const std::string& executionIdA, 
                                                          const std::string& executionIdB) {
    ExecutionComparison comp;
    comp.executionIdA = executionIdA;
    comp.executionIdB = executionIdB;
    
    auto graphA = getExecutionGraph(executionIdA);
    auto graphB = getExecutionGraph(executionIdB);
    
    if (!graphA || !graphB) {
        comp.isomorphic = false;
        return comp;
    }
    
    comp.hashA = GraphHasher::hashTopology(*graphA);
    comp.hashB = GraphHasher::hashTopology(*graphB);
    comp.isomorphic = GraphHasher::equal(comp.hashA, comp.hashB);
    
    auto diff = GraphHasher::diff(*graphA, *graphB);
    comp.structuralDifferences = diff.structuralDifferences;
    comp.outcomeDifferences = diff.outcomeDifferences;
    
    // Calculate latency delta
    auto outcomeA = GraphHasher::hashOutcome(*graphA);
    auto outcomeB = GraphHasher::hashOutcome(*graphB);
    comp.latencyDeltaPercent = 0.0;  // TODO: Extract actual latency
    
    return comp;
}

// ====================================================================
// ADAPTIVE ROUTING CONTROL API
// ====================================================================

ExecutionQueryAPI::RoutingPolicy ExecutionQueryAPI::getRoutingPolicy() {
    RoutingPolicy policy;
    policy.mode = GetGlobalRuntimeMode();
    
    // Get current backend weights from statistical models
    auto& agg = StatisticalAggregator::instance();
    auto model = agg.getModel("inference");
    
    for (const auto& [backend, count] : model.routing.backendUsage) {
        policy.backendWeights[backend] = static_cast<double>(count) / model.routing.totalCalls;
    }
    
    return policy;
}

bool ExecutionQueryAPI::updateRoutingPolicy(const RoutingPolicy& policy) {
    SetGlobalRuntimeMode(policy.mode);
    fprintf(stderr, "[QueryAPI] Updated routing policy to mode %d\n", static_cast<int>(policy.mode));
    return true;
}

ExecutionQueryAPI::RoutingPolicy ExecutionQueryAPI::getRecommendedPolicy() {
    RoutingPolicy policy;
    policy.mode = AdaptivePolicyTuner::recommendRuntimeMode("inference");
    
    std::string bestBackend = AdaptivePolicyTuner::recommendBackend("inference");
    policy.backendWeights[bestBackend] = 1.0;
    
    return policy;
}

bool ExecutionQueryAPI::applyRecommendedPolicy() {
    auto policy = getRecommendedPolicy();
    return updateRoutingPolicy(policy);
}

// ====================================================================
// MODEL BEHAVIOR ANALYTICS API
// ====================================================================

std::vector<AnomalyDetectionResult> ExecutionQueryAPI::detectAnomalies() {
    std::vector<AnomalyDetectionResult> anomalies;
    
    auto& agg = StatisticalAggregator::instance();
    
    // Check each node type for anomalies
    std::vector<std::string> nodeTypes = {"inference", "agent", "task"};
    
    for (const auto& nodeType : nodeTypes) {
        // This would check actual recent executions
        // For now, return empty
    }
    
    return anomalies;
}

std::vector<ExecutionQueryAPI::FailureCluster> ExecutionQueryAPI::analyzeFailureClusters() {
    std::vector<FailureCluster> clusters;
    
    auto& agg = StatisticalAggregator::instance();
    auto model = agg.getModel("inference");
    
    for (const auto& [errorClass, count] : model.failures.failureClasses) {
        if (count > 5) {  // Threshold for cluster
            FailureCluster cluster;
            cluster.errorPattern = errorClass;
            cluster.occurrenceCount = count;
            cluster.suggestedMitigation = "Review " + errorClass + " handling";
            clusters.push_back(cluster);
        }
    }
    
    return clusters;
}

std::vector<ExecutionQueryAPI::BehaviorPattern> ExecutionQueryAPI::discoverBehaviorPatterns() {
    std::vector<BehaviorPattern> patterns;
    
    // Discover patterns from statistical models
    auto& agg = StatisticalAggregator::instance();
    
    std::vector<std::string> nodeTypes = {"inference", "agent", "task"};
    
    for (const auto& nodeType : nodeTypes) {
        auto model = agg.getModel(nodeType);
        if (model.totalExecutions == 0) continue;
        
        BehaviorPattern pattern;
        pattern.patternId = nodeType + "_pattern";
        pattern.description = "Typical " + nodeType + " execution pattern";
        pattern.frequency = static_cast<double>(model.totalExecutions) / 1000.0;  // Normalized
        pattern.avgLatency = model.latency.meanMs;
        pattern.successRate = 1.0 - (static_cast<double>(model.failures.totalFailures) / model.totalExecutions);
        
        patterns.push_back(pattern);
    }
    
    return patterns;
}

// ====================================================================
// REAL-TIME STREAMING API
// ====================================================================

int ExecutionQueryAPI::subscribeToEvents(ExecutionEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    int id = m_nextSubscriptionId++;
    m_eventCallbacks[id] = callback;
    return id;
}

void ExecutionQueryAPI::unsubscribeFromEvents(int subscriptionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_eventCallbacks.erase(subscriptionId);
}

int ExecutionQueryAPI::subscribeToAnomalies(AnomalyCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    int id = m_nextSubscriptionId++;
    m_anomalyCallbacks[id] = callback;
    return id;
}

void ExecutionQueryAPI::unsubscribeFromAnomalies(int subscriptionId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_anomalyCallbacks.erase(subscriptionId);
}

// ====================================================================
// EXPORT API
// ====================================================================

std::string ExecutionQueryAPI::exportExecutionData(const std::string& executionId, 
                                                    const std::string& format) {
    if (format == "json") {
        auto graph = getExecutionGraph(executionId);
        if (!graph) return "{}";
        return SerializeGraphToLog(*graph);
    } else if (format == "dot") {
        // Export as DOT graph
        std::stringstream dot;
        dot << "digraph Execution {\n";
        // TODO: Traverse and export
        dot << "}\n";
        return dot.str();
    }
    return "{}";
}

std::string ExecutionQueryAPI::exportStatisticalModels(const std::string& nodeType) {
    auto& agg = StatisticalAggregator::instance();
    
    if (nodeType == "all") {
        // Export all models
        std::stringstream json;
        json << "{\"models\":[";
        // TODO: Export all
        json << "]}";
        return json.str();
    } else {
        auto model = agg.getModel(nodeType);
        return model.toJson();
    }
}

std::string ExecutionQueryAPI::exportLineageGraph(const std::string& format) {
    return TokenLineage::instance().exportLineageGraph();
}

} // namespace RawrXD
