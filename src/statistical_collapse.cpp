#include "statistical_collapse.h"
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>

namespace RawrXD {

// ============================================================================
// LatencyHistogram Implementation
// ============================================================================

void LatencyHistogram::addSample(int64_t latencyMs) {
    totalSamples++;
    
    // Update bucket
    if (latencyMs < 10) buckets[0]++;
    else if (latencyMs < 50) buckets[1]++;
    else if (latencyMs < 100) buckets[2]++;
    else if (latencyMs < 500) buckets[3]++;
    else if (latencyMs < 1000) buckets[4]++;
    else buckets[5]++;
    
    // Update mean
    double delta = latencyMs - meanMs;
    meanMs += delta / totalSamples;
    
    // Calculate percentiles (simplified)
    // In real implementation, would use reservoir sampling or t-digest
    if (totalSamples == 1) {
        p50Ms = p95Ms = p99Ms = latencyMs;
    } else {
        // Weighted update
        p50Ms = p50Ms * 0.9 + latencyMs * 0.1;
        p95Ms = p95Ms * 0.95 + latencyMs * 0.05;
        p99Ms = p99Ms * 0.99 + latencyMs * 0.01;
    }
}

void LatencyHistogram::merge(const LatencyHistogram& other) {
    for (size_t i = 0; i < buckets.size(); ++i) {
        buckets[i] += other.buckets[i];
    }
    
    totalSamples += other.totalSamples;
    meanMs = (meanMs * totalSamples + other.meanMs * other.totalSamples) / 
             (totalSamples + other.totalSamples);
    p50Ms = (p50Ms + other.p50Ms) / 2;
    p95Ms = (p95Ms + other.p95Ms) / 2;
    p99Ms = (p99Ms + other.p99Ms) / 2;
}

std::string LatencyHistogram::toString() const {
    std::stringstream ss;
    ss << "LatencyHistogram[samples=" << totalSamples;
    ss << ", mean=" << std::fixed << std::setprecision(2) << meanMs << "ms";
    ss << ", p50=" << p50Ms << "ms";
    ss << ", p95=" << p95Ms << "ms";
    ss << ", p99=" << p99Ms << "ms";
    ss << ", buckets=[";
    for (size_t i = 0; i < buckets.size(); ++i) {
        if (i > 0) ss << ",";
        ss << buckets[i];
    }
    ss << "]]";
    return ss.str();
}

// ============================================================================
// FailureDistribution Implementation
// ============================================================================

void FailureDistribution::recordFailure(const std::string& errorClass) {
    failureClasses[errorClass]++;
    totalFailures++;
    
    // Recalculate failure rate
    // Note: totalAttempts would need to be tracked separately
}

void FailureDistribution::merge(const FailureDistribution& other) {
    for (const auto& [errorClass, count] : other.failureClasses) {
        failureClasses[errorClass] += count;
    }
    totalFailures += other.totalFailures;
    failureRate = (failureRate + other.failureRate) / 2;
}

std::string FailureDistribution::toString() const {
    std::stringstream ss;
    ss << "FailureDistribution[total=" << totalFailures;
    ss << ", rate=" << std::fixed << std::setprecision(4) << failureRate;
    ss << ", classes={";
    bool first = true;
    for (const auto& [errorClass, count] : failureClasses) {
        if (!first) ss << ",";
        first = false;
        ss << errorClass << ":" << count;
    }
    ss << "}]";
    return ss.str();
}

// ============================================================================
// BackendRoutingDistribution Implementation
// ============================================================================

void BackendRoutingDistribution::recordBackend(const std::string& backendId) {
    backendUsage[backendId]++;
    totalCalls++;
    
    // Update dominant backend
    uint32_t maxCount = 0;
    for (const auto& [id, count] : backendUsage) {
        if (count > maxCount) {
            maxCount = count;
            dominantBackend = id;
        }
    }
    
    // Calculate entropy
    backendEntropy = 0.0;
    for (const auto& [id, count] : backendUsage) {
        double p = static_cast<double>(count) / totalCalls;
        backendEntropy -= p * std::log2(p);
    }
}

void BackendRoutingDistribution::merge(const BackendRoutingDistribution& other) {
    for (const auto& [backendId, count] : other.backendUsage) {
        backendUsage[backendId] += count;
    }
    totalCalls += other.totalCalls;
    dominantBackend = other.dominantBackend; // Simplified
    backendEntropy = (backendEntropy + other.backendEntropy) / 2;
}

std::string BackendRoutingDistribution::toString() const {
    std::stringstream ss;
    ss << "BackendRoutingDistribution[total=" << totalCalls;
    ss << ", dominant=" << dominantBackend;
    ss << ", entropy=" << std::fixed << std::setprecision(4) << backendEntropy;
    ss << ", backends={";
    bool first = true;
    for (const auto& [id, count] : backendUsage) {
        if (!first) ss << ",";
        first = false;
        ss << id << ":" << count;
    }
    ss << "}]";
    return ss.str();
}

// ============================================================================
// RetryPattern Implementation
// ============================================================================

void RetryPattern::recordAttempt(uint32_t retryCount, bool success) {
    if (retryCount == 0) {
        immediateSuccess++;
    } else if (retryCount == 1) {
        singleRetry++;
    } else {
        multipleRetries++;
    }
    
    if (!success) {
        ultimateFailure++;
    }
    
    // Update averages
    uint32_t totalAttempts = immediateSuccess + singleRetry + multipleRetries + ultimateFailure;
    if (totalAttempts > 0) {
        averageRetries = static_cast<double>(singleRetry + multipleRetries * 2) / totalAttempts;
        retrySuccessRate = 1.0 - (static_cast<double>(ultimateFailure) / totalAttempts);
    }
}

void RetryPattern::merge(const RetryPattern& other) {
    immediateSuccess += other.immediateSuccess;
    singleRetry += other.singleRetry;
    multipleRetries += other.multipleRetries;
    ultimateFailure += other.ultimateFailure;
    
    averageRetries = (averageRetries + other.averageRetries) / 2;
    retrySuccessRate = (retrySuccessRate + other.retrySuccessRate) / 2;
}

std::string RetryPattern::toString() const {
    std::stringstream ss;
    ss << "RetryPattern[immediate=" << immediateSuccess;
    ss << ", single=" << singleRetry;
    ss << ", multiple=" << multipleRetries;
    ss << ", failed=" << ultimateFailure;
    ss << ", avgRetries=" << std::fixed << std::setprecision(2) << averageRetries;
    ss << ", successRate=" << std::fixed << std::setprecision(4) << retrySuccessRate << "]";
    return ss.str();
}

// ============================================================================
// StatisticalNodeModel Implementation
// ============================================================================

void StatisticalNodeModel::recordExecution(const AgenticTaskNode& node) {
    totalExecutions++;
    lastSeen = std::chrono::system_clock::now();
    
    // Record latency if available
    if (node.latencyMs > 0) {
        latency.addSample(node.latencyMs);
    }
    
    // Record failure if present
    if (node.state == AgenticTaskNode::State::FAILED && node.errorMessage) {
        failures.recordFailure(*node.errorMessage);
    }
    
    // Record backend
    if (node.backendId) {
        routing.recordBackend(*node.backendId);
    }
    
    // Record retry pattern
    retries.recordAttempt(node.retryCount, node.state != AgenticTaskNode::State::FAILED);
}

void StatisticalNodeModel::merge(const StatisticalNodeModel& other) {
    totalExecutions += other.totalExecutions;
    latency.merge(other.latency);
    failures.merge(other.failures);
    routing.merge(other.routing);
    retries.merge(other.retries);
    
    // Merge child models
    for (const auto& [type, childModel] : other.childModels) {
        if (childModels.count(type)) {
            childModels[type].merge(childModel);
        } else {
            childModels[type] = childModel;
        }
    }
}

std::string StatisticalNodeModel::toJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"nodeType\":\"" << nodeType << "\",";
    ss << "\"intentPattern\":\"" << intentPattern << "\",";
    ss << "\"totalExecutions\":" << totalExecutions << ",";
    ss << "\"latency\":" << latency.toString() << ",";
    ss << "\"failures\":" << failures.toString() << ",";
    ss << "\"routing\":" << routing.toString() << ",";
    ss << "\"retries\":" << retries.toString();
    ss << "}";
    return ss.str();
}

StatisticalNodeModel StatisticalNodeModel::fromCollapsedNode(const AgenticTaskNode& node) {
    StatisticalNodeModel model;
    model.nodeType = node.nodeType;
    model.intentPattern = node.intent; // Simplified - would generalize
    model.firstSeen = model.lastSeen = std::chrono::system_clock::now();
    model.totalExecutions = node.successCount + node.failureCount;
    
    // Record from collapsed data
    model.latency.addSample(node.latencyMs);
    if (node.failureCount > 0) {
        model.failures.failureRate = static_cast<double>(node.failureCount) / 
                                      (node.successCount + node.failureCount);
    }
    
    return model;
}

// ============================================================================
// StatisticalAggregator Implementation
// ============================================================================

StatisticalAggregator& StatisticalAggregator::instance() {
    static StatisticalAggregator instance;
    return instance;
}

void StatisticalAggregator::recordExecution(const AgenticTaskNode& node) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string key = node.nodeType + ":" + node.intent;
    
    if (!m_models.count(key)) {
        m_models[key] = StatisticalNodeModel::fromCollapsedNode(node);
    } else {
        m_models[key].recordExecution(node);
    }
    
    // Update global stats
    m_totalExecutions++;
    if (node.state == AgenticTaskNode::State::FAILED) {
        m_totalFailures++;
    }
}

void StatisticalAggregator::recordCollapsedNode(const AgenticTaskNode& node) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    StatisticalNodeModel model = StatisticalNodeModel::fromCollapsedNode(node);
    std::string key = model.nodeType + ":" + model.intentPattern;
    
    if (m_models.count(key)) {
        m_models[key].merge(model);
    } else {
        m_models[key] = model;
    }
}

std::vector<std::string> StatisticalAggregator::getHotPaths(int topN) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<std::string, uint64_t>> sorted;
    for (const auto& [key, model] : m_models) {
        sorted.push_back({key, model.totalExecutions});
    }
    
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<std::string> result;
    for (size_t i = 0; i < std::min(size_t(topN), sorted.size()); ++i) {
        result.push_back(sorted[i].first);
    }
    return result;
}

std::vector<std::string> StatisticalAggregator::getAnomalousPaths(double threshold) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::string> result;
    for (const auto& [key, model] : m_models) {
        if (model.failures.failureRate > threshold) {
            result.push_back(key);
        }
    }
    return result;
}

double StatisticalAggregator::predictLatency(const std::string& pathPattern, double percentile) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_models.find(pathPattern);
    if (it == m_models.end()) {
        return -1.0; // Unknown pattern
    }
    
    if (percentile <= 0.5) return it->second.latency.p50Ms;
    if (percentile <= 0.95) return it->second.latency.p95Ms;
    return it->second.latency.p99Ms;
}

bool StatisticalAggregator::isAnomalous(const AgenticTaskNode& node, double threshold) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::string key = node.nodeType + ":" + node.intent;
    auto it = m_models.find(key);
    if (it == m_models.end()) {
        return false; // No baseline
    }
    
    // Check if latency is anomalous
    if (node.latencyMs > it->second.latency.p99Ms * threshold) {
        return true;
    }
    
    // Check if failure rate is anomalous
    if (it->second.failures.failureRate > 0.1) { // 10% threshold
        return true;
    }
    
    return false;
}

std::string StatisticalAggregator::exportStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::stringstream ss;
    ss << "{";
    ss << "\"totalExecutions\":" << m_totalExecutions << ",";
    ss << "\"totalFailures\":" << m_totalFailures << ",";
    ss << "\"models\":[";
    
    bool first = true;
    for (const auto& [key, model] : m_models) {
        if (!first) ss << ",";
        first = false;
        ss << model.toJson();
    }
    
    ss << "]}";
    return ss.str();
}

// ============================================================================
// AdaptivePolicyTuner Implementation
// ============================================================================

AdaptivePolicyTuner& AdaptivePolicyTuner::instance() {
    static AdaptivePolicyTuner instance;
    return instance;
}

RuntimeMode AdaptivePolicyTuner::recommendRuntimeMode(const std::string& taskType) const {
    auto& aggregator = StatisticalAggregator::instance();
    
    // Get hot paths for this task type
    auto hotPaths = aggregator.getHotPaths(10);
    
    // Analyze failure rates
    double totalFailureRate = 0.0;
    int pathCount = 0;
    
    for (const auto& path : hotPaths) {
        if (path.find(taskType) != std::string::npos) {
            auto anomalous = aggregator.getAnomalousPaths(0.1);
            bool isAnomalous = std::find(anomalous.begin(), anomalous.end(), path) != anomalous.end();
            if (isAnomalous) {
                totalFailureRate += 0.1;
                pathCount++;
            }
        }
    }
    
    double avgFailureRate = pathCount > 0 ? totalFailureRate / pathCount : 0.0;
    
    // Recommend mode based on failure rate
    if (avgFailureRate > 0.2) {
        return RuntimeMode::StrictLocal; // High failure rate - stay local
    } else if (avgFailureRate > 0.05) {
        return RuntimeMode::HybridControlled; // Moderate - hybrid
    } else {
        return RuntimeMode::FullyDistributed; // Low failure - distributed OK
    }
}

std::string AdaptivePolicyTuner::recommendBackend(const std::string& taskType) const {
    auto& aggregator = StatisticalAggregator::instance();
    
    // Get hot paths
    auto hotPaths = aggregator.getHotPaths(10);
    
    // Find best backend for this task type
    std::map<std::string, uint64_t> backendScores;
    
    for (const auto& path : hotPaths) {
        if (path.find(taskType) != std::string::npos) {
            // Would query actual backend usage from models
            // Simplified: return first match
            return "local_gguf";
        }
    }
    
    return "local_gguf"; // Default
}

ExecutionPolicy AdaptivePolicyTuner::generatePolicy(const std::string& taskType) const {
    ExecutionPolicy policy;
    policy.runtimeMode = recommendRuntimeMode(taskType);
    policy.preferredBackend = recommendBackend(taskType);
    policy.fallbackPolicy = FallbackPolicy::LOCAL_FIRST;
    policy.timeoutMs = 30000;
    policy.maxRetries = 2;
    
    return policy;
}

void AdaptivePolicyTuner::applyTuning(const std::string& taskType) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    ExecutionPolicy policy = generatePolicy(taskType);
    m_activePolicies[taskType] = policy;
    
    // Would apply to global policy router
    // SetGlobalRuntimeMode(policy.runtimeMode);
}

std::map<std::string, ExecutionPolicy> AdaptivePolicyTuner::getActivePolicies() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activePolicies;
}

} // namespace RawrXD
