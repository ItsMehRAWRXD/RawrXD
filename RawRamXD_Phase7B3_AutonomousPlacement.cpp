// =============================================================================
// RawRamXD_Phase7B3_AutonomousPlacement.cpp
// Implementation: Autonomous Tensor Placement with Predictive Migration
// =============================================================================

#include "RawRamXD_Phase7B3_AutonomousPlacement.hpp"
#include "RawRamXD_Phase7B2_TopologyValidated.hpp"
#include <iostream>
#include <iomanip>
#include <math>

namespace RawRamXD {

// =============================================================================
// Workload Pattern Analysis Implementation
// =============================================================================

bool WorkloadPatternAnalyzer::Initialize() {
    std::cout << "[PatternAnalyzer] Initializing..." << std::endl;
    return true;
}

void WorkloadPatternAnalyzer::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    accessHistory_.clear();
    lastAnalysis_.clear();
}

void WorkloadPatternAnalyzer::RecordAccess(uint64_t tensorId, uint64_t offset, 
                                          size_t size, bool isRead, uint32_t nodeId) {
    AccessRecord record;
    record.timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    record.offset = offset;
    record.size = size;
    record.isRead = isRead;
    record.nodeId = nodeId;
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto& history = accessHistory_[tensorId];
    history.push_back(record);
    
    // Keep only recent history
    while (history.size() > MAX_HISTORY) {
        history.pop_front();
    }
}

PatternAnalysis WorkloadPatternAnalyzer::AnalyzePattern(uint64_t tensorId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    PatternAnalysis analysis;
    analysis.detectedPattern = AccessPattern::RANDOM;
    analysis.confidence = 0.0;
    analysis.workingSetSize = 0;
    analysis.temporalLocality = 0.0;
    analysis.spatialLocality = 0.0;
    analysis.reuseRatio = 0.0;
    analysis.preferredNode = 0;
    
    auto it = accessHistory_.find(tensorId);
    if (it == accessHistory_.end() || it->second.size() < 10) {
        return analysis;
    }
    
    const auto& history = it->second;
    
    // Detect sequential pattern
    AccessPattern seqPattern = DetectSequential(history);
    if (seqPattern != AccessPattern::RANDOM) {
        analysis.detectedPattern = seqPattern;
        analysis.confidence = 0.8;
    }
    
    // Detect strided pattern
    AccessPattern stridedPattern = DetectStrided(history);
    if (stridedPattern != AccessPattern::RANDOM && analysis.confidence < 0.8) {
        analysis.detectedPattern = stridedPattern;
        analysis.confidence = 0.7;
    }
    
    // Calculate locality metrics
    analysis.temporalLocality = CalculateTemporalLocality(history);
    analysis.spatialLocality = CalculateSpatialLocality(history);
    
    // Calculate working set
    uint64_t minOffset = UINT64_MAX;
    uint64_t maxOffset = 0;
    std::unordered_map<uint64_t, uint32_t> offsetCounts;
    for (const auto& rec : history) {
        minOffset = std::min(minOffset, rec.offset);
        maxOffset = std::max(maxOffset, rec.offset + rec.size);
        offsetCounts[rec.offset / 4096]++; // Page granularity
    }
    analysis.workingSetSize = maxOffset - minOffset;
    
    // Calculate reuse ratio
    uint32_t totalAccesses = (uint32_t)history.size();
    uint32_t uniquePages = (uint32_t)offsetCounts.size();
    analysis.reuseRatio = totalAccesses > 0 ? 1.0 - ((double)uniquePages / totalAccesses) : 0.0;
    
    // Determine preferred node (most accessed)
    std::unordered_map<uint32_t, uint32_t> nodeCounts;
    for (const auto& rec : history) {
        nodeCounts[rec.nodeId]++;
    }
    uint32_t maxCount = 0;
    for (const auto& [node, count] : nodeCounts) {
        if (count > maxCount) {
            maxCount = count;
            analysis.preferredNode = node;
        }
    }
    
    // Identify hot regions
    for (const auto& [page, count] : offsetCounts) {
        if (count > totalAccesses / uniquePages * 2) { // Above average
            analysis.hotOffsets.push_back(page * 4096);
        }
    }
    
    lastAnalysis_[tensorId] = analysis;
    return analysis;
}

AccessPattern WorkloadPatternAnalyzer::DetectSequential(
    const std::deque<AccessRecord>& history) {
    if (history.size() < 3) return AccessPattern::RANDOM;
    
    uint32_t sequentialCount = 0;
    uint32_t totalCount = 0;
    
    for (size_t i = 1; i < history.size(); ++i) {
        uint64_t expectedOffset = history[i-1].offset + history[i-1].size;
        if (history[i].offset == expectedOffset) {
            sequentialCount++;
        }
        totalCount++;
    }
    
    double sequentialRatio = totalCount > 0 ? (double)sequentialCount / totalCount : 0.0;
    if (sequentialRatio > 0.8) {
        return AccessPattern::SEQUENTIAL;
    }
    
    return AccessPattern::RANDOM;
}

AccessPattern WorkloadPatternAnalyzer::DetectStrided(
    const std::deque<AccessRecord>& history) {
    if (history.size() < 4) return AccessPattern::RANDOM;
    
    // Calculate stride between consecutive accesses
    std::unordered_map<uint64_t, uint32_t> strideCounts;
    for (size_t i = 1; i < history.size(); ++i) {
        uint64_t stride = history[i].offset - history[i-1].offset;
        if (stride > 0 && stride < 1024*1024*1024) { // Reasonable stride
            strideCounts[stride]++;
        }
    }
    
    // Find most common stride
    uint64_t commonStride = 0;
    uint32_t maxCount = 0;
    for (const auto& [stride, count] : strideCounts) {
        if (count > maxCount) {
            maxCount = count;
            commonStride = stride;
        }
    }
    
    double strideRatio = history.size() > 1 ? (double)maxCount / (history.size() - 1) : 0.0;
    if (strideRatio > 0.6 && commonStride > 0) {
        return AccessPattern::STRIDED;
    }
    
    return AccessPattern::RANDOM;
}

double WorkloadPatternAnalyzer::CalculateTemporalLocality(
    const std::deque<AccessRecord>& history) {
    if (history.size() < 2) return 0.0;
    
    // Count re-accesses within short time window
    std::unordered_map<uint64_t, uint64_t> lastAccessTime;
    uint32_t reaccessCount = 0;
    
    for (const auto& rec : history) {
        uint64_t page = rec.offset / 4096;
        auto it = lastAccessTime.find(page);
        if (it != lastAccessTime.end()) {
            uint64_t timeDiff = rec.timestamp - it->second;
            if (timeDiff < 1000000000) { // Within 1 second
                reaccessCount++;
            }
        }
        lastAccessTime[page] = rec.timestamp;
    }
    
    return history.size() > 0 ? (double)reaccessCount / history.size() : 0.0;
}

double WorkloadPatternAnalyzer::CalculateSpatialLocality(
    const std::deque<AccessRecord>& history) {
    if (history.size() < 2) return 0.0;
    
    // Count accesses within same cache line
    uint32_t spatialCount = 0;
    uint64_t lastPage = history[0].offset / 64; // Cache line size
    
    for (size_t i = 1; i < history.size(); ++i) {
        uint64_t page = history[i].offset / 64;
        if (page == lastPage || page == lastPage + 1 || page == lastPage - 1) {
            spatialCount++;
        }
        lastPage = page;
    }
    
    return history.size() > 1 ? (double)spatialCount / (history.size() - 1) : 0.0;
}

WorkloadPatternAnalyzer::AccessPrediction WorkloadPatternAnalyzer::PredictNextAccess(
    uint64_t tensorId) {
    AccessPrediction prediction;
    prediction.predictedOffset = 0;
    prediction.confidence = 0.0;
    prediction.predictedTimeNs = 0;
    prediction.predictedNode = 0;
    
    auto analysis = AnalyzePattern(tensorId);
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = accessHistory_.find(tensorId);
    if (it == accessHistory_.end() || it->second.empty()) {
        return prediction;
    }
    
    const auto& lastRecord = it->second.back();
    
    switch (analysis.detectedPattern) {
        case AccessPattern::SEQUENTIAL:
            prediction.predictedOffset = lastRecord.offset + lastRecord.size;
            prediction.confidence = 0.8;
            break;
        case AccessPattern::STRIDED:
            // Use average stride
            if (it->second.size() >= 2) {
                uint64_t stride = lastRecord.offset - it->second[it->second.size()-2].offset;
                prediction.predictedOffset = lastRecord.offset + stride;
                prediction.confidence = 0.7;
            }
            break;
        case AccessPattern::REPEATED:
            // Predict hot region
            if (!analysis.hotOffsets.empty()) {
                prediction.predictedOffset = analysis.hotOffsets[0];
                prediction.confidence = 0.6;
            }
            break;
        default:
            prediction.confidence = 0.3;
            break;
    }
    
    prediction.predictedNode = analysis.preferredNode;
    prediction.predictedTimeNs = lastRecord.timestamp + 1000000; // +1ms
    
    return prediction;
}

double WorkloadPatternAnalyzer::GetHotnessScore(uint64_t tensorId) {
    auto analysis = AnalyzePattern(tensorId);
    return analysis.reuseRatio * analysis.temporalLocality;
}

bool WorkloadPatternAnalyzer::DetectPhaseChange(uint64_t tensorId) {
    auto currentAnalysis = AnalyzePattern(tensorId);
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = lastAnalysis_.find(tensorId);
    if (it == lastAnalysis_.end()) {
        lastAnalysis_[tensorId] = currentAnalysis;
        return false;
    }
    
    const auto& lastAnalysis = it->second;
    
    // Check for significant change
    bool patternChanged = currentAnalysis.detectedPattern != lastAnalysis.detectedPattern;
    bool localityChanged = std::abs(currentAnalysis.temporalLocality - lastAnalysis.temporalLocality) > 0.3;
    bool nodeChanged = currentAnalysis.preferredNode != lastAnalysis.preferredNode;
    
    lastAnalysis_[tensorId] = currentAnalysis;
    
    return patternChanged || localityChanged || nodeChanged;
}

// =============================================================================
// Predictive Migration Engine Implementation
// =============================================================================

bool PredictiveMigrationEngine::Initialize(MigrationEconomicsEngine* economics,
                                           WorkloadPatternAnalyzer* analyzer) {
    economics_ = economics;
    analyzer_ = analyzer;
    std::cout << "[MigrationEngine] Initializing..." << std::endl;
    return true;
}

void PredictiveMigrationEngine::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    triggerHistory_.clear();
}

std::vector<MigrationTriggerEvent> PredictiveMigrationEngine::EvaluateTriggers(
    const std::vector<uint64_t>& tensorIds,
    const FabricTopology& topology) {
    
    std::vector<MigrationTriggerEvent> triggers;
    
    for (uint64_t tensorId : tensorIds) {
        // Check access pattern shift
        if (CheckAccessPatternShift(tensorId)) {
            auto analysis = analyzer_->AnalyzePattern(tensorId);
            
            MigrationTriggerEvent event;
            event.trigger = MigrationTrigger::ACCESS_PATTERN_CHANGE;
            event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            event.tensorId = tensorId;
            event.srcNode = analysis.preferredNode; // Current
            event.dstNode = analysis.preferredNode;   // Will be updated
            event.confidence = analysis.confidence;
            event.reasoning = "Access pattern changed to " + 
                std::to_string((int)analysis.detectedPattern);
            
            triggers.push_back(event);
        }
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    triggerHistory_.insert(triggerHistory_.end(), triggers.begin(), triggers.end());
    
    return triggers;
}

bool PredictiveMigrationEngine::CheckCapacityPressure(uint32_t nodeId, 
                                                       const FabricTopology& topology) {
    // Check if node is near capacity
    for (const auto& node : topology.nodes) {
        if (node.deviceId == nodeId) {
            double usageRatio = (double)node.currentUsage / node.budget;
            return usageRatio > 0.9; // 90% threshold
        }
    }
    return false;
}

bool PredictiveMigrationEngine::CheckAccessPatternShift(uint64_t tensorId) {
    return analyzer_->DetectPhaseChange(tensorId);
}

bool PredictiveMigrationEngine::CheckThermalThrottle(uint32_t nodeId) {
    // Would query thermal sensors in real implementation
    return false;
}

bool PredictiveMigrationEngine::CheckBandwidthOptimization(uint64_t tensorId,
                                                          const FabricTopology& topology) {
    auto analysis = analyzer_->AnalyzePattern(tensorId);
    
    // Check if there's a better node for this pattern
    if (analysis.detectedPattern == AccessPattern::SEQUENTIAL) {
        // Sequential patterns benefit from high bandwidth
        // Check if current node has lower bandwidth than alternatives
        return false; // Simplified
    }
    
    return false;
}

bool PredictiveMigrationEngine::CheckLoadBalancing(const FabricTopology& topology) {
    // Check node utilization imbalance
    double avgUsage = 0.0;
    for (const auto& node : topology.nodes) {
        avgUsage += (double)node.currentUsage / node.budget;
    }
    avgUsage /= topology.nodes.size();
    
    for (const auto& node : topology.nodes) {
        double nodeUsage = (double)node.currentUsage / node.budget;
        if (std::abs(nodeUsage - avgUsage) > 0.3) { // 30% deviation
            return true;
        }
    }
    
    return false;
}

std::vector<PredictiveMigrationEngine::PrefetchDecision> 
PredictiveMigrationEngine::GeneratePrefetchList(uint64_t lookaheadMs) {
    std::vector<PrefetchDecision> prefetchList;
    
    // Would iterate over tensors and predict future accesses
    // Simplified implementation
    
    return prefetchList;
}

bool PredictiveMigrationEngine::ExecuteMigration(uint64_t tensorId, uint32_t dstNode) {
    std::cout << "[MigrationEngine] Executing migration: tensor " << tensorId
              << " -> node " << dstNode << std::endl;
    
    // Would perform actual migration in real implementation
    return true;
}

std::vector<MigrationTriggerEvent> PredictiveMigrationEngine::GetTriggerHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return triggerHistory_;
}

// =============================================================================
// Placement Policy Optimizer Implementation
// =============================================================================

PlacementPolicy PlacementPolicyOptimizer::GetDefaultPolicy() {
    PlacementPolicy policy;
    policy.name = "default";
    policy.memoryWeight = 0.25;
    policy.bandwidthWeight = 0.20;
    policy.latencyWeight = 0.25;
    policy.thermalWeight = 0.10;
    policy.computeWeight = 0.10;
    policy.residencyWeight = 0.10;
    policy.migrationThreshold = 0.5;
    policy.replicationFactor = 1;
    policy.enablePrefetch = false;
    policy.prefetchDistance = 0;
    return policy;
}

PlacementPolicy PlacementPolicyOptimizer::GetLatencyOptimizedPolicy() {
    PlacementPolicy policy = GetDefaultPolicy();
    policy.name = "latency_optimized";
    policy.latencyWeight = 0.50;
    policy.memoryWeight = 0.15;
    policy.bandwidthWeight = 0.15;
    policy.migrationThreshold = 0.3; // More aggressive migration
    policy.enablePrefetch = true;
    policy.prefetchDistance = 1024 * 1024; // 1MB
    return policy;
}

PlacementPolicy PlacementPolicyOptimizer::GetThroughputOptimizedPolicy() {
    PlacementPolicy policy = GetDefaultPolicy();
    policy.name = "throughput_optimized";
    policy.bandwidthWeight = 0.40;
    policy.memoryWeight = 0.20;
    policy.latencyWeight = 0.15;
    policy.replicationFactor = 2; // Replicate for throughput
    return policy;
}

PlacementPolicy PlacementPolicyOptimizer::GetBalancedPolicy() {
    return GetDefaultPolicy();
}

PlacementPolicy PlacementPolicyOptimizer::GetMemoryOptimizedPolicy() {
    PlacementPolicy policy = GetDefaultPolicy();
    policy.name = "memory_optimized";
    policy.memoryWeight = 0.50;
    policy.migrationThreshold = 0.8; // Less migration
    policy.residencyWeight = 0.20;
    return policy;
}

bool PlacementPolicyOptimizer::Initialize() {
    activePolicy_ = GetDefaultPolicy();
    std::cout << "[PolicyOptimizer] Initialized with policy: " << activePolicy_.name << std::endl;
    return true;
}

void PlacementPolicyOptimizer::Shutdown() {
    metricsHistory_.clear();
}

PlacementPolicy PlacementPolicyOptimizer::OptimizePolicy(
    const std::vector<PatternAnalysis>& patterns,
    const FabricTopology& topology) {
    
    // Analyze workload characteristics
    uint32_t sequentialCount = 0;
    uint32_t randomCount = 0;
    double avgTemporalLocality = 0.0;
    
    for (const auto& pattern : patterns) {
        if (pattern.detectedPattern == AccessPattern::SEQUENTIAL) {
            sequentialCount++;
        } else if (pattern.detectedPattern == AccessPattern::RANDOM) {
            randomCount++;
        }
        avgTemporalLocality += pattern.temporalLocality;
    }
    
    if (!patterns.empty()) {
        avgTemporalLocality /= patterns.size();
    }
    
    // Select policy based on characteristics
    if (sequentialCount > randomCount) {
        return GetThroughputOptimizedPolicy();
    } else if (avgTemporalLocality > 0.7) {
        return GetLatencyOptimizedPolicy();
    } else {
        return GetBalancedPolicy();
    }
}

PlacementPolicyOptimizer::PolicyMetrics PlacementPolicyOptimizer::EvaluatePolicy(
    const PlacementPolicy& policy) {
    PolicyMetrics metrics;
    metrics.avgPlacementScore = 0.0;
    metrics.migrationRate = 0.0;
    metrics.cacheHitRate = 0.0;
    metrics.bandwidthUtilization = 0.0;
    metrics.thermalEfficiency = 0.0;
    metrics.overallThroughput = 0.0;
    
    // Would evaluate based on actual measurements
    // Simplified implementation
    
    return metrics;
}

void PlacementPolicyOptimizer::UpdatePolicyFromFeedback(const PolicyMetrics& metrics) {
    metricsHistory_.push_back(metrics);
    
    // Auto-tune based on history
    if (metricsHistory_.size() > 10) {
        // Calculate trend
        double avgThroughput = 0.0;
        for (const auto& m : metricsHistory_) {
            avgThroughput += m.overallThroughput;
        }
        avgThroughput /= metricsHistory_.size();
        
        // Adjust weights if needed
        if (metrics.overallThroughput < avgThroughput * 0.9) {
            // Performance degraded, try different weights
            activePolicy_.bandwidthWeight += 0.05;
            activePolicy_.latencyWeight += 0.05;
            activePolicy_.memoryWeight -= 0.10;
        }
    }
}

// =============================================================================
// Real-Time Adaptation Controller Implementation
// =============================================================================

bool RealTimeAdaptationController::Initialize(PredictiveMigrationEngine* migration,
                                               PlacementPolicyOptimizer* policy,
                                               CostModelScheduler* scheduler) {
    migration_ = migration;
    policy_ = policy;
    scheduler_ = scheduler;
    std::cout << "[AdaptationController] Initialized" << std::endl;
    return true;
}

void RealTimeAdaptationController::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    adaptationHistory_.clear();
}

void RealTimeAdaptationController::RunAdaptationCycle() {
    // This would be called periodically
    // Simplified implementation
}

AdaptationDecision RealTimeAdaptationController::ProcessTensor(uint64_t tensorId) {
    AdaptationDecision decision;
    decision.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    decision.action = AdaptationDecision::Action::NONE;
    decision.tensorId = tensorId;
    decision.srcNode = 0;
    decision.dstNode = 0;
    decision.confidence = 0.0;
    decision.reasoning = "No action needed";
    
    // Would evaluate and make decision based on patterns
    // Simplified implementation
    
    return decision;
}

std::vector<AdaptationDecision> RealTimeAdaptationController::RebalanceNodes() {
    std::vector<AdaptationDecision> decisions;
    
    // Would analyze node utilization and generate migration decisions
    // Simplified implementation
    
    return decisions;
}

std::vector<AdaptationDecision> RealTimeAdaptationController::HandleEmergency(uint32_t nodeId) {
    std::vector<AdaptationDecision> decisions;
    
    // Would generate emergency migrations
    // Simplified implementation
    
    return decisions;
}

std::vector<AdaptationDecision> RealTimeAdaptationController::GetAdaptationHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return adaptationHistory_;
}

RealTimeAdaptationController::AdaptationMetrics RealTimeAdaptationController::GetMetrics() const {
    AdaptationMetrics metrics;
    metrics.decisionsPerSecond = decisionCount_.load() / 60; // Assuming 60s window
    metrics.avgDecisionLatencyMs = totalLatencyNs_.load() / (double)decisionCount_.load() / 1e6;
    metrics.successRate = 0.95; // Placeholder
    metrics.totalMigrations = 0;
    metrics.totalPrefetches = 0;
    metrics.throughputImprovement = 0.0;
    
    return metrics;
}

// =============================================================================
// Autonomous Placement Report Generator Implementation
// =============================================================================

std::string AutonomousPlacementReportGenerator::EscapeJsonString(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

std::string AutonomousPlacementReportGenerator::PatternToJson(const PatternAnalysis& pattern) {
    std::stringstream ss;
    ss << "{\n";
    ss << "      \"detected_pattern\": " << (int)pattern.detectedPattern << ",\n";
    ss << "      \"confidence\": " << pattern.confidence << ",\n";
    ss << "      \"working_set_size\": " << pattern.workingSetSize << ",\n";
    ss << "      \"temporal_locality\": " << pattern.temporalLocality << ",\n";
    ss << "      \"spatial_locality\": " << pattern.spatialLocality << ",\n";
    ss << "      \"reuse_ratio\": " << pattern.reuseRatio << ",\n";
    ss << "      \"preferred_node\": " << pattern.preferredNode << "\n";
    ss << "    }";
    return ss.str();
}

std::string AutonomousPlacementReportGenerator::TriggerToJson(
    const MigrationTriggerEvent& trigger) {
    std::stringstream ss;
    ss << "{\n";
    ss << "      \"trigger\": " << (int)trigger.trigger << ",\n";
    ss << "      \"timestamp\": " << trigger.timestamp << ",\n";
    ss << "      \"tensor_id\": " << trigger.tensorId << ",\n";
    ss << "      \"src_node\": " << trigger.srcNode << ",\n";
    ss << "      \"dst_node\": " << trigger.dstNode << ",\n";
    ss << "      \"confidence\": " << trigger.confidence << ",\n";
    ss << "      \"reasoning\": \"" << EscapeJsonString(trigger.reasoning) << "\"\n";
    ss << "    }";
    return ss.str();
}

std::string AutonomousPlacementReportGenerator::DecisionToJson(
    const AdaptationDecision& decision) {
    std::stringstream ss;
    ss << "{\n";
    ss << "      \"timestamp\": " << decision.timestamp << ",\n";
    ss << "      \"action\": " << (int)decision.action << ",\n";
    ss << "      \"tensor_id\": " << decision.tensorId << ",\n";
    ss << "      \"src_node\": " << decision.srcNode << ",\n";
    ss << "      \"dst_node\": " << decision.dstNode << ",\n";
    ss << "      \"confidence\": " << decision.confidence << ",\n";
    ss << "      \"reasoning\": \"" << EscapeJsonString(decision.reasoning) << "\"\n";
    ss << "    }";
    return ss.str();
}

std::string AutonomousPlacementReportGenerator::PolicyToJson(const PlacementPolicy& policy) {
    std::stringstream ss;
    ss << "{\n";
    ss << "      \"name\": \"" << EscapeJsonString(policy.name) << "\",\n";
    ss << "      \"memory_weight\": " << policy.memoryWeight << ",\n";
    ss << "      \"bandwidth_weight\": " << policy.bandwidthWeight << ",\n";
    ss << "      \"latency_weight\": " << policy.latencyWeight << ",\n";
    ss << "      \"thermal_weight\": " << policy.thermalWeight << ",\n";
    ss << "      \"compute_weight\": " << policy.computeWeight << ",\n";
    ss << "      \"residency_weight\": " << policy.residencyWeight << ",\n";
    ss << "      \"migration_threshold\": " << policy.migrationThreshold << ",\n";
    ss << "      \"replication_factor\": " << policy.replicationFactor << ",\n";
    ss << "      \"enable_prefetch\": " << (policy.enablePrefetch ? "true" : "false") << ",\n";
    ss << "      \"prefetch_distance\": " << policy.prefetchDistance << "\n";
    ss << "    }";
    return ss.str();
}

std::string AutonomousPlacementReportGenerator::MetricsToJson(
    const RealTimeAdaptationController::AdaptationMetrics& metrics) {
    std::stringstream ss;
    ss << "{\n";
    ss << "      \"decisions_per_second\": " << metrics.decisionsPerSecond << ",\n";
    ss << "      \"avg_decision_latency_ms\": " << metrics.avgDecisionLatencyMs << ",\n";
    ss << "      \"success_rate\": " << metrics.successRate << ",\n";
    ss << "      \"total_migrations\": " << metrics.totalMigrations << ",\n";
    ss << "      \"total_prefetches\": " << metrics.totalPrefetches << ",\n";
    ss << "      \"throughput_improvement\": " << metrics.throughputImprovement << "\n";
    ss << "    }";
    return ss.str();
}

bool AutonomousPlacementReportGenerator::GenerateReport(
    const std::vector<AdaptationDecision>& decisions,
    const PlacementPolicy& policy,
    const RealTimeAdaptationController::AdaptationMetrics& metrics,
    const std::string& filename) {
    
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    file << "{\n";
    file << "  \"version\": \"1.0\",\n";
    file << "  \"timestamp\": " << now << ",\n";
    file << "  \"policy\": " << PolicyToJson(policy) << ",\n";
    file << "  \"metrics\": " << MetricsToJson(metrics) << ",\n";
    file << "  \"decisions\": [\n";
    
    for (size_t i = 0; i < decisions.size(); ++i) {
        file << DecisionToJson(decisions[i]);
        if (i < decisions.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    std::cout << "[Report] Generated autonomous placement report: " << filename << std::endl;
    return true;
}

bool AutonomousPlacementReportGenerator::GenerateFullReport(
    const std::vector<PatternAnalysis>& patterns,
    const std::vector<MigrationTriggerEvent>& triggers,
    const std::vector<AdaptationDecision>& decisions,
    const PlacementPolicy& policy,
    const RealTimeAdaptationController::AdaptationMetrics& metrics,
    const std::string& filename) {
    
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    file << "{\n";
    file << "  \"version\": \"1.0\",\n";
    file << "  \"timestamp\": " << now << ",\n";
    file << "  \"phase\": \"7B.3\",\n";
    file << "  \"name\": \"Autonomous Placement Engine\",\n";
    file << "  \"policy\": " << PolicyToJson(policy) << ",\n";
    file << "  \"metrics\": " << MetricsToJson(metrics) << ",\n";
    
    // Patterns
    file << "  \"patterns\": [\n";
    for (size_t i = 0; i < patterns.size(); ++i) {
        file << PatternToJson(patterns[i]);
        if (i < patterns.size() - 1) file << ",";
        file << "\n";
    }
    file << "  ],\n";
    
    // Triggers
    file << "  \"triggers\": [\n";
    for (size_t i = 0; i < triggers.size(); ++i) {
        file << TriggerToJson(triggers[i]);
        if (i < triggers.size() - 1) file << ",";
        file << "\n";
    }
    file << "  ],\n";
    
    // Decisions
    file << "  \"decisions\": [\n";
    for (size_t i = 0; i < decisions.size(); ++i) {
        file << DecisionToJson(decisions[i]);
        if (i < decisions.size() - 1) file << ",";
        file << "\n";
    }
    file << "  ]\n";
    
    file << "}\n";
    
    std::cout << "[Report] Generated full autonomous placement report: " << filename << std::endl;
    return true;
}

// =============================================================================
// Autonomous Placement Controller Implementation
// =============================================================================

AutonomousPlacementController& AutonomousPlacementController::Instance() {
    static AutonomousPlacementController instance;
    return instance;
}

bool AutonomousPlacementController::Initialize() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawRamXD Phase 7B.3: Autonomous Placement" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Initialize subsystems
    patternAnalyzer_ = std::make_unique<WorkloadPatternAnalyzer>();
    patternAnalyzer_->Initialize();
    
    migrationEngine_ = std::make_unique<PredictiveMigrationEngine>();
    // Note: Would need proper initialization with economics engine
    // migrationEngine_->Initialize(...);
    
    policyOptimizer_ = std::make_unique<PlacementPolicyOptimizer>();
    policyOptimizer_->Initialize();
    
    adaptationController_ = std::make_unique<RealTimeAdaptationController>();
    // Note: Would need proper initialization
    // adaptationController_->Initialize(...);
    
    std::cout << "Autonomous placement controller initialized" << std::endl;
    return true;
}

void AutonomousPlacementController::Shutdown() {
    StopAutonomousMode();
    
    if (adaptationController_) adaptationController_->Shutdown();
    if (policyOptimizer_) policyOptimizer_->Shutdown();
    if (migrationEngine_) migrationEngine_->Shutdown();
    if (patternAnalyzer_) patternAnalyzer_->Shutdown();
}

bool AutonomousPlacementController::StartAutonomousMode() {
    if (isRunning_) return false;
    
    isRunning_ = true;
    adaptationThread_ = std::thread(&AutonomousPlacementController::AdaptationLoop, this);
    
    std::cout << "[Autonomous] Started autonomous mode" << std::endl;
    return true;
}

void AutonomousPlacementController::StopAutonomousMode() {
    isRunning_ = false;
    if (adaptationThread_.joinable()) {
        adaptationThread_.join();
    }
    std::cout << "[Autonomous] Stopped autonomous mode" << std::endl;
}

void AutonomousPlacementController::AdaptationLoop() {
    while (isRunning_) {
        // Run adaptation cycle
        if (adaptationController_) {
            adaptationController_->RunAdaptationCycle();
        }
        
        // Sleep between cycles
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

AdaptationDecision AutonomousPlacementController::PlaceTensor(uint64_t tensorId, size_t size) {
    AdaptationDecision decision;
    decision.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    decision.tensorId = tensorId;
    decision.action = AdaptationDecision::Action::NONE;
    decision.confidence = 0.0;
    decision.reasoning = "Default placement";
    
    // Would use scheduler to select optimal node
    // Simplified: place on node 0
    decision.dstNode = 0;
    
    std::cout << "[Autonomous] Placed tensor " << tensorId << " (" << (size / (1024*1024)) 
              << " MB) on node " << decision.dstNode << std::endl;
    
    return decision;
}

bool AutonomousPlacementController::TriggerMigration(uint64_t tensorId, uint32_t dstNode) {
    if (!migrationEngine_) return false;
    
    std::cout << "[Autonomous] Triggering migration: tensor " << tensorId 
              << " -> node " << dstNode << std::endl;
    
    return migrationEngine_->ExecuteMigration(tensorId, dstNode);
}

bool AutonomousPlacementController::UpdatePolicy(const PlacementPolicy& policy) {
    if (!policyOptimizer_) return false;
    
    policyOptimizer_->SetActivePolicy(policy);
    std::cout << "[Autonomous] Updated policy to: " << policy.name << std::endl;
    
    return true;
}

bool AutonomousPlacementController::GeneratePlacementReport(const std::string& filename) {
    AutonomousPlacementReportGenerator generator;
    
    std::vector<AdaptationDecision> decisions;
    if (adaptationController_) {
        decisions = adaptationController_->GetAdaptationHistory();
    }
    
    PlacementPolicy policy;
    if (policyOptimizer_) {
        policy = policyOptimizer_->GetActivePolicy();
    }
    
    RealTimeAdaptationController::AdaptationMetrics metrics;
    if (adaptationController_) {
        metrics = adaptationController_->GetMetrics();
    }
    
    return generator.GenerateReport(decisions, policy, metrics, filename);
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

bool RawRamXD_Autonomous_Initialize() {
    return AutonomousPlacementController::Instance().Initialize();
}

void RawRamXD_Autonomous_Shutdown() {
    AutonomousPlacementController::Instance().Shutdown();
}

bool RawRamXD_Autonomous_Start() {
    return AutonomousPlacementController::Instance().StartAutonomousMode();
}

void RawRamXD_Autonomous_Stop() {
    AutonomousPlacementController::Instance().StopAutonomousMode();
}

uint64_t RawRamXD_Autonomous_PlaceTensor(size_t size, uint32_t preferredNode) {
    // Generate tensor ID
    static std::atomic<uint64_t> nextId{1};
    uint64_t tensorId = nextId.fetch_add(1);
    
    AutonomousPlacementController::Instance().PlaceTensor(tensorId, size);
    return tensorId;
}

bool RawRamXD_Autonomous_Migrate(uint64_t tensorId, uint32_t dstNode) {
    return AutonomousPlacementController::Instance().TriggerMigration(tensorId, dstNode);
}

bool RawRamXD_Autonomous_SetPolicy(const char* policyName) {
    PlacementPolicy policy;
    std::string name(policyName);
    
    if (name == "latency_optimized") {
        policy = PlacementPolicyOptimizer::GetLatencyOptimizedPolicy();
    } else if (name == "throughput_optimized") {
        policy = PlacementPolicyOptimizer::GetThroughputOptimizedPolicy();
    } else if (name == "memory_optimized") {
        policy = PlacementPolicyOptimizer::GetMemoryOptimizedPolicy();
    } else {
        policy = PlacementPolicyOptimizer::GetBalancedPolicy();
    }
    
    return AutonomousPlacementController::Instance().UpdatePolicy(policy);
}

bool RawRamXD_Autonomous_SaveReport(const char* filename) {
    return AutonomousPlacementController::Instance().GeneratePlacementReport(filename);
}

} // extern "C"

} // namespace RawRamXD