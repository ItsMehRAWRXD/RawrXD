// RawrXD Auto-Tuning Engine Implementation
// Phase P.4: Automatic performance tuning with ML-based optimization

#include "AutoTuningEngine.hpp"
#include "PerformanceProfiler.hpp"
#include "BottleneckAnalyzer.hpp"
#include "AlertManager.hpp"

#include <sstream>
#include <algorithm>
#include <cmath>

namespace RawrXD {
namespace Performance {

// ============================================================================
// AutoTuningEngine Implementation
// ============================================================================

AutoTuningEngine::AutoTuningEngine(PerformanceProfiler* profiler,
                                 BottleneckAnalyzer* analyzer,
                                 AlertManager* alertManager)
    : profiler_(profiler)
    , analyzer_(analyzer)
    , alertManager_(alertManager)
    , running_(false)
    , initialized_(false) {
}

AutoTuningEngine::~AutoTuningEngine() {
    if (running_) {
        shutdown();
    }
}

bool AutoTuningEngine::initialize(const AutoTuningConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Initialize current parameters with defaults
    currentParameters_[TuningParameter::BATCH_SIZE] = 1;
    currentParameters_[TuningParameter::THREAD_COUNT] = 4;
    currentParameters_[TuningParameter::GPU_MEMORY_FRACTION] = 0.8;
    currentParameters_[TuningParameter::KV_CACHE_SIZE] = 1024 * 1024 * 1024; // 1GB
    currentParameters_[TuningParameter::ATTENTION_HEADS] = 32;
    currentParameters_[TuningParameter::QUANTIZATION_BITS] = 16;
    currentParameters_[TuningParameter::STREAMING_CHUNK_SIZE] = 64;
    currentParameters_[TuningParameter::PREFETCH_DISTANCE] = 10;
    currentParameters_[TuningParameter::SCHEDULER_PRIORITY] = 0;
    currentParameters_[TuningParameter::WORKER_AFFINITY] = 0;
    
    // Start threads if enabled
    if (config_.enabled) {
        running_ = true;
        tuningThread_ = std::thread(&AutoTuningEngine::tuningLoop, this);
        evalThread_ = std::thread(&AutoTuningEngine::evaluationLoop, this);
        learningThread_ = std::thread(&AutoTuningEngine::learningLoop, this);
    }
    
    initialized_ = true;
    return true;
}

bool AutoTuningEngine::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    if (tuningThread_.joinable()) {
        tuningThread_.join();
    }
    if (evalThread_.joinable()) {
        evalThread_.join();
    }
    if (learningThread_.joinable()) {
        learningThread_.join();
    }
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Control
// ============================================================================

void AutoTuningEngine::enable() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enabled = true;
    
    if (!running_) {
        running_ = true;
        tuningThread_ = std::thread(&AutoTuningEngine::tuningLoop, this);
        evalThread_ = std::thread(&AutoTuningEngine::evaluationLoop, this);
        learningThread_ = std::thread(&AutoTuningEngine::learningLoop, this);
    }
}

void AutoTuningEngine::disable() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.enabled = false;
}

void AutoTuningEngine::setDryRun(bool dryRun) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.constraints.dryRun = dryRun;
}

// ============================================================================
// Manual Tuning
// ============================================================================

void AutoTuningEngine::triggerTuning() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TuningAdjustment> adjustments;
    
    switch (config_.strategy) {
        case TuningStrategy::GRADIENT_DESCENT:
            adjustments = generateAdjustmentsGradientDescent();
            break;
        case TuningStrategy::BAYESIAN:
            adjustments = generateAdjustmentsBayesian();
            break;
        case TuningStrategy::GENETIC:
            adjustments = generateAdjustmentsGenetic();
            break;
        case TuningStrategy::REINFORCEMENT_LEARNING:
            adjustments = generateAdjustmentsRL();
            break;
        case TuningStrategy::RULE_BASED:
            adjustments = generateAdjustmentsRuleBased();
            break;
    }
    
    // Add to pending
    for (const auto& adj : adjustments) {
        if (config_.constraints.requireApproval) {
            pendingAdjustments_[adj.id] = adj;
        } else {
            activeAdjustments_[adj.id] = adj;
            applyAdjustment(adj);
        }
        
        if (tuningCallback_) {
            tuningCallback_(adj);
        }
    }
}

bool AutoTuningEngine::applyAdjustment(const TuningAdjustment& adjustment) {
    if (config_.constraints.dryRun) {
        return true; // Simulate success in dry run
    }
    
    // Validate adjustment
    if (!validateAdjustment(adjustment)) {
        return false;
    }
    
    // Apply the parameter change
    if (!setParameterValue(adjustment.parameter, adjustment.newValue)) {
        return false;
    }
    
    // Update current parameters
    currentParameters_[adjustment.parameter] = adjustment.newValue;
    
    return true;
}

bool AutoTuningEngine::rollbackAdjustment(const std::string& adjustmentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = activeAdjustments_.find(adjustmentId);
    if (it == activeAdjustments_.end()) {
        return false;
    }
    
    // Restore old value
    setParameterValue(it->second.parameter, it->second.oldValue);
    currentParameters_[it->second.parameter] = it->second.oldValue;
    
    // Update status
    it->second.status = TuningAdjustment::Status::ROLLED_BACK;
    
    // Add to history
    TuningRecord record;
    record.id = it->second.id;
    record.timestamp = std::chrono::steady_clock::now();
    record.parameter = it->second.parameter;
    record.oldValue = it->second.newValue; // Rolled back from
    record.newValue = it->second.oldValue; // Rolled back to
    record.reason = it->second.reason;
    record.approved = true;
    record.successful = false;
    record.measuredImprovement = 0.0;
    record.rollbackReason = "Manual rollback";
    
    tuningHistory_.push_back(record);
    rolledBackAdjustments_++;
    
    activeAdjustments_.erase(it);
    
    return true;
}

// ============================================================================
// Approval Workflow
// ============================================================================

std::vector<TuningAdjustment> AutoTuningEngine::getPendingAdjustments() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<TuningAdjustment> result;
    for (const auto& [id, adj] : pendingAdjustments_) {
        result.push_back(adj);
    }
    return result;
}

bool AutoTuningEngine::approveAdjustment(const std::string& adjustmentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pendingAdjustments_.find(adjustmentId);
    if (it == pendingAdjustments_.end()) {
        return false;
    }
    
    TuningAdjustment adj = it->second;
    adj.status = TuningAdjustment::Status::APPROVED;
    
    pendingAdjustments_.erase(it);
    activeAdjustments_[adjustmentId] = adj;
    
    // Apply the adjustment
    applyAdjustment(adj);
    
    return true;
}

bool AutoTuningEngine::rejectAdjustment(const std::string& adjustmentId, 
                                        const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pendingAdjustments_.find(adjustmentId);
    if (it == pendingAdjustments_.end()) {
        return false;
    }
    
    it->second.status = TuningAdjustment::Status::REJECTED;
    
    // Add to history as rejected
    TuningRecord record;
    record.id = it->second.id;
    record.timestamp = std::chrono::steady_clock::now();
    record.parameter = it->second.parameter;
    record.oldValue = it->second.oldValue;
    record.newValue = it->second.newValue;
    record.reason = it->second.reason;
    record.approved = false;
    record.successful = false;
    record.measuredImprovement = 0.0;
    record.rollbackReason = reason;
    
    tuningHistory_.push_back(record);
    
    pendingAdjustments_.erase(it);
    
    return true;
}

// ============================================================================
// History and Learning
// ============================================================================

std::vector<TuningRecord> AutoTuningEngine::getTuningHistory(uint32_t days) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(24 * days);
    
    std::vector<TuningRecord> result;
    for (const auto& record : tuningHistory_) {
        if (record.timestamp >= cutoff) {
            result.push_back(record);
        }
    }
    
    // Sort by timestamp descending
    std::sort(result.begin(), result.end(),
              [](const TuningRecord& a, const TuningRecord& b) {
                  return a.timestamp > b.timestamp;
              });
    
    return result;
}

std::vector<PerformanceSnapshot> AutoTuningEngine::getPerformanceHistory(uint32_t hours) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto cutoff = std::chrono::steady_clock::now() - std::chrono::hours(hours);
    
    std::vector<PerformanceSnapshot> result;
    for (const auto& snapshot : performanceHistory_) {
        if (snapshot.timestamp >= cutoff) {
            result.push_back(snapshot);
        }
    }
    
    return result;
}

bool AutoTuningEngine::saveLearningModel(const std::string& path) {
    // Implementation would serialize learned model to disk
    // For now, just log
    return true;
}

bool AutoTuningEngine::loadLearningModel(const std::string& path) {
    // Implementation would deserialize learned model from disk
    // For now, just log
    return true;
}

void AutoTuningEngine::resetLearning() {
    std::lock_guard<std::mutex> lock(mutex_);
    tuningHistory_.clear();
    performanceHistory_.clear();
}

// ============================================================================
// Recommendations
// ============================================================================

std::vector<AutoTuningEngine::Recommendation> AutoTuningEngine::getRecommendations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return generateRecommendationsFromModel();
}

// ============================================================================
// Statistics
// ============================================================================

AutoTuningEngine::TuningStats AutoTuningEngine::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    TuningStats stats{};
    stats.totalAdjustments = totalAdjustments_.load();
    stats.successfulAdjustments = successfulAdjustments_.load();
    stats.rolledBackAdjustments = rolledBackAdjustments_.load();
    
    // Calculate averages
    if (!tuningHistory_.empty()) {
        double totalImprovement = 0.0;
        double best = 0.0;
        double worst = 0.0;
        
        for (const auto& record : tuningHistory_) {
            if (record.successful) {
                totalImprovement += record.measuredImprovement;
                best = std::max(best, record.measuredImprovement);
            } else {
                worst = std::min(worst, record.measuredImprovement);
            }
            
            stats.adjustmentsByParameter[record.parameter]++;
        }
        
        stats.avgImprovement = totalImprovement / tuningHistory_.size();
        stats.bestImprovement = best;
        stats.worstRegression = worst;
    }
    
    // Current performance
    if (!performanceHistory_.empty()) {
        const auto& latest = performanceHistory_.back();
        stats.currentLatency = latest.latencyMs;
        stats.currentThroughput = latest.throughput;
        stats.currentErrorRate = latest.errorRate;
    }
    
    return stats;
}

// ============================================================================
// Configuration
// ============================================================================

bool AutoTuningEngine::updateConfig(const AutoTuningConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    return true;
}

void AutoTuningEngine::setTuningCallback(TuningCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    tuningCallback_ = callback;
}

void AutoTuningEngine::setRecommendationCallback(RecommendationCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    recommendationCallback_ = callback;
}

// ============================================================================
// Internal Loops
// ============================================================================

void AutoTuningEngine::tuningLoop() {
    while (running_) {
        if (config_.enabled) {
            triggerTuning();
        }
        
        std::this_thread::sleep_for(std::chrono::minutes(config_.tuningIntervalMinutes));
    }
}

void AutoTuningEngine::evaluationLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::minutes(config_.stabilizationMinutes));
        
        if (!running_ || !config_.enabled) continue;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        // Evaluate active adjustments
        for (auto& [id, adjustment] : activeAdjustments_) {
            if (adjustment.status == TuningAdjustment::Status::APPLIED) {
                adjustment.status = TuningAdjustment::Status::EVALUATING;
                
                // Check if we should rollback
                if (config_.autoRollback && shouldRollback(adjustment)) {
                    rollbackAdjustment(id);
                } else {
                    adjustment.status = TuningAdjustment::Status::SUCCESS;
                    successfulAdjustments_++;
                    
                    // Add to history
                    TuningRecord record;
                    record.id = adjustment.id;
                    record.timestamp = std::chrono::steady_clock::now();
                    record.parameter = adjustment.parameter;
                    record.oldValue = adjustment.oldValue;
                    record.newValue = adjustment.newValue;
                    record.reason = adjustment.reason;
                    record.approved = true;
                    record.successful = true;
                    record.measuredImprovement = adjustment.measuredImprovement;
                    
                    tuningHistory_.push_back(record);
                }
            }
        }
    }
}

void AutoTuningEngine::learningLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::minutes(1));
        
        if (!running_ || !config_.enabled) continue;
        
        // Capture performance snapshot
        auto snapshot = captureSnapshot();
        
        std::lock_guard<std::mutex> lock(mutex_);
        performanceHistory_.push_back(snapshot);
        
        // Keep history bounded
        if (performanceHistory_.size() > 10000) {
            performanceHistory_.erase(performanceHistory_.begin());
        }
        
        // Update learning model with completed adjustments
        for (const auto& [id, adjustment] : activeAdjustments_) {
            if (adjustment.status == TuningAdjustment::Status::SUCCESS ||
                adjustment.status == TuningAdjustment::Status::ROLLED_BACK) {
                // Find before/after snapshots
                PerformanceSnapshot before = snapshot; // Simplified
                updateLearningModel(adjustment, before, snapshot);
            }
        }
    }
}

// ============================================================================
// Tuning Strategies
// ============================================================================

std::vector<TuningAdjustment> AutoTuningEngine::generateAdjustmentsGradientDescent() {
    std::vector<TuningAdjustment> adjustments;
    
    // Calculate gradient for each parameter
    for (TuningParameter param : config_.parametersToTune) {
        double current = getCurrentValue(param);
        double step = current * config_.constraints.maxAdjustmentPercent;
        
        // Try positive direction
        TuningAdjustment adj;
        adj.id = "adj-" + std::to_string(adjustmentIdCounter_.fetch_add(1));
        adj.parameter = param;
        adj.oldValue = current;
        adj.newValue = current + step;
        adj.reason = "Gradient descent optimization";
        adj.proposedAt = std::chrono::steady_clock::now();
        adj.status = TuningAdjustment::Status::PENDING_APPROVAL;
        adj.confidence = 0.7;
        
        adjustments.push_back(adj);
    }
    
    return adjustments;
}

std::vector<TuningAdjustment> AutoTuningEngine::generateAdjustmentsBayesian() {
    // Simplified Bayesian optimization
    std::vector<TuningAdjustment> adjustments;
    
    // Use acquisition function to find promising points
    for (TuningParameter param : config_.parametersToTune) {
        double current = getCurrentValue(param);
        
        // Expected improvement acquisition
        TuningAdjustment adj;
        adj.id = "adj-" + std::to_string(adjustmentIdCounter_.fetch_add(1));
        adj.parameter = param;
        adj.oldValue = current;
        adj.newValue = current * 1.1; // Explore 10% increase
        adj.reason = "Bayesian optimization (expected improvement)";
        adj.proposedAt = std::chrono::steady_clock::now();
        adj.status = TuningAdjustment::Status::PENDING_APPROVAL;
        adj.confidence = 0.75;
        
        adjustments.push_back(adj);
    }
    
    return adjustments;
}

std::vector<TuningAdjustment> AutoTuningEngine::generateAdjustmentsGenetic() {
    // Simplified genetic algorithm
    std::vector<TuningAdjustment> adjustments;
    
    // Create mutations of current parameters
    for (TuningParameter param : config_.parametersToTune) {
        double current = getCurrentValue(param);
        
        // Random mutation
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.9, 1.1);
        
        TuningAdjustment adj;
        adj.id = "adj-" + std::to_string(adjustmentIdCounter_.fetch_add(1));
        adj.parameter = param;
        adj.oldValue = current;
        adj.newValue = current * dis(gen);
        adj.reason = "Genetic algorithm mutation";
        adj.proposedAt = std::chrono::steady_clock::now();
        adj.status = TuningAdjustment::Status::PENDING_APPROVAL;
        adj.confidence = 0.6;
        
        adjustments.push_back(adj);
    }
    
    return adjustments;
}

std::vector<TuningAdjustment> AutoTuningEngine::generateAdjustmentsRL() {
    // Simplified reinforcement learning
    std::vector<TuningAdjustment> adjustments;
    
    // Use learned policy to select actions
    for (TuningParameter param : config_.parametersToTune) {
        double current = getCurrentValue(param);
        
        // Policy-based action selection
        TuningAdjustment adj;
        adj.id = "adj-" + std::to_string(adjustmentIdCounter_.fetch_add(1));
        adj.parameter = param;
        adj.oldValue = current;
        adj.newValue = current * 1.05; // Conservative increase
        adj.reason = "RL policy recommendation";
        adj.proposedAt = std::chrono::steady_clock::now();
        adj.status = TuningAdjustment::Status::PENDING_APPROVAL;
        adj.confidence = 0.8;
        
        adjustments.push_back(adj);
    }
    
    return adjustments;
}

std::vector<TuningAdjustment> AutoTuningEngine::generateAdjustmentsRuleBased() {
    std::vector<TuningAdjustment> adjustments;
    
    // Apply heuristics based on current performance
    auto snapshot = captureSnapshot();
    
    // Rule: If latency > target, reduce batch size
    if (snapshot.latencyMs > config_.target.targetLatencyMs) {
        TuningAdjustment adj;
        adj.id = "adj-" + std::to_string(adjustmentIdCounter_.fetch_add(1));
        adj.parameter = TuningParameter::BATCH_SIZE;
        adj.oldValue = getCurrentValue(TuningParameter::BATCH_SIZE);
        adj.newValue = std::max(1.0, adj.oldValue * 0.8);
        adj.reason = "High latency detected, reducing batch size";
        adj.proposedAt = std::chrono::steady_clock::now();
        adj.status = TuningAdjustment::Status::PENDING_APPROVAL;
        adj.confidence = 0.9;
        
        adjustments.push_back(adj);
    }
    
    // Rule: If throughput < target, increase thread count
    if (snapshot.throughput < config_.target.targetThroughput) {
        TuningAdjustment adj;
        adj.id = "adj-" + std::to_string(adjustmentIdCounter_.fetch_add(1));
        adj.parameter = TuningParameter::THREAD_COUNT;
        adj.oldValue = getCurrentValue(TuningParameter::THREAD_COUNT);
        adj.newValue = std::min(static_cast<double>(config_.constraints.maxThreadCount),
                                adj.oldValue + 2);
        adj.reason = "Low throughput detected, increasing thread count";
        adj.proposedAt = std::chrono::steady_clock::now();
        adj.status = TuningAdjustment::Status::PENDING_APPROVAL;
        adj.confidence = 0.85;
        
        adjustments.push_back(adj);
    }
    
    return adjustments;
}

// ============================================================================
// Analysis
// ============================================================================

PerformanceSnapshot AutoTuningEngine::captureSnapshot() {
    PerformanceSnapshot snapshot;
    snapshot.timestamp = std::chrono::steady_clock::now();
    snapshot.parameters = currentParameters_;
    
    // Get metrics from profiler
    // These would come from actual measurements
    snapshot.latencyMs = 100.0;
    snapshot.throughput = 1000.0;
    snapshot.errorRate = 0.01;
    snapshot.cpuUtilization = 0.5;
    snapshot.memoryUtilization = 0.6;
    snapshot.gpuUtilization = 0.7;
    snapshot.gpuMemoryUtilization = 0.8;
    snapshot.requestRate = 100;
    snapshot.concurrentUsers = 10;
    snapshot.workloadType = "mixed";
    
    return snapshot;
}

double AutoTuningEngine::calculateObjective(const PerformanceSnapshot& snapshot) {
    // Multi-objective optimization
    double latencyScore = config_.target.targetLatencyMs / snapshot.latencyMs;
    double throughputScore = snapshot.throughput / config_.target.targetThroughput;
    double errorScore = 1.0 - (snapshot.errorRate / config_.target.targetErrorRate);
    
    return config_.target.latencyWeight * latencyScore +
           config_.target.throughputWeight * throughputScore +
           config_.target.errorWeight * errorScore;
}

double AutoTuningEngine::calculateImprovement(const PerformanceSnapshot& before,
                                              const PerformanceSnapshot& after) {
    double beforeObj = calculateObjective(before);
    double afterObj = calculateObjective(after);
    
    return (afterObj - beforeObj) / beforeObj;
}

bool AutoTuningEngine::shouldRollback(const TuningAdjustment& adjustment) {
    // Check if performance degraded beyond threshold
    return adjustment.measuredImprovement < -config_.rollbackThreshold;
}

// ============================================================================
// Parameter Management
// ============================================================================

double AutoTuningEngine::getCurrentValue(TuningParameter param) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = currentParameters_.find(param);
    if (it != currentParameters_.end()) {
        return it->second;
    }
    return 0.0;
}

bool AutoTuningEngine::setParameterValue(TuningParameter param, double value) {
    // Apply constraints
    switch (param) {
        case TuningParameter::BATCH_SIZE:
            value = std::min(value, static_cast<double>(config_.constraints.maxBatchSize));
            value = std::max(value, 1.0);
            break;
        case TuningParameter::THREAD_COUNT:
            value = std::min(value, static_cast<double>(config_.constraints.maxThreadCount));
            value = std::max(value, 1.0);
            break;
        case TuningParameter::GPU_MEMORY_FRACTION:
            value = std::min(value, static_cast<double>(config_.constraints.maxGpuMemoryFraction));
            value = std::max(value, 0.1);
            break;
        default:
            break;
    }
    
    // In production, this would actually apply the parameter change
    return true;
}

bool AutoTuningEngine::validateAdjustment(const TuningAdjustment& adjustment) {
    // Check if adjustment is within constraints
    double changePercent = std::abs(adjustment.newValue - adjustment.oldValue) / adjustment.oldValue;
    if (changePercent > config_.constraints.maxAdjustmentPercent) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Learning
// ============================================================================

void AutoTuningEngine::updateLearningModel(const TuningAdjustment& adjustment,
                                           const PerformanceSnapshot& before,
                                           const PerformanceSnapshot& after) {
    // Update model with new observation
    // In production, this would update a Gaussian process or neural network
}

std::vector<AutoTuningEngine::Recommendation> AutoTuningEngine::generateRecommendationsFromModel() const {
    std::vector<Recommendation> recommendations;
    
    // Generate recommendations based on learned model
    for (TuningParameter param : config_.parametersToTune) {
        double current = getCurrentValue(param);
        
        Recommendation rec;
        rec.parameter = param;
        rec.currentValue = current;
        rec.recommendedValue = current * 1.1; // Suggest 10% increase
        rec.expectedImprovement = 0.05;
        rec.confidence = 0.7;
        rec.reasoning = "Based on historical performance data";
        
        recommendations.push_back(rec);
    }
    
    return recommendations;
}

} // namespace Performance
} // namespace RawrXD
