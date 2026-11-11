// SchedulerPolicy.cpp
// Phase C.2 — Scheduling Policy Implementation

#include "SchedulerPolicy.hpp"
#include <algorithm>
#include <math>

namespace Scheduler {

// ============================================================================
// PolicyConfig Implementation
// ============================================================================

PolicyConfig PolicyConfig::CreateDefault() {
    PolicyConfig config;
    return config;
}

PolicyConfig PolicyConfig::CreateHighThroughput() {
    PolicyConfig config;
    config.throughput_weight = 0.6;
    config.latency_weight = 0.2;
    config.reliability_weight = 0.2;
    config.resource_efficiency_weight = 0.3;
    return config;
}

PolicyConfig PolicyConfig::CreateLowLatency() {
    PolicyConfig config;
    config.throughput_weight = 0.2;
    config.latency_weight = 0.6;
    config.reliability_weight = 0.2;
    config.resource_efficiency_weight = 0.2;
    return config;
}

PolicyConfig PolicyConfig::CreateBalanced() {
    PolicyConfig config;
    config.throughput_weight = 0.3;
    config.latency_weight = 0.3;
    config.reliability_weight = 0.2;
    config.resource_efficiency_weight = 0.2;
    return config;
}

PolicyConfig PolicyConfig::CreateResourceOptimized() {
    PolicyConfig config;
    config.throughput_weight = 0.2;
    config.latency_weight = 0.2;
    config.reliability_weight = 0.2;
    config.resource_efficiency_weight = 0.6;
    return config;
}

void PolicyConfig::Normalize() {
    double total = throughput_weight + latency_weight + 
                   reliability_weight + resource_efficiency_weight +
                   fairness_weight + exploration_weight;
    
    if (total > 0.0) {
        throughput_weight /= total;
        latency_weight /= total;
        reliability_weight /= total;
        resource_efficiency_weight /= total;
        fairness_weight /= total;
        exploration_weight /= total;
    }
}

// ============================================================================
// PolicyMetrics Implementation
// ============================================================================

double PolicyMetrics::CalculateCompositeScore(const PolicyConfig& config) const {
    double score = 0.0;
    
    // Throughput component (higher is better)
    double normalized_throughput = std::min(1.0, average_throughput / 1000.0);
    score += normalized_throughput * config.throughput_weight;
    
    // Latency component (lower is better)
    double normalized_latency = 1.0 - std::min(1.0, average_latency_ms / 100.0);
    score += normalized_latency * config.latency_weight;
    
    // Reliability component (higher is better)
    score += success_rate * config.reliability_weight;
    
    // Resource efficiency (higher is better)
    double normalized_efficiency = resource_utilization > 0.0 
        ? std::min(1.0, tasks_completed / (resource_utilization * 100.0))
        : 0.0;
    score += normalized_efficiency * config.resource_efficiency_weight;
    
    // Fairness (higher is better)
    score += fairness_index * config.fairness_weight;
    
    // Exploration bonus (higher is better for learning)
    double normalized_exploration = std::min(1.0, exploration_tasks / 100.0);
    score += normalized_exploration * config.exploration_weight;
    
    return score;
}

// ============================================================================
// SchedulerPolicyEngine Implementation
// ============================================================================

SchedulerPolicyEngine::SchedulerPolicyEngine() 
    : current_policy_(SchedulingPolicy::BALANCED)
    , current_config_(PolicyConfig::CreateBalanced())
    , policy_switch_count_(0) {}

void SchedulerPolicyEngine::SetPolicy(SchedulingPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (current_policy_ != policy) {
        current_policy_ = policy;
        policy_switch_count_++;
        
        switch (policy) {
            case SchedulingPolicy::THROUGHPUT_OPTIMIZED:
                current_config_ = PolicyConfig::CreateHighThroughput();
                break;
            case SchedulingPolicy::LATENCY_OPTIMIZED:
                current_config_ = PolicyConfig::CreateLowLatency();
                break;
            case SchedulingPolicy::BALANCED:
                current_config_ = PolicyConfig::CreateBalanced();
                break;
            case SchedulingPolicy::RESOURCE_OPTIMIZED:
                current_config_ = PolicyConfig::CreateResourceOptimized();
                break;
            case SchedulingPolicy::ADAPTIVE:
                // Config will be updated dynamically
                current_config_ = PolicyConfig::CreateBalanced();
                break;
            case SchedulingPolicy::CUSTOM:
                // Keep current custom config
                break;
        }
        
        policy_history_.push_back({
            std::chrono::steady_clock::now(),
            policy,
            current_config_
        });
    }
}

SchedulingPolicy SchedulerPolicyEngine::GetCurrentPolicy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_policy_;
}

PolicyConfig SchedulerPolicyEngine::GetCurrentConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_config_;
}

void SchedulerPolicyEngine::SetCustomConfig(const PolicyConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_config_ = config;
    current_policy_ = SchedulingPolicy::CUSTOM;
}

double SchedulerPolicyEngine::EvaluatePolicy(
    SchedulingPolicy policy,
    const PolicyMetrics& metrics) const {
    
    PolicyConfig config;
    
    switch (policy) {
        case SchedulingPolicy::THROUGHPUT_OPTIMIZED:
            config = PolicyConfig::CreateHighThroughput();
            break;
        case SchedulingPolicy::LATENCY_OPTIMIZED:
            config = PolicyConfig::CreateLowLatency();
            break;
        case SchedulingPolicy::BALANCED:
            config = PolicyConfig::CreateBalanced();
            break;
        case SchedulingPolicy::RESOURCE_OPTIMIZED:
            config = PolicyConfig::CreateResourceOptimized();
            break;
        default:
            config = current_config_;
            break;
    }
    
    return metrics.CalculateCompositeScore(config);
}

SchedulingPolicy SchedulerPolicyEngine::SelectBestPolicy(
    const PolicyMetrics& metrics) const {
    
    double best_score = -1.0;
    SchedulingPolicy best_policy = SchedulingPolicy::BALANCED;
    
    // Evaluate all standard policies
    std::vector<SchedulingPolicy> policies = {
        SchedulingPolicy::THROUGHPUT_OPTIMIZED,
        SchedulingPolicy::LATENCY_OPTIMIZED,
        SchedulingPolicy::BALANCED,
        SchedulingPolicy::RESOURCE_OPTIMIZED
    };
    
    for (auto policy : policies) {
        double score = EvaluatePolicy(policy, metrics);
        if (score > best_score) {
            best_score = score;
            best_policy = policy;
        }
    }
    
    return best_policy;
}

void SchedulerPolicyEngine::UpdateAdaptivePolicy(const PolicyMetrics& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (current_policy_ != SchedulingPolicy::ADAPTIVE) {
        return;
    }
    
    // Adjust weights based on current performance
    double throughput_ratio = metrics.average_throughput / 1000.0;
    double latency_ratio = metrics.average_latency_ms / 100.0;
    double reliability = metrics.success_rate;
    
    // If throughput is low, increase throughput weight
    if (throughput_ratio < 0.5) {
        current_config_.throughput_weight = std::min(0.8, 
            current_config_.throughput_weight * 1.1);
    }
    
    // If latency is high, increase latency weight
    if (latency_ratio > 0.5) {
        current_config_.latency_weight = std::min(0.8,
            current_config_.latency_weight * 1.1);
    }
    
    // If reliability is low, increase reliability weight
    if (reliability < 0.9) {
        current_config_.reliability_weight = std::min(0.8,
            current_config_.reliability_weight * 1.1);
    }
    
    // Normalize weights
    current_config_.Normalize();
}

PolicyDecision SchedulerPolicyEngine::MakeDecision(
    const std::vector<ScheduledTask>& candidates,
    const PolicyMetrics& metrics) const {
    
    PolicyDecision decision;
    decision.timestamp = std::chrono::steady_clock::now();
    decision.policy_used = current_policy_;
    decision.config_used = current_config_;
    
    if (candidates.empty()) {
        decision.decision_type = PolicyDecision::DecisionType::WAIT;
        return decision;
    }
    
    // Score each candidate
    std::vector<std::pair<uint64_t, double>> scored_tasks;
    
    for (const auto& task : candidates) {
        double score = ScoreTask(task, metrics);
        scored_tasks.push_back({task.task_id, score});
    }
    
    // Sort by score (highest first)
    std::sort(scored_tasks.begin(), scored_tasks.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Select top tasks
    size_t max_selection = std::min(candidates.size(), 
        static_cast<size_t>(current_config_.max_concurrent_tasks));
    
    for (size_t i = 0; i < max_selection; ++i) {
        decision.selected_task_ids.push_back(scored_tasks[i].first);
        decision.utility_scores[scored_tasks[i].first] = scored_tasks[i].second;
    }
    
    decision.decision_type = PolicyDecision::DecisionType::SCHEDULE;
    
    // Calculate overall utility
    double total_utility = 0.0;
    for (const auto& [id, score] : decision.utility_scores) {
        total_utility += score;
    }
    decision.overall_utility = total_utility / decision.utility_scores.size();
    
    return decision;
}

double SchedulerPolicyEngine::ScoreTask(
    const ScheduledTask& task,
    const PolicyMetrics& metrics) const {
    
    double score = 0.0;
    
    // Priority component
    score += task.priority.total_priority * 0.3;
    
    // Pattern stability component
    score += task.priority.stability_factor * 0.2;
    
    // Resource fit component
    uint32_t available_workers = metrics.active_workers - 
        static_cast<uint32_t>(metrics.resource_utilization * metrics.active_workers);
    double resource_fit = (available_workers >= task.min_workers) ? 1.0 : 0.0;
    score += resource_fit * 0.2;
    
    // Wait time component (older tasks get priority)
    auto now = std::chrono::steady_clock::now();
    auto wait_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - task.submit_time).count();
    double wait_score = std::min(1.0, wait_time / 1000.0);
    score += wait_score * 0.1;
    
    // Exploration bonus
    score += task.priority.exploration_weight * 0.2;
    
    return score;
}

std::vector<PolicyHistoryEntry> SchedulerPolicyEngine::GetPolicyHistory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_history_;
}

uint32_t SchedulerPolicyEngine::GetPolicySwitchCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return policy_switch_count_;
}

void SchedulerPolicyEngine::ResetHistory() {
    std::lock_guard<std::mutex> lock(mutex_);
    policy_history_.clear();
    policy_switch_count_ = 0;
}

} // namespace Scheduler
