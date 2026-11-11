// SchedulerPolicy.hpp
// Phase C.2 — Scheduling Policies and Decision Rules

#ifndef SCHEDULER_POLICY_HPP
#define SCHEDULER_POLICY_HPP

#include <string>
#include <map>
#include <vector>

namespace Scheduler {

// Policy types
enum class SchedulingPolicy {
    STATIC,           // Fixed assignment
    ROUND_ROBIN,      // Cyclic distribution
    PRIORITY_QUEUE,   // Priority-based
    PATTERN_DRIVEN,   // Emergent pattern aware
    ADAPTIVE,        // Fully adaptive (default)
    EXPLORATION_ONLY, // Force exploration
    EXPLOITATION_ONLY // Force exploitation
};

// Policy configuration
struct PolicyConfig {
    SchedulingPolicy type = SchedulingPolicy::ADAPTIVE;
    
    // Static policy
    std::map<std::string, uint32_t> static_assignments;
    
    // Priority queue policy
    bool use_pattern_priority = true;
    bool use_historical_performance = true;
    bool use_resource_availability = true;
    
    // Pattern-driven policy
    double pattern_influence_weight = 0.6;
    double historical_influence_weight = 0.3;
    double resource_influence_weight = 0.1;
    
    // Adaptive policy
    double adaptation_rate = 0.1;
    double policy_switch_threshold = 0.5;
};

// Policy evaluation result
struct PolicyEvaluation {
    SchedulingPolicy selected_policy;
    std::map<std::string, double> policy_scores;
    std::string rationale;
    double confidence;
};

// Policy engine
class SchedulerPolicyEngine {
public:
    SchedulerPolicyEngine(const PolicyConfig& config = PolicyConfig{});
    
    // Evaluate and select policy
    PolicyEvaluation EvaluatePolicy(
        const std::vector<ScheduledTask>& pending_tasks,
        const SchedulerMetrics& metrics);
    
    // Apply policy to task
    TaskPriority ApplyPolicy(
        const ScheduledTask& task,
        SchedulingPolicy policy,
        const SchedulerMetrics& metrics);
    
    // Update policy based on results
    void UpdatePolicyPerformance(
        SchedulingPolicy policy,
        double task_success_rate,
        double average_tps);
    
    // Get/set configuration
    PolicyConfig GetConfig() const;
    void SetConfig(const PolicyConfig& config);
    
private:
    PolicyConfig config_;
    std::map<SchedulingPolicy, std::vector<double>> policy_performance_;
    
    double CalculatePolicyScore(
        SchedulingPolicy policy,
        const std::vector<ScheduledTask>& pending_tasks,
        const SchedulerMetrics& metrics);
};

} // namespace Scheduler

#endif // SCHEDULER_POLICY_HPP
