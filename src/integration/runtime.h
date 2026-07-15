// runtime.h
// Integration Layer: Wires Scheduler → Router → Executor → Policy
// This is the ONLY layer that knows about all components

#pragma once

#include "../core/scheduler/scheduler.h"
#include "../core/router/router.h"
#include "../core/executor/executor.h"
#include "../core/policy/policy.h"

#include <memory>
#include <functional>

namespace rawrxd::runtime {

// ═══════════════════════════════════════════════════════════════════════════════
// Execution Request
// ═══════════════════════════════════════════════════════════════════════════════

struct ExecutionRequest {
    // Scheduling info
    scheduler::NodeType type;
    scheduler::Priority priority;
    scheduler::TokenCredits estimated_tokens;
    
    // Routing info
    router::WorkSpec work;
    router::CapabilityToken capability;
    
    // Execution info
    executor::NodeSpec spec;
    
    // Policy (read at construct-time only)
    policy::PolicySnapshot policy_snapshot;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Execution Result
// ═══════════════════════════════════════════════════════════════════════════════

struct ExecutionResult {
    bool success;
    std::string error_message;
    
    // Component results
    scheduler::CreditAllocation credits;
    router::RoutingDecision routing;
    executor::ExecutionResult execution;
    
    // Timing
    std::chrono::microseconds total_latency;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Runtime Interface
// ═══════════════════════════════════════════════════════════════════════════════

class InferenceRuntime {
public:
    InferenceRuntime();
    ~InferenceRuntime();

    // Disable copy/move
    InferenceRuntime(const InferenceRuntime&) = delete;
    InferenceRuntime& operator=(const InferenceRuntime&) = delete;
    InferenceRuntime(InferenceRuntime&&) = delete;
    InferenceRuntime& operator=(InferenceRuntime&&) = delete;

    // Initialize all layers
    bool Initialize(const std::string& config_path);
    void Shutdown();

    // Execute a request through all layers
    std::optional<ExecutionResult> Execute(const ExecutionRequest& request);

    // Execute asynchronously
    void ExecuteAsync(const ExecutionRequest& request,
                      std::function<void(const ExecutionResult&)> callback);

    // Get component references (for advanced usage)
    scheduler::CreditBasedScheduler& GetScheduler();
    router::CapabilityRouter& GetRouter();
    executor::NodeExecutor& GetExecutor();
    policy::StatisticalPolicyLearner& GetPolicyLearner();

    // Update policy from learner (call periodically)
    void RefreshPolicy();

    // Get runtime statistics
    struct Statistics {
        uint64_t total_requests;
        uint64_t successful_requests;
        uint64_t failed_requests;
        double avg_latency_ms;
    };
    Statistics GetStatistics() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ═══════════════════════════════════════════════════════════════════════════════
// Global Runtime Instance
// ═══════════════════════════════════════════════════════════════════════════════

InferenceRuntime& GetRuntime();
bool InitializeRuntime(const std::string& config_path);
void ShutdownRuntime();

} // namespace rawrxd::runtime
