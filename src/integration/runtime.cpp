// runtime.cpp
// Integration Layer: Wires all components together

#include "runtime.h"
#include <iostream>

namespace rawrxd::runtime {

// ═══════════════════════════════════════════════════════════════════════════════
// Implementation
// ═══════════════════════════════════════════════════════════════════════════════

class InferenceRuntime::Impl {
public:
    bool initialized_ = false;
    
    // Component references (singletons)
    scheduler::CreditBasedScheduler* scheduler_ = nullptr;
    router::CapabilityRouter* router_ = nullptr;
    executor::NodeExecutor* executor_ = nullptr;
    policy::StatisticalPolicyLearner* policy_ = nullptr;
    
    // Current policy snapshot (updated periodically)
    policy::PolicySnapshot current_policy_;
    
    // Statistics
    std::atomic<uint64_t> total_requests_{0};
    std::atomic<uint64_t> successful_requests_{0};
    std::atomic<uint64_t> failed_requests_{0};
    std::atomic<double> total_latency_ms_{0.0};
};

// ═══════════════════════════════════════════════════════════════════════════════
// InferenceRuntime Implementation
// ═══════════════════════════════════════════════════════════════════════════════

InferenceRuntime::InferenceRuntime() : impl_(std::make_unique<Impl>()) {}
InferenceRuntime::~InferenceRuntime() = default;

bool InferenceRuntime::Initialize(const std::string& config_path) {
    // Initialize all layers
    if (!scheduler::InitializeScheduler(config_path)) {
        std::cerr << "[Runtime] Failed to initialize scheduler" << std::endl;
        return false;
    }
    impl_->scheduler_ = &scheduler::GetScheduler();
    
    if (!router::InitializeRouter(config_path)) {
        std::cerr << "[Runtime] Failed to initialize router" << std::endl;
        return false;
    }
    impl_->router_ = &router::GetRouter();
    
    if (!executor::InitializeExecutor(config_path)) {
        std::cerr << "[Runtime] Failed to initialize executor" << std::endl;
        return false;
    }
    impl_->executor_ = &executor::GetExecutor();
    
    if (!policy::InitializePolicyLearner(config_path)) {
        std::cerr << "[Runtime] Failed to initialize policy learner" << std::endl;
        return false;
    }
    impl_->policy_ = &policy::GetPolicyLearner();
    
    // Get initial policy snapshot
    impl_->current_policy_ = impl_->policy_->ProduceSnapshot();
    
    impl_->initialized_ = true;
    std::cout << "[Runtime] Initialized successfully" << std::endl;
    return true;
}

void InferenceRuntime::Shutdown() {
    if (!impl_->initialized_) return;
    
    policy::ShutdownPolicyLearner();
    executor::ShutdownExecutor();
    router::ShutdownRouter();
    scheduler::ShutdownScheduler();
    
    impl_->initialized_ = false;
    std::cout << "[Runtime] Shutdown complete" << std::endl;
}

std::optional<ExecutionResult> InferenceRuntime::Execute(const ExecutionRequest& request) {
    if (!impl_->initialized_) {
        return std::nullopt;
    }
    
    auto start = std::chrono::steady_clock::now();
    impl_->total_requests_++;
    
    ExecutionResult result;
    result.start_time = start;
    
    // Step 1: Scheduler - Allocate credits
    auto credits = impl_->scheduler_->AllocateCredits(
        request.type, request.priority, request.estimated_tokens
    );
    
    if (!credits.has_value()) {
        result.success = false;
        result.error_message = "Scheduler rejected: insufficient credits";
        impl_->failed_requests_++;
        result.end_time = std::chrono::steady_clock::now();
        result.total_latency = std::chrono::duration_cast<std::chrono::microseconds>(
            result.end_time - start);
        return result;
    }
    result.credits = credits.value();
    
    // Step 2: Router - Select backend
    auto routing = impl_->router_->Route(request.capability, request.work);
    
    if (!routing.has_value()) {
        // Return credits
        impl_->scheduler_->ReturnCredits(request.type, credits->granted);
        
        result.success = false;
        result.error_message = "Router rejected: no suitable backend";
        impl_->failed_requests_++;
        result.end_time = std::chrono::steady_clock::now();
        result.total_latency = std::chrono::duration_cast<std::chrono::microseconds>(
            result.end_time - start);
        return result;
    }
    result.routing = routing.value();
    
    // Step 3: Executor - Execute
    executor::NodeSpec exec_spec = request.spec;
    exec_spec.id = impl_->total_requests_.load(); // Use request count as ID
    
    if (!impl_->executor_->Execute(exec_spec)) {
        // Return credits
        impl_->scheduler_->ReturnCredits(request.type, credits->granted);
        
        result.success = false;
        result.error_message = "Executor rejected: unable to execute";
        impl_->failed_requests_++;
        result.end_time = std::chrono::steady_clock::now();
        result.total_latency = std::chrono::duration_cast<std::chrono::microseconds>(
            result.end_time - start);
        return result;
    }
    
    // Wait for execution to complete
    auto exec_result = impl_->executor_->WaitForResult(exec_spec.id, 
        std::chrono::milliseconds(60000));
    
    if (!exec_result.has_value()) {
        result.success = false;
        result.error_message = "Execution timed out or failed";
        impl_->failed_requests_++;
    } else {
        result.execution = exec_result.value();
        result.success = result.execution.success;
        
        if (result.success) {
            impl_->successful_requests_++;
        } else {
            impl_->failed_requests_++;
        }
        
        // Step 4: Policy - Observe (fire and forget)
        policy::Trace trace;
        trace.id = exec_spec.id;
        trace.timestamp = std::chrono::steady_clock::now();
        trace.model_architecture = request.work.model_architecture;
        trace.input_tokens = request.estimated_tokens;
        trace.output_tokens = 0; // Would be populated from actual execution
        trace.latency = result.execution.execution_time;
        trace.success = result.execution.success;
        trace.backend_used = result.routing.backend_name;
        trace.memory_used = result.execution.memory_used;
        trace.compute_units = result.execution.compute_units_used;
        trace.quality_score = result.success ? 1.0f : 0.0f;
        trace.error_type = result.execution.error_message;
        
        impl_->policy_->Observe(trace);
        
        // Report latency to router for future routing decisions
        impl_->router_->ReportLatency(result.routing.backend, trace.latency);
        impl_->router_->ReportOutcome(result.routing.backend, result.success);
    }
    
    result.end_time = std::chrono::steady_clock::now();
    result.total_latency = std::chrono::duration_cast<std::chrono::microseconds>(
        result.end_time - start);
    
    // Update latency statistics
    impl_->total_latency_ms_ += result.total_latency.count() / 1000.0;
    
    return result;
}

void InferenceRuntime::ExecuteAsync(const ExecutionRequest& request,
                                    std::function<void(const ExecutionResult&)> callback) {
    // For simplicity, just call Execute in a detached thread
    // In production, would use a proper thread pool
    std::thread([this, request, callback]() {
        auto result = Execute(request);
        if (result.has_value()) {
            callback(result.value());
        } else {
            ExecutionResult failed;
            failed.success = false;
            failed.error_message = "Execute returned nullopt";
            callback(failed);
        }
    }).detach();
}

scheduler::CreditBasedScheduler& InferenceRuntime::GetScheduler() {
    return *impl_->scheduler_;
}

router::CapabilityRouter& InferenceRuntime::GetRouter() {
    return *impl_->router_;
}

executor::NodeExecutor& InferenceRuntime::GetExecutor() {
    return *impl_->executor_;
}

policy::StatisticalPolicyLearner& InferenceRuntime::GetPolicyLearner() {
    return *impl_->policy_;
}

void InferenceRuntime::RefreshPolicy() {
    if (impl_->policy_) {
        impl_->current_policy_ = impl_->policy_->ProduceSnapshot();
    }
}

InferenceRuntime::Statistics InferenceRuntime::GetStatistics() const {
    Statistics stats;
    stats.total_requests = impl_->total_requests_.load();
    stats.successful_requests = impl_->successful_requests_.load();
    stats.failed_requests = impl_->failed_requests_.load();
    
    uint64_t total = stats.total_requests;
    if (total > 0) {
        stats.avg_latency_ms = impl_->total_latency_ms_ / total;
    }
    
    return stats;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global Instance
// ═══════════════════════════════════════════════════════════════════════════════

static std::unique_ptr<InferenceRuntime> g_runtime;
static std::once_flag g_init_flag;

InferenceRuntime& GetRuntime() {
    std::call_once(g_init_flag, []() {
        g_runtime = std::make_unique<InferenceRuntime>();
    });
    return *g_runtime;
}

bool InitializeRuntime(const std::string& config_path) {
    return GetRuntime().Initialize(config_path);
}

void ShutdownRuntime() {
    if (g_runtime) {
        g_runtime->Shutdown();
        g_runtime.reset();
    }
}

} // namespace rawrxd::runtime
