//=============================================================================
// Agent Split Orchestrator
// Connects Planner (200B resident) to Implementer (800B streaming)
// Uses SovereignRPC for inter-agent communication
//=============================================================================
#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace RawrXD {
namespace Agent {

//=============================================================================
// Task Types
//=============================================================================

enum class TaskType {
    CODE_GENERATION,
    DEBUG_ANALYSIS,
    REFACTORING,
    TEST_GENERATION,
    DOCUMENTATION
};

struct TaskPlan {
    TaskType type;
    std::string description;
    std::vector<std::string> subtasks;
    std::string target_language;
    int estimated_tokens;
    int priority;  // 1-10, higher = more urgent
};

struct ImplementationResult {
    bool success;
    std::string generated_code;
    std::string explanation;
    int tokens_generated;
    double time_ms;
    std::vector<std::string> warnings;
};

//=============================================================================
// Agent Interface
//=============================================================================

class IAgent {
public:
    virtual ~IAgent() = default;
    
    virtual bool Initialize(const wchar_t* model_path, size_t memory_budget) = 0;
    virtual void Shutdown() = 0;
    
    virtual bool IsReady() const = 0;
    virtual size_t GetMemoryUsage() const = 0;
};

//=============================================================================
// Planner Agent (200B model - Resident)
//=============================================================================

class PlannerAgent : public IAgent {
public:
    // Initialize with 200B model (fits in RAM)
    bool Initialize(const wchar_t* model_path, size_t memory_budget) override;
    void Shutdown() override;
    
    // Plan a complex task
    TaskPlan PlanTask(const std::string& user_request);
    
    // Validate implementation against plan
    bool ValidateImplementation(const TaskPlan& plan, 
                                const ImplementationResult& result);
    
    bool IsReady() const override { return ready_; }
    size_t GetMemoryUsage() const override { return memory_usage_; }
    
private:
    bool ready_ = false;
    size_t memory_usage_ = 0;
    void* model_handle_ = nullptr;
};

//=============================================================================
// Implementer Agent (800B model - Streaming)
//=============================================================================

class ImplementerAgent : public IAgent {
public:
    // Initialize with 800B model (streaming)
    bool Initialize(const wchar_t* model_path, size_t memory_budget) override;
    void Shutdown() override;
    
    // Execute a subtask from the plan
    ImplementationResult ExecuteSubtask(const std::string& subtask,
                                        const TaskPlan& context);
    
    // Preload experts for upcoming task
    void PreloadExperts(const std::vector<int>& expert_ids);
    
    bool IsReady() const override { return ready_; }
    size_t GetMemoryUsage() const override { return memory_usage_; }
    
private:
    bool ready_ = false;
    size_t memory_usage_ = 0;
    void* model_handle_ = nullptr;
    void* prefetcher_ = nullptr;
};

//=============================================================================
// Orchestrator
// Manages the Planner -> Implementer pipeline
//=============================================================================

class AgentSplitOrchestrator {
public:
    // Initialize both agents
    bool Initialize(
        const wchar_t* planner_model,    // 200B model path
        const wchar_t* implementer_model   // 800B model path
    );
    
    // Shutdown both agents
    void Shutdown();
    
    // Execute a user request through the full pipeline
    struct OrchestrationResult {
        TaskPlan plan;
        std::vector<ImplementationResult> implementations;
        std::string final_output;
        double total_time_ms;
        bool success;
    };
    
    OrchestrationResult ExecuteRequest(const std::string& user_request);
    
    // Async execution with callback
    using CompletionCallback = std::function<void(const OrchestrationResult&)>;
    void ExecuteRequestAsync(const std::string& user_request, 
                            CompletionCallback callback);
    
    // Get system status
    struct SystemStatus {
        bool planner_ready;
        bool implementer_ready;
        size_t total_memory_usage;
        size_t planner_memory;
        size_t implementer_memory;
        int pending_tasks;
        double prefetch_hit_rate;
    };
    SystemStatus GetStatus() const;
    
    // Telemetry
    struct Telemetry {
        uint64_t tasks_completed;
        uint64_t tasks_failed;
        double avg_planning_time_ms;
        double avg_implementation_time_ms;
        double avg_tokens_per_second;
    };
    Telemetry GetTelemetry() const;
    
private:
    std::unique_ptr<PlannerAgent> planner_;
    std::unique_ptr<ImplementerAgent> implementer_;
    
    // Task queue for async execution
    std::queue<std::pair<std::string, CompletionCallback>> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    HANDLE worker_thread_ = nullptr;
    bool shutdown_ = false;
    
    // Telemetry
    mutable std::mutex telemetry_mutex_;
    Telemetry telemetry_ = {};
    
    // Worker thread function
    static DWORD WINAPI WorkerThread(LPVOID param);
    void ProcessTasks();
};

//=============================================================================
// RPC Integration
// Uses existing SovereignRPC infrastructure
//=============================================================================

class AgentRPCBridge {
public:
    // Serialize task plan for RPC transmission
    static std::vector<uint8_t> SerializePlan(const TaskPlan& plan);
    static TaskPlan DeserializePlan(const std::vector<uint8_t>& data);
    
    // Serialize implementation result
    static std::vector<uint8_t> SerializeResult(const ImplementationResult& result);
    static ImplementationResult DeserializeResult(const std::vector<uint8_t>& data);
    
    // RPC endpoints
    static constexpr uint16_t kPlannerPort = 9001;
    static constexpr uint16_t kImplementerPort = 9002;
};

} // namespace Agent
} // namespace RawrXD
