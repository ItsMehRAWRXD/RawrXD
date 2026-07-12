#pragma once

#include "../infinite/InfinitePerfectionEngine.hpp"
#include "../model/ModelRegistry.hpp"
#include "../inference/InferenceBackend.hpp"
#include "../cli/SovereignCLI.hpp"
#include "../seg/SovereignSEG.hpp"
#include "../os/SovereignOS.hpp"
#include "../telemetry/Telemetry.hpp"
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <unordered_map>

namespace Sovereign {

// Forward declarations
struct SwarmAgentContext;
struct SwarmTask;
class SwarmAgent;
class SwarmScheduler;

// Model selection strategy per role
enum class ModelRole : uint8_t {
    Scanner,      // For scanning subsystems
    Repairer,     // For repairing issues
    Extender,     // For extending functionality
    Optimizer,    // For optimizing hot paths
    Harmonizer,   // For cycle harmonization
    Finalizer,    // For runtime finalization
    General       // Fallback/general purpose
};

// Model configuration per role
struct RoleModelConfig {
    std::string modelName;
    std::string modelPath;
    std::string quantType;      // Q4_K_M, Q8_0, etc.
    uint32_t    contextLength;
    float       temperature;
    float       topP;
    uint32_t    topK;
    std::vector<std::string> tags;
};

// Default role model mappings
struct DefaultRoleModels {
    // High-capacity model for scanning (needs broad understanding)
    static constexpr const char* Scanner = "nemotron-super:latest";
    
    // Precise model for repairs (needs accuracy)
    static constexpr const char* Repairer = "qwen3.5:40b";
    
    // Creative model for extensions
    static constexpr const char* Extender = "codestral:22b";
    
    // Fast model for optimization
    static constexpr const char* Optimizer = "deepseek-r1:8b";
    
    // Balanced model for harmonization
    static constexpr const char* Harmonizer = "gemma3:27b";
    
    // Powerful model for finalization
    static constexpr const char* Finalizer = "bigdaddyg:38gb";
    
    // General fallback
    static constexpr const char* General = "llama3.2:3b";
};

struct SwarmAgentContext {
    InfinitePerfectionEngine* engine;
    InferenceBackend*         backend;
    ModelRegistry*            registry;
    SovereignCLI*             cli;
    SovereignSEG*             seg;
    SovereignOS*              os;
    Telemetry*                telemetry;
    
    // Role-to-model mapping (configurable per swarm)
    std::unordered_map<ModelRole, RoleModelConfig> roleModels;
    
    // Default constructor with role model initialization
    SwarmAgentContext() {
        InitializeDefaultRoleModels();
    }
    
    void InitializeDefaultRoleModels();
    void SetRoleModel(ModelRole role, const RoleModelConfig& config);
    RoleModelConfig GetRoleModel(ModelRole role) const;
    std::string SelectModelForRole(ModelRole role, const std::string& target);
};

enum class SwarmTaskKind : uint8_t {
    ScanSubsystem,
    RepairSubsystem,
    ExtendSubsystem,
    OptimizeSubsystem,
    HarmonizeCycle,
    FinalizeRuntime
};

// Get ModelRole from SwarmTaskKind
inline ModelRole TaskKindToModelRole(SwarmTaskKind kind) {
    switch (kind) {
        case SwarmTaskKind::ScanSubsystem:   return ModelRole::Scanner;
        case SwarmTaskKind::RepairSubsystem: return ModelRole::Repairer;
        case SwarmTaskKind::ExtendSubsystem: return ModelRole::Extender;
        case SwarmTaskKind::OptimizeSubsystem: return ModelRole::Optimizer;
        case SwarmTaskKind::HarmonizeCycle:  return ModelRole::Harmonizer;
        case SwarmTaskKind::FinalizeRuntime: return ModelRole::Finalizer;
        default: return ModelRole::General;
    }
}

struct SwarmTask {
    SwarmTaskKind kind;
    std::string   target;   // "IDE", "GUI", "SEG", "OS", "Unity", "Totality", etc.
    uint32_t      cycleId;  // 243-256 for Unity, 0 if N/A
    uint32_t      priority; // 0 = highest priority
    uint64_t      id;
    
    // Optional: override model for this specific task
    std::string   overrideModel;
    
    // Assigned model (set by scheduler based on role)
    std::string   assignedModel;
    
    SwarmTask() : kind(SwarmTaskKind::ScanSubsystem), target(""), cycleId(0), priority(10), id(0) {}
};

// Priority queue comparator
struct SwarmTaskCompare {
    bool operator()(const SwarmTask& a, const SwarmTask& b) const {
        return a.priority > b.priority; // min-heap by priority
    }
};

// Result of a swarm task execution
struct SwarmTaskResult {
    uint64_t    taskId;
    bool        success;
    std::string message;
    float       confidence;
    int64_t     executionTimeMs;
    std::string modelUsed;
};

class SwarmAgent {
public:
    explicit SwarmAgent(const SwarmAgentContext& ctx, uint32_t agentId = 0);
    
    // Execute a single task
    SwarmTaskResult Execute(const SwarmTask& task);
    
    // Batch execution
    std::vector<SwarmTaskResult> ExecuteBatch(const std::vector<SwarmTask>& tasks);
    
private:
    SwarmAgentContext ctx_;
    uint32_t          agentId_;
    std::string       currentModel_;
    
    // Task handlers
    SwarmTaskResult HandleScan(const SwarmTask& task);
    SwarmTaskResult HandleRepair(const SwarmTask& task);
    SwarmTaskResult HandleExtend(const SwarmTask& task);
    SwarmTaskResult HandleOptimize(const SwarmTask& task);
    SwarmTaskResult HandleHarmonize(const SwarmTask& task);
    SwarmTaskResult HandleFinalize(const SwarmTask& task);
    
    // Model management
    bool LoadModelForRole(ModelRole role, const std::string& target);
    bool LoadModelByName(const std::string& modelName);
    void UnloadCurrentModel();
    
    // Prompt builders
    std::string BuildScanPrompt(const std::string& target);
    std::string BuildRepairPrompt(const std::string& target, const std::string& issue);
    std::string BuildExtendPrompt(const std::string& target);
    std::string BuildOptimizePrompt(const std::string& target, const std::string& path);
    std::string BuildHarmonizePrompt(uint32_t cycleId);
    std::string BuildFinalizePrompt();
};

class SwarmScheduler {
public:
    explicit SwarmScheduler(const SwarmAgentContext& ctx, 
                              uint32_t workerCount = std::thread::hardware_concurrency());
    ~SwarmScheduler();
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const { return running_; }
    
    // Task submission
    uint64_t Enqueue(const SwarmTask& task);
    std::vector<uint64_t> EnqueueBatch(const std::vector<SwarmTask>& tasks);
    
    // Wait for completion
    void WaitForCompletion();
    bool WaitForCompletionWithTimeout(int64_t timeoutMs);
    
    // Results
    std::vector<SwarmTaskResult> GetResults() const;
    SwarmTaskResult GetResult(uint64_t taskId) const;
    
    // Convenience: enqueue all global completion tasks
    void EnqueueGlobalCompletionTasks();
    
    // Statistics
    size_t GetPendingCount() const;
    size_t GetCompletedCount() const;
    size_t GetFailedCount() const;
    
private:
    SwarmAgentContext                              ctx_;
    uint32_t                                       workerCount_;
    std::atomic<bool>                              running_;
    std::atomic<uint64_t>                          nextId_;
    
    // Task queue
    std::priority_queue<SwarmTask, std::vector<SwarmTask>, SwarmTaskCompare> queue_;
    mutable std::mutex                             queueMutex_;
    std::condition_variable                        queueCv_;
    
    // Results
    std::unordered_map<uint64_t, SwarmTaskResult>  results_;
    mutable std::mutex                             resultsMutex_;
    
    // Workers
    std::vector<std::thread>                       workers_;
    
    // Statistics
    std::atomic<size_t>                            completedCount_;
    std::atomic<size_t>                            failedCount_;
    
    void WorkerLoop(uint32_t workerId);
    void BuildGlobalTaskList(std::vector<SwarmTask>& tasks);
};

// Main SovereignSwarm orchestrator
class SovereignSwarm {
public:
    explicit SovereignSwarm(const SwarmAgentContext& ctx);
    
    // Configure role models before running
    void SetRoleModel(ModelRole role, const RoleModelConfig& config);
    void SetRoleModelByName(ModelRole role, const std::string& modelName);
    void ResetRoleModelsToDefaults();
    
    // Print current role model configuration
    void PrintRoleConfiguration() const;
    
    // Main entry point - runs global completion with full swarm
    void RunGlobalCompletion(InfinitePerfectionEngine& engine,
                             InferenceBackend&         backend,
                             ModelRegistry&            registry,
                             SovereignCLI&             cli);
    
    // Targeted completion for specific subsystems
    void RunSubsystemCompletion(const std::string& target); // "IDE", "GUI", "SEG", "OS"
    void RunCycleHarmonization(uint32_t startCycle, uint32_t endCycle);
    void RunFinalization();
    
    // Interactive mode - user selects models per role
    void RunInteractiveConfiguration();
    
private:
    SwarmAgentContext ctx_;
    std::unique_ptr<SwarmScheduler> scheduler_;
    
    void InitializeScheduler();
    void BuildAndEnqueueGlobalTasks();
};

// Utility functions
namespace SwarmUtils {
    // Get available models from registry
    std::vector<std::string> GetAvailableModels(const ModelRegistry& registry);
    
    // Recommend model for role based on capabilities
    std::string RecommendModelForRole(ModelRole role, const std::vector<std::string>& availableModels);
    
    // Print model capabilities
    void PrintModelCapabilities(const std::string& modelName);
    
    // Validate model configuration
    bool ValidateRoleModelConfig(const RoleModelConfig& config);
}

} // namespace Sovereign
