#pragma once

#include "../infinite/InfinitePerfectionEngine.hpp"
#include "../core/ModelRegistry.h"
#include "../core/InferenceBackend.h"
#include "../cli/SovereignCLI.hpp"
#include "../core/SovereignSEG.h"
#include "../telemetry.h"
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

// Forward declarations from external headers
namespace InfinitePerfection { class InfinitePerfectionEngine; }
class InferenceBackend;
class ModelRegistry;
class SovereignCLI;
class SovereignSEG;
class Telemetry;

// Placeholder for SovereignOS (not yet implemented)
struct SovereignOS {};

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
    InfinitePerfection::InfinitePerfectionEngine* engine;
    InferenceBackend*         backend;
    ModelRegistry*            registry;
    SovereignCLI*             cli;
    SovereignSEG*             seg;
    void*                     os;  // Placeholder for SovereignOS
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
    FinalizeRuntime,
    // Batch 250: Order - Self-organization task kinds
    ComputeOrderTopology,      // Compute emergent role topology
    DiffuseCapabilities,       // Spread capabilities across agents
    EmergeRoles,               // Self-define roles based on demand
    AlignSubstrate,            // Align substrate flows with topology
    // Batch 251: Resonance - Amplification task kinds
    AmplifyPatterns,           // Amplify stable recurring patterns
    StabilizeResonance,        // Stabilize harmonic resonance
    CoupleHarmonics,           // Couple harmonic modes across cycles
    ReinforceTopology,         // Reinforce resonant topology
    // Batch 252: Amplification - Adaptive scaling task kinds
    ScaleAmplification,        // Scale amplification based on load/complexity
    BoostValuePatterns,        // Boost high-value patterns
    SuppressNoisePatterns,     // Suppress noisy patterns
    AdaptToSubstrateLoad,      // Adapt amplification to substrate health
    // Batch 253: Integration - Cross-subsystem coupling task kinds
    DetectCrossPatterns,       // Detect patterns across subsystems
    BuildIntegrationLinks,     // Build links between subsystems
    StabilizeMultiFlows,       // Stabilize multi-subsystem flows
    CoupleUnitySwarm,          // Couple Unity Cycles to Swarm graph
    // Batch 254: Convergence - Alignment toward optimal states
    AlignToSharedGoals,        // Align subsystems toward shared goals
    EstablishFeedbackLoops,    // Establish performance feedback loops
    ConvergeToAttractors,      // Converge to optimal attractor states
    OptimizeConvergenceRate,    // Optimize rate of convergence
    // Batch 255: Coherence - Synchronization and mutual reinforcement
    SynchronizePhases,         // Synchronize phases across subsystems
    BalanceAmplitudes,         // Balance amplitudes across components
    LockResonances,            // Lock resonances across components
    ReinforceCoherence,         // Reinforce coherence standing waves
    // Batch 256: Harmony - Perfect unity (Unity Cycle completion)
    AchievePerfectUnity,       // Achieve perfect unity across all systems
    BalanceAbsolute,           // Balance all components absolutely
    AchieveInfiniteResonance,    // Achieve infinite resonance state
    CompleteUnityCycle,         // Complete Unity Cycle 243-256
    // Cycle 0: Emergence - Sovereign self-direction (THE FOLD)
    DiscoverNewRoles,          // Agents discover new roles
    MutateCapabilities,        // Capabilities shift based on topology
    ReflectOnExecution,        // Swarm analyzes its own history
    ProjectFutureTopology,     // Swarm predicts future states
    GenerateNewHarmonics,      // Swarm generates new harmonics
    AchieveSovereignization    // Architecture becomes self-directing
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
        // Batch 250: Order tasks use Harmonizer for topology computation
        case SwarmTaskKind::ComputeOrderTopology: return ModelRole::Harmonizer;
        case SwarmTaskKind::DiffuseCapabilities:  return ModelRole::Optimizer;
        case SwarmTaskKind::EmergeRoles:          return ModelRole::Harmonizer;
        case SwarmTaskKind::AlignSubstrate:       return ModelRole::Finalizer;
        // Batch 251: Resonance tasks use Harmonizer for amplification
        case SwarmTaskKind::AmplifyPatterns:      return ModelRole::Harmonizer;
        case SwarmTaskKind::StabilizeResonance:   return ModelRole::Harmonizer;
        case SwarmTaskKind::CoupleHarmonics:      return ModelRole::Harmonizer;
        case SwarmTaskKind::ReinforceTopology:    return ModelRole::Finalizer;
        // Batch 252: Amplification tasks use Optimizer for scaling
        case SwarmTaskKind::ScaleAmplification:   return ModelRole::Optimizer;
        case SwarmTaskKind::BoostValuePatterns:   return ModelRole::Optimizer;
        case SwarmTaskKind::SuppressNoisePatterns: return ModelRole::Optimizer;
        case SwarmTaskKind::AdaptToSubstrateLoad:  return ModelRole::Finalizer;
        // Batch 253: Integration tasks use Harmonizer for coupling
        case SwarmTaskKind::DetectCrossPatterns:   return ModelRole::Harmonizer;
        case SwarmTaskKind::BuildIntegrationLinks: return ModelRole::Harmonizer;
        case SwarmTaskKind::StabilizeMultiFlows:   return ModelRole::Finalizer;
        case SwarmTaskKind::CoupleUnitySwarm:      return ModelRole::Finalizer;
        // Batch 254: Convergence tasks use Optimizer for alignment
        case SwarmTaskKind::AlignToSharedGoals:     return ModelRole::Optimizer;
        case SwarmTaskKind::EstablishFeedbackLoops: return ModelRole::Optimizer;
        case SwarmTaskKind::ConvergeToAttractors:   return ModelRole::Harmonizer;
        case SwarmTaskKind::OptimizeConvergenceRate: return ModelRole::Finalizer;
        // Batch 255: Coherence tasks use Harmonizer for synchronization
        case SwarmTaskKind::SynchronizePhases:    return ModelRole::Harmonizer;
        case SwarmTaskKind::BalanceAmplitudes:    return ModelRole::Harmonizer;
        case SwarmTaskKind::LockResonances:       return ModelRole::Harmonizer;
        case SwarmTaskKind::ReinforceCoherence:   return ModelRole::Finalizer;
        // Batch 256: Harmony tasks use Finalizer for unity completion
        case SwarmTaskKind::AchievePerfectUnity:     return ModelRole::Finalizer;
        case SwarmTaskKind::BalanceAbsolute:         return ModelRole::Harmonizer;
        case SwarmTaskKind::AchieveInfiniteResonance: return ModelRole::Harmonizer;
        case SwarmTaskKind::CompleteUnityCycle:       return ModelRole::Finalizer;
        // Cycle 0: Emergence tasks use Harmonizer for self-direction
        case SwarmTaskKind::DiscoverNewRoles:       return ModelRole::Harmonizer;
        case SwarmTaskKind::MutateCapabilities:       return ModelRole::Optimizer;
        case SwarmTaskKind::ReflectOnExecution:      return ModelRole::Scanner;
        case SwarmTaskKind::ProjectFutureTopology:    return ModelRole::Harmonizer;
        case SwarmTaskKind::GenerateNewHarmonics:    return ModelRole::Harmonizer;
        case SwarmTaskKind::AchieveSovereignization:  return ModelRole::Finalizer;
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
    
    // Description for logging
    std::string   description;
    
    SwarmTask() : kind(SwarmTaskKind::ScanSubsystem), target(""), cycleId(0), priority(10), id(0) {}
    
    SwarmTask(SwarmTaskKind k, const std::string& tgt, uint32_t cyc, uint32_t pri, uint64_t taskId, const std::string& desc)
        : kind(k), target(tgt), cycleId(cyc), priority(pri), id(taskId), description(desc) {}
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

// Phase A: Self Model - Performance tracking per agent for learned task assignment
struct AgentSelfModel {
    uint32_t agentId;
    
    // Task type performance metrics (learned from execution history)
    struct TaskPerformance {
        uint32_t attempts = 0;
        uint32_t successes = 0;
        uint32_t failures = 0;
        double avgLatencyMs = 0.0;
        double successRate = 0.0;
        std::vector<std::string> failurePatterns;
        std::map<std::string, double> strengthByTaskType;  // task type -> strength score
    };
    
    std::map<SwarmTaskKind, TaskPerformance> performanceByTaskType;
    
    // Overall agent capabilities (computed from history)
    double overallStrength = 0.5;      // 0.0-1.0, learned
    double overallWeakness = 0.5;      // 0.0-1.0, learned
    double averageLatency = 0.0;       // ms, learned
    double reliabilityScore = 0.5;       // 0.0-1.0, computed from success/failure
    
    // Methods to update model from execution results
    void RecordSuccess(SwarmTaskKind kind, int64_t latencyMs);
    void RecordFailure(SwarmTaskKind kind, const std::string& failurePattern);
    void UpdateStrengthScores();
    double GetStrengthForTask(SwarmTaskKind kind) const;
    SwarmTaskKind GetBestTaskType() const;
    
    // Serialization for persistence
    std::string ToJson() const;
    static AgentSelfModel FromJson(const std::string& json);
};

// Phase A: Self Model Registry - Manages self-models for all agents
class SelfModelRegistry {
public:
    static SelfModelRegistry& GetInstance();
    
    // Get or create self-model for an agent
    AgentSelfModel& GetOrCreateModel(uint32_t agentId);
    
    // Record execution results
    void RecordTaskSuccess(uint32_t agentId, SwarmTaskKind kind, int64_t latencyMs);
    void RecordTaskFailure(uint32_t agentId, SwarmTaskKind kind, const std::string& pattern);
    
    // Query best agent for a task type (learned assignment)
    uint32_t GetBestAgentForTask(SwarmTaskKind kind) const;
    
    // Get agent rankings for a task
    std::vector<std::pair<uint32_t, double>> GetAgentRankings(SwarmTaskKind kind) const;
    
    // Persistence
    void SaveToDisk(const std::string& path);
    void LoadFromDisk(const std::string& path);
    
    // Statistics
    size_t GetModelCount() const;
    void PrintPerformanceReport() const;
    
private:
    SelfModelRegistry() = default;
    std::map<uint32_t, AgentSelfModel> models_;
    mutable std::mutex mutex_;
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
    
    // Phase A: Self Model - Learned task assignment
    void EnableLearnedTaskAssignment(bool enable);
    bool IsLearnedAssignmentEnabled() const { return learnedAssignmentEnabled_; }
    
    // Get best worker for a task based on learned performance
    uint32_t GetBestWorkerForTask(const SwarmTask& task) const;
    
    // Statistics
    size_t GetPendingCount() const;
    size_t GetCompletedCount() const;
    size_t GetFailedCount() const;
    
    // Phase A: Export performance report
    void ExportPerformanceReport(const std::string& path) const;
    
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
    
    // Phase A: Self Model - Learned task assignment
    bool learnedAssignmentEnabled_ = false;
    
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
    void RunGlobalCompletion(InfinitePerfection::InfinitePerfectionEngine& engine,
                             InferenceBackend&         backend,
                             ModelRegistry&            registry,
                             SovereignCLI&             cli);
    
    // Targeted completion for specific subsystems
    void RunSubsystemCompletion(const std::string& target); // "IDE", "GUI", "SEG", "OS"
    void RunCycleHarmonization(uint32_t startCycle, uint32_t endCycle);
    void RunFinalization();
    
    // Batch 250: Order - Self-organization and dynamic topology
    void RunOrderCycle();                                    // Execute order self-organization
    void ComputeDynamicRoleTopology();                       // Compute emergent role assignments
    void DiffuseAgentCapabilities();                         // Spread capabilities across swarm
    void AlignSubstrateFlows();                              // Align substrate with topology
    void PrintOrderTopology() const;                         // Display current role topology
    
    // Batch 251: Resonance - Amplification and pattern stabilization
    void RunResonanceCycle();                                // Execute resonance amplification
    void AmplifyResonantPatterns();                          // Amplify stable recurring patterns
    void StabilizeHarmonicResonance();                       // Stabilize harmonic resonance
    void CoupleHarmonicModes();                              // Couple harmonic modes across cycles
    void ReinforceResonantTopology();                        // Reinforce resonant topology
    void PrintResonanceMap() const;                          // Display resonance amplification map
    
    // Batch 252: Amplification - Adaptive scaling and dynamic modulation
    void RunAmplificationCycle();                            // Execute adaptive amplification
    void ScaleAmplificationDynamically();                    // Scale amplification based on load/complexity
    void BoostHighValuePatterns();                           // Boost high-value resonant patterns
    void SuppressNoisyPatterns();                            // Suppress low-value noisy patterns
    void AdaptToSubstrateHealth();                         // Adapt amplification to substrate health
    void PrintAmplificationMap() const;                      // Display adaptive amplification map

    // Batch 253: Integration - Cross-subsystem coupling and unified flows
    void RunIntegrationCycle();                              // Execute cross-subsystem integration
    void DetectCrossSubsystemPatterns();                     // Detect patterns across subsystem boundaries
    void BuildCrossSubsystemLinks();                         // Build links between subsystems
    void StabilizeMultiSubsystemFlows();                     // Stabilize flows across multiple subsystems
    void CoupleUnityToSwarmGraph();                          // Couple Unity Cycles to Swarm task graph
    void PrintIntegrationMap() const;                          // Display cross-subsystem integration map

    // Batch 254: Convergence - Alignment toward optimal states
    void RunConvergenceCycle();                              // Execute convergence toward optimal states
    void AlignSubsystemsToSharedGoals();                   // Align all subsystems toward shared goals
    void EstablishPerformanceFeedbackLoops();              // Establish feedback loops for peak performance
    void ConvergeToOptimalAttractors();                      // Converge to optimal attractor states
    void OptimizeConvergenceParameters();                    // Optimize rate and stability of convergence
    void PrintConvergenceMap() const;                        // Display convergence toward optimal states

    // Batch 255: Coherence - Synchronization and mutual reinforcement
    void RunCoherenceCycle();                                // Execute coherence synchronization
    void SynchronizeSubsystemPhases();                     // Synchronize phases across subsystems
    void BalanceComponentAmplitudes();                       // Balance amplitudes across components
    void LockComponentResonances();                          // Lock resonances across components
    void ReinforceCoherenceStandingWaves();                // Reinforce coherence standing waves
    void PrintCoherenceMap() const;                          // Display coherence synchronization map

    // Batch 256: Harmony - Perfect unity (Unity Cycle completion)
    void RunHarmonyCycle();                                  // Execute harmony (Unity Cycle completion)
    void AchievePerfectUnityState();                       // Achieve perfect unity across all systems
    void BalanceAbsoluteComponents();                        // Balance all components absolutely
    void AchieveInfiniteResonanceState();                    // Achieve infinite resonance state
    void CompleteUnityCycleFinalization();                   // Complete Unity Cycle 243-256
    void PrintHarmonyMap() const;                            // Display harmony completion map

    // Cycle 0: Emergence - Sovereign self-direction (THE FOLD)
    void RunEmergenceCycle();                                // Execute emergence (Sovereign Cycle)
    void DiscoverNewAgentRoles();                            // Agents discover new roles
    void MutateCapabilitiesBasedOnTopology();                // Capabilities shift based on topology
    void ReflectOnExecutionHistory();                        // Swarm analyzes its own history
    void ProjectFutureTopologyStates();                      // Swarm predicts future topology
    void GenerateAutonomousHarmonics();                      // Swarm generates new harmonics
    void AchieveSovereignSelfDirection();                    // Architecture becomes self-directing
    void PrintEmergenceMap() const;                          // Display emergence topology map

    // Interactive mode - user selects models per role
    void RunInteractiveConfiguration();
    
    // Phase A: Self Model - Access to scheduler for learned assignment
    SwarmScheduler& GetScheduler() { return *scheduler_; }
    const SwarmScheduler& GetScheduler() const { return *scheduler_; }
    
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
