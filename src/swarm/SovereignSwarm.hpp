#pragma once

#include "../infinite/InfinitePerfectionEngine.hpp"
#include "../core/ModelRegistry.h"
#include "../core/InferenceBackend.h"
#include "../cli/SovereignCLI.hpp"
#include "../core/SovereignSEG.h"
#include "../telemetry.h"
#include "InfinitePerfectionTelemetry.hpp"
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
#include <map>
#include <deque>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>

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
    InfinitePerfectionTelemetry* infiniteTelemetry;  // Phase B.2: Engine telemetry bridge
    
    // Role-to-model mapping (configurable per swarm)
    std::unordered_map<ModelRole, RoleModelConfig> roleModels;
    
    // Default constructor with role model initialization
    SwarmAgentContext() : engine(nullptr), backend(nullptr), registry(nullptr), cli(nullptr), seg(nullptr), os(nullptr), telemetry(nullptr), infiniteTelemetry(nullptr) {
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

// Convert SwarmTaskKind to string for logging/debugging
inline std::string TaskKindToString(SwarmTaskKind kind) {
    switch (kind) {
        case SwarmTaskKind::ScanSubsystem: return "ScanSubsystem";
        case SwarmTaskKind::RepairSubsystem: return "RepairSubsystem";
        case SwarmTaskKind::ExtendSubsystem: return "ExtendSubsystem";
        case SwarmTaskKind::OptimizeSubsystem: return "OptimizeSubsystem";
        case SwarmTaskKind::HarmonizeCycle: return "HarmonizeCycle";
        case SwarmTaskKind::FinalizeRuntime: return "FinalizeRuntime";
        case SwarmTaskKind::ComputeOrderTopology: return "ComputeOrderTopology";
        case SwarmTaskKind::DiffuseCapabilities: return "DiffuseCapabilities";
        case SwarmTaskKind::EmergeRoles: return "EmergeRoles";
        case SwarmTaskKind::AlignSubstrate: return "AlignSubstrate";
        case SwarmTaskKind::AmplifyPatterns: return "AmplifyPatterns";
        case SwarmTaskKind::StabilizeResonance: return "StabilizeResonance";
        case SwarmTaskKind::CoupleHarmonics: return "CoupleHarmonics";
        case SwarmTaskKind::ReinforceTopology: return "ReinforceTopology";
        case SwarmTaskKind::ScaleAmplification: return "ScaleAmplification";
        case SwarmTaskKind::BoostValuePatterns: return "BoostValuePatterns";
        case SwarmTaskKind::SuppressNoisePatterns: return "SuppressNoisePatterns";
        case SwarmTaskKind::AdaptToSubstrateLoad: return "AdaptToSubstrateLoad";
        case SwarmTaskKind::DetectCrossPatterns: return "DetectCrossPatterns";
        case SwarmTaskKind::BuildIntegrationLinks: return "BuildIntegrationLinks";
        case SwarmTaskKind::StabilizeMultiFlows: return "StabilizeMultiFlows";
        case SwarmTaskKind::CoupleUnitySwarm: return "CoupleUnitySwarm";
        case SwarmTaskKind::AlignToSharedGoals: return "AlignToSharedGoals";
        case SwarmTaskKind::EstablishFeedbackLoops: return "EstablishFeedbackLoops";
        case SwarmTaskKind::ConvergeToAttractors: return "ConvergeToAttractors";
        case SwarmTaskKind::OptimizeConvergenceRate: return "OptimizeConvergenceRate";
        case SwarmTaskKind::SynchronizePhases: return "SynchronizePhases";
        case SwarmTaskKind::BalanceAmplitudes: return "BalanceAmplitudes";
        case SwarmTaskKind::LockResonances: return "LockResonances";
        case SwarmTaskKind::ReinforceCoherence: return "ReinforceCoherence";
        case SwarmTaskKind::AchievePerfectUnity: return "AchievePerfectUnity";
        case SwarmTaskKind::BalanceAbsolute: return "BalanceAbsolute";
        case SwarmTaskKind::AchieveInfiniteResonance: return "AchieveInfiniteResonance";
        case SwarmTaskKind::CompleteUnityCycle: return "CompleteUnityCycle";
        case SwarmTaskKind::DiscoverNewRoles: return "DiscoverNewRoles";
        case SwarmTaskKind::MutateCapabilities: return "MutateCapabilities";
        case SwarmTaskKind::ReflectOnExecution: return "ReflectOnExecution";
        case SwarmTaskKind::ProjectFutureTopology: return "ProjectFutureTopology";
        case SwarmTaskKind::GenerateNewHarmonics: return "GenerateNewHarmonics";
        case SwarmTaskKind::AchieveSovereignization: return "AchieveSovereignization";
        default: return "Unknown";
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
// Phase A.1-A.5: Measurable learning with confidence, exploration, forgetting, explainability
struct AgentSelfModel {
    uint32_t agentId;
    
    // Task type performance metrics (learned from execution history)
    struct TaskPerformance {
        // Phase A.1: Basic metrics
        uint32_t attempts = 0;
        uint32_t successes = 0;
        uint32_t failures = 0;
        double avgLatencyMs = 0.0;
        double successRate = 0.0;
        std::vector<std::string> failurePatterns;
        
        // Phase A.2: Confidence scoring
        double confidence = 0.0;           // 0.0-1.0 based on sample count
        static constexpr uint32_t MIN_SAMPLES_FOR_CONFIDENCE = 10;
        static constexpr uint32_t MAX_SAMPLES_FOR_CONFIDENCE = 1000;
        
        // Phase A.4: Rolling statistics (exponential moving average)
        double emaSuccessRate = 0.5;       // EMA of success rate (alpha = 0.1)
        double emaLatency = 0.0;           // EMA of latency
        static constexpr double EMA_ALPHA = 0.1;
        
        // Phase A.4: Rolling window (last N executions)
        static constexpr size_t ROLLING_WINDOW_SIZE = 100;
        std::deque<bool> recentOutcomes;   // true = success, false = failure
        std::deque<int64_t> recentLatencies;
        double rollingSuccessRate = 0.5;   // Success rate over last N executions
        double rollingLatency = 0.0;       // Average latency over last N executions
        
        // Phase A.1: Composite score (used for ranking)
        double compositeScore = 0.5;       // Combined metric for selection
        
        // Phase A.5: Last update timestamp
        std::chrono::steady_clock::time_point lastUpdated;
    };
    
    std::map<SwarmTaskKind, TaskPerformance> performanceByTaskType;
    
    // Overall agent capabilities (computed from history)
    double overallStrength = 0.5;      // 0.0-1.0, learned
    double overallWeakness = 0.5;      // 0.0-1.0, learned
    double averageLatency = 0.0;       // ms, learned
    double reliabilityScore = 0.5;       // 0.0-1.0, computed from success/failure
    
    // Phase A.3: Exploration tracking
    uint32_t explorationCount = 0;       // Times this agent was selected for exploration
    double explorationRate = 0.0;        // Historical exploration rate
    
    // Methods to update model from execution results
    void RecordSuccess(SwarmTaskKind kind, int64_t latencyMs);
    void RecordFailure(SwarmTaskKind kind, const std::string& failurePattern);
    void UpdateStrengthScores();
    double GetStrengthForTask(SwarmTaskKind kind) const;
    double GetCompositeScore(SwarmTaskKind kind) const;  // Phase A.1: Composite scoring
    SwarmTaskKind GetBestTaskType() const;
    
    // Phase A.2: Confidence calculation
    double CalculateConfidence(uint32_t samples) const;
    
    // Phase A.5: Explainability
    struct SelectionExplanation {
        uint32_t agentId;
        SwarmTaskKind taskKind;
        double successRate;
        double confidence;
        uint32_t sampleCount;
        double avgLatency;
        double compositeScore;
        bool wasExploration;
        std::string reason;
    };
    SelectionExplanation ExplainSelection(SwarmTaskKind kind) const;
    
    // Serialization for persistence
    std::string ToJson() const;
    static AgentSelfModel FromJson(const std::string& json);
};

// Phase A.5: Routing decision log for explainability
struct RoutingDecision {
    uint64_t taskId;
    SwarmTaskKind taskKind;
    uint32_t selectedAgent;
    double selectedScore;
    std::vector<std::pair<uint32_t, double>> candidateScores;  // agent -> score
    bool wasExploration;
    std::string reason;
    std::chrono::steady_clock::time_point timestamp;
};

// Phase A: Self Model Registry - Manages self-models for all agents
// Phase A.1-A.5: Measurable learning with confidence, exploration, forgetting, explainability
class SelfModelRegistry {
public:
    static SelfModelRegistry& GetInstance();
    
    // Get or create self-model for an agent
    AgentSelfModel& GetOrCreateModel(uint32_t agentId);
    
    // Record execution results
    void RecordTaskSuccess(uint32_t agentId, SwarmTaskKind kind, int64_t latencyMs);
    void RecordTaskFailure(uint32_t agentId, SwarmTaskKind kind, const std::string& pattern);
    
    // Phase A.1: Query best agent for a task type (learned assignment with composite scoring)
    uint32_t GetBestAgentForTask(SwarmTaskKind kind) const;
    
    // Phase A.3: Select agent with exploration
    struct SelectionResult {
        uint32_t agentId;
        bool wasExploration;
        double exploitationScore;
        double explorationScore;
        std::string reason;
    };
    SelectionResult SelectAgentWithExploration(SwarmTaskKind kind, double explorationRate = 0.1) const;
    
    // Get agent rankings for a task
    std::vector<std::pair<uint32_t, double>> GetAgentRankings(SwarmTaskKind kind) const;
    
    // Phase A.5: Get detailed explanation for a selection
    AgentSelfModel::SelectionExplanation ExplainSelection(uint32_t agentId, SwarmTaskKind kind) const;
    
    // Phase A.5: Get routing decision history
    std::vector<RoutingDecision> GetRoutingHistory(uint64_t taskId) const;
    void LogRoutingDecision(const RoutingDecision& decision);
    
    // Phase A.1: Benchmark and validation
    struct BenchmarkResult {
        SwarmTaskKind taskKind;
        uint32_t totalRuns;
        std::map<uint32_t, uint32_t> assignmentCounts;  // agent -> count
        std::map<uint32_t, double> agentSuccessRates;   // agent -> rate
        std::map<uint32_t, double> agentLatencies;    // agent -> avg latency
        double overallSuccessRate;
        double avgLatency;
        std::string ToString() const;
    };
    BenchmarkResult RunBenchmark(SwarmTaskKind kind, uint32_t iterations = 100) const;
    void PrintBenchmarkReport(const BenchmarkResult& result) const;
    
    // Persistence
    void SaveToDisk(const std::string& path);
    void LoadFromDisk(const std::string& path);
    
    // Statistics
    size_t GetModelCount() const;
    void PrintPerformanceReport() const;
    
    // Phase A.1: Reset statistics (for testing)
    void ResetStatistics();
    
private:
    SelfModelRegistry() = default;
    std::map<uint32_t, AgentSelfModel> models_;
    mutable std::mutex mutex_;
    
    // Phase A.5: Routing decision log
    std::vector<RoutingDecision> routingHistory_;
    static constexpr size_t MAX_ROUTING_HISTORY = 10000;
    
    // Phase A.3: Random number generation for exploration
    mutable std::mt19937 rng_{std::random_device{}()};
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
    void SetLearnedAssignmentEnabled(bool enable);
    bool IsLearnedAssignmentEnabled() const { return learnedAssignmentEnabled_; }
    
    // Phase A.1-A.5: Get best worker with full learning pipeline
    uint32_t GetBestWorkerForTask(SwarmTaskKind kind) const;
    
    // Phase A.3: Set exploration rate (0.0-1.0, default 0.1)
    void SetExplorationRate(double rate) { explorationRate_ = std::clamp(rate, 0.0, 1.0); }
    double GetExplorationRate() const { return explorationRate_; }
    
    // Phase A.1: Benchmark and validation
    SelfModelRegistry::BenchmarkResult RunBenchmark(SwarmTaskKind kind, uint32_t iterations = 100) const;
    void PrintBenchmarkReport(SwarmTaskKind kind, uint32_t iterations = 100) const;
    
    // Phase A.5: Explain last routing decision
    std::string ExplainLastDecision() const;
    
    // Phase B.2 Batch 13-17: Adaptive Scheduling
    void AdaptExplorationRate(double convergenceScore);
    double GetTargetConvergenceRate() const { return targetConvergenceRate_; }
    void SetTargetConvergenceRate(double rate) { targetConvergenceRate_ = std::clamp(rate, 0.0, 1.0); }
    
    // Convergence-based task prioritization
    void PrioritizeConvergingTasks(bool enable) { prioritizeConverging_ = enable; }
    bool IsPrioritizingConverging() const { return prioritizeConverging_; }
    
    // Dynamic worker scaling based on convergence
    void SetAutoScaleWorkers(bool enable) { autoScaleWorkers_ = enable; }
    bool IsAutoScalingWorkers() const { return autoScaleWorkers_; }
    uint32_t GetOptimalWorkerCount(double convergenceScore) const;
    
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
    
    // Phase A.3: Exploration rate (10% default)
    double explorationRate_ = 0.1;
    
    // Phase A.5: Last routing decision for explainability
    mutable RoutingDecision lastDecision_;
    
    // Phase B.2 Batch 13-17: Adaptive Scheduling
    double targetConvergenceRate_ = 0.85;  // Target convergence score
    bool prioritizeConverging_ = true;      // Prioritize tasks that improve convergence
    bool autoScaleWorkers_ = false;         // Auto-scale worker count based on convergence
    double lastConvergenceScore_ = 0.0;     // Track for adaptation
    uint32_t minWorkers_ = 2;               // Minimum worker count
    uint32_t maxWorkers_ = 32;              // Maximum worker count
    
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

    // Phase 2: Unity Sequence - Execute full Order→Harmony pipeline
    struct UnitySequenceResult {
        bool success = false;
        double finalHarmonyIndex = 0.0;
        double finalEquilibriumStrength = 0.0;
        std::vector<std::pair<std::string, double>> stepMetrics; // step name → metric
        int64_t totalExecutionTimeMs = 0;
        std::string summary;
    };
    UnitySequenceResult ExecuteUnitySequence(InfinitePerfection::InfinitePerfectionEngine& engine);
    void LogUnitySequenceMetrics(const UnitySequenceResult& result) const;

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
