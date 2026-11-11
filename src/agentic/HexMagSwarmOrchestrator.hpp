// =============================================================================
// HexMagSwarmOrchestrator.hpp - Unified Multi-Agent Coding System
// Connects: SubAgentManager, AgentOrchestrator, CEOAgent, AdvancedAgentCoordinator,
// Deep2Engine, Native Toolchain, HexMagRepeatTunerBridge
// =============================================================================
//
// BUILD STATUS — READ FIRST
//
// This header and its .cpp are the *unified orchestration layer* for
// RAWRXD_HEXMAG_SWARM_INTEGRATION_001. They are intentionally written against
// the real subsystems named above, and they are NOT part of any CMake target.
//
// They currently DO NOT COMPILE, because the following headers they include were
// deleted from the tree by concurrent work on this repository:
//
//   src/subagent_core.h
//   src/agentic/AgentOrchestrator.h
//   src/agents/CEOAgent.hpp
//   src/agentic/AdvancedAgentCoordinator.h
//   src/agentic/HexMagAction.hpp
//   src/agentic/HexMagRepeatTunerBridge.hpp
//   src/agentic/ToolRegistry.hpp
//   src/Deep2Engine.h
//
// As soon as those sources are restored, this layer becomes the integration
// entry point that wires SubAgentManager + AgentOrchestrator + CEOAgent +
// AdvancedAgentCoordinator + Deep2 + the native toolchain together (gaps G1-G4
// and G9 in certs/RAWRXD_HEXMAG_SWARM_INTEGRATION_001.md).
//
// A working, self-contained certification of the same swarm pipeline (planner ->
// falsifier -> epistemic -> resolver -> test_driven -> consistency, with the
// dependency-aware scheduler, shared context, conflict resolver, evidence
// ledger and RepeatTuner) is in certs/hexmag_swarm_cert.cpp and currently
// PASSES. See certs/RAWRXD_HEXMAG_SWARM_INTEGRATION_001.md.
// =============================================================================

#pragma once

#include "../subagent_core.h"
#include "AgentOrchestrator.h"
#include "../agents/CEOAgent.hpp"
#include "AdvancedAgentCoordinator.h"
#include "HexMagAction.hpp"
#include "HexMagRepeatTunerBridge.hpp"
#include "ToolRegistry.hpp"
#include "../Deep2Engine.h"
#include "ToolRegistry.hpp"
// Certified resilience subsystems (RAWRXD_AGENT_RELIABILITY_001).
// hexmag_resilience_bridge.hpp pulls these in transitively, but this header
// names the types directly (DelegationManager, AgentCapability), so it needs
// its own include to stay self-contained.
#include "../agent/delegated_agents.hpp"
#include "../agent/adaptive_retry.hpp"
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>
#include <future>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace HexMag {

// Forward declarations
class NativeToolExecutor;
class Deep2InferenceRouter;
class SwarmContextManager;
class ConflictResolver;
class IDEReporter;

// =============================================================================
// Swarm Execution Result
// =============================================================================
struct SwarmExecutionResult {
    bool success = false;
    std::string mergedOutput;
    std::vector<std::string> agentResults;
    std::vector<std::string> errors;
    std::vector<std::string> toolExecutions;
    std::vector<std::string> buildResults;
    std::vector<std::string> testResults;
    double totalElapsedMs = 0.0;
    int agentsSpawned = 0;
    int agentsCompleted = 0;
    int agentsFailed = 0;
    nlohmann::json evidence;  // Tool outputs, build logs, test logs
};

// =============================================================================
// Specialist Configuration
// =============================================================================
struct SpecialistConfig {
    std::string name;
    RawrXD::Agentic::Specialist specialistType;
    std::string systemPrompt;
    std::vector<std::string> allowedTools;
    double temperature = 0.2;
    double topP = 0.95;
    int maxTokens = 4096;
    int maxRetries = 3;
};

// =============================================================================
// Task Decomposition Result
// =============================================================================
struct TaskDecomposition {
    std::string originalTask;
    std::vector<std::string> subtasks;
    std::vector<std::pair<int, int>> dependencies;  // (taskIndex, dependsOnIndex)
    std::vector<RawrXD::Agentic::Specialist> assignedSpecialists;
    std::vector<std::string> requiredTools;
    RawrXD::Agentic::TaskPriority priority = RawrXD::Agentic::TaskPriority::NORMAL;
};

// =============================================================================
// HexMag Swarm Orchestrator - Main Integration Point
// =============================================================================
class HexMagSwarmOrchestrator {
public:
    using ProgressCallback = std::function<void(const std::string& stage, float percent, const std::string& detail)>;
    using ToolActivityCallback = std::function<void(const std::string& agentId, const std::string& tool, const std::string& status)>;
    using CompletionCallback = std::function<void(const SwarmExecutionResult& result)>;

    HexMagSwarmOrchestrator();
    ~HexMagSwarmOrchestrator();

    // ---- Initialization ----
    bool initialize(const std::string& workingDir = ".");
    void shutdown();

    // ---- Main Entry: Execute User Request through Full Swarm ----
    // User request -> Planning -> Parallel execution -> Verification -> Final result
    SwarmExecutionResult executeSwarmTask(
        const std::string& userRequest,
        ProgressCallback onProgress = nullptr,
        ToolActivityCallback onToolActivity = nullptr);

    // Async version
    std::future<SwarmExecutionResult> executeSwarmTaskAsync(
        const std::string& userRequest,
        ProgressCallback onProgress = nullptr,
        ToolActivityCallback onToolActivity = nullptr,
        CompletionCallback onComplete = nullptr);

    // ---- Specialist Management ----
    void registerSpecialist(const SpecialistConfig& config);
    std::vector<SpecialistConfig> getSpecialists() const;
    SpecialistConfig getDefaultSpecialist(RawrXD::Agentic::Specialist type) const;

    // ---- Deep2 Integration ----
    void setDeep2Engine(Deep2::Deep2Engine* engine);
    Deep2::Deep2Engine* getDeep2Engine() const;

    // ---- Native Toolchain ----
    void setNativeToolExecutor(NativeToolExecutor* executor);
    NativeToolExecutor* getNativeToolExecutor() const;

    // ---- IDE Integration ----
    void setIDEReporter(IDEReporter* reporter);
    void reportProgress(const std::string& stage, float percent, const std::string& detail);
    void reportToolActivity(const std::string& agentId, const std::string& tool, const std::string& status);

    // ---- Configuration ----
    void setMaxParallelAgents(int max) { m_maxParallelAgents = max; }
    void setDefaultTimeoutMs(int ms) { m_defaultTimeoutMs = ms; }
    void setEnableAutoBuild(bool enable) { m_enableAutoBuild = enable; }
    void setEnableAutoTest(bool enable) { m_enableAutoTest = enable; }
    void setEnableConflictResolution(bool enable) { m_enableConflictResolution = enable; }

    // ---- Status ----
    bool isInitialized() const { return m_initialized; }
    std::string getStatusSummary() const;
    nlohmann::json getMetrics() const;

private:
    // ---- Core Pipeline Stages ----
    TaskDecomposition decomposeTask(const std::string& userRequest);
    std::vector<std::string> createSpecialistPrompts(const TaskDecomposition& decomposition);
    SwarmExecutionResult executeParallelAgents(const std::vector<std::string>& prompts, const TaskDecomposition& decomposition);
    SwarmExecutionResult verifyAndMergeResults(const SwarmExecutionResult& rawResult, const TaskDecomposition& decomposition);
    bool runVerificationCycle(SwarmExecutionResult& result, const TaskDecomposition& decomposition);

    // ---- Specialist Routing ----
    std::string routeToDeep2(const std::string& prompt, const SpecialistConfig& specialist, const rawrxd::agentic::hexmag::GenProfile& profile);
    std::string executeWithRepeatTuner(const std::string& task, const SpecialistConfig& specialist);

    // ---- Resilience integration ----
    // Maps a specialist to the capabilities its delegated agent must hold.
    static std::vector<RawrXD::Delegation::AgentCapability> delegationCapabilities(
        const SpecialistConfig& spec);
    // Delegated-agent concurrency and depth limits.
    static constexpr int kDelegationConcurrency = 4;
    static constexpr int kDelegationMaxDepth = 3;

    // ---- Tool Execution ----
    bool executeNativeTool(const std::string& toolName, const nlohmann::json& args, std::string& output);
    bool executeBuild(const std::string& target, const std::string& config, std::string& output);
    bool executeTests(const std::string& suite, std::string& output);
    bool executeShell(const std::string& command, bool powershell, std::string& output);

    // ---- Conflict Resolution ----
    bool detectConflicts(const std::vector<std::string>& edits);
    bool resolveConflicts(std::vector<std::string>& edits);

    // ---- Evidence Collection ----
    void collectEvidence(SwarmExecutionResult& result, const std::string& agentId, const std::string& tool, const std::string& output, bool success);

    // ---- Component References ----
    std::unique_ptr<SubAgentManager> m_subAgentManager;
    std::unique_ptr<Agent::AgentOrchestrator> m_agentOrchestrator;
    std::unique_ptr<Agents::CEOAgent> m_ceoAgent;
    // AdvancedAgentCoordinator::instance() is a process-wide singleton owned by
    // the coordinator itself, so this is a NON-OWNING observer. Holding it in a
    // unique_ptr both lacked a valid operator=(raw*) and incorrectly transferred
    // ownership of a shared singleton.
    Agentic::AdvancedAgentCoordinator* m_advancedCoordinator = nullptr;
    Deep2::Deep2Engine* m_deep2Engine = nullptr;
    NativeToolExecutor* m_nativeToolExecutor = nullptr;
    std::unique_ptr<NativeToolExecutor> m_ownedNativeExecutor;
    IDEReporter* m_ideReporter = nullptr;
    std::unique_ptr<SwarmContextManager> m_contextManager;
    std::unique_ptr<ConflictResolver> m_conflictResolver;

    // Delegated-agent accounting for spawned specialists (quotas, depth cap,
    // lifecycle). Created lazily on first parallel execution.
    std::unique_ptr<RawrXD::Delegation::DelegationManager> m_delegationManager;

    // ---- Specialist Registry ----
    std::unordered_map<RawrXD::Agentic::Specialist, SpecialistConfig> m_specialists;
    mutable std::mutex m_specialistMutex;

    // ---- Configuration ----
    int m_maxParallelAgents = 4;
    int m_defaultTimeoutMs = 120000;
    bool m_enableAutoBuild = true;
    bool m_enableAutoTest = true;
    bool m_enableConflictResolution = true;
    std::string m_workingDir;

    // ---- State ----
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    ProgressCallback m_progressCallback;
    ToolActivityCallback m_toolActivityCallback;
    CompletionCallback m_completionCallback;

    // ---- Metrics ----
    std::atomic<uint64_t> m_totalTasks{0};
    std::atomic<uint64_t> m_successfulTasks{0};
    std::atomic<uint64_t> m_failedTasks{0};
    std::atomic<double> m_totalLatencyMs{0.0};
};

// =============================================================================
// Native Tool Executor - Wires HexMag Actions to Real Operations
// =============================================================================
class NativeToolExecutor {
public:
    virtual ~NativeToolExecutor() = default;

    // File operations
    virtual bool readFile(const std::string& path, std::string& content) = 0;
    virtual bool writeFile(const std::string& path, const std::string& content) = 0;
    virtual bool listDir(const std::string& path, std::vector<std::string>& entries) = 0;

    // Search/navigation
    virtual bool grepFiles(const std::string& pattern, const std::string& path, std::string& results) = 0;
    virtual bool searchFiles(const std::string& query, const std::string& path, std::string& results) = 0;
    virtual bool referenceSymbol(const std::string& symbol, std::string& results) = 0;

    // Build operations
    virtual bool compile(const std::string& target, const std::string& config, std::string& output) = 0;
    virtual bool runBuild(const std::string& target, const std::string& config, std::string& output) = 0;
    virtual bool cleanBuild(const std::string& target, std::string& output) = 0;

    // Test operations
    virtual bool runTests(const std::string& suite, std::string& output) = 0;

    // Shell operations
    virtual bool executeShell(const std::string& command, bool powershell, std::string& output) = 0;

    // Analysis operations
    virtual bool analyzeBinary(const std::string& path, std::string& output) = 0;
    virtual bool verifyCode(const std::string& path, std::string& output) = 0;
};

// =============================================================================
// Deep2 Inference Router - Routes Specialists through Local Inference
// =============================================================================
class Deep2InferenceRouter {
public:
    explicit Deep2InferenceRouter(Deep2::Deep2Engine* engine = nullptr) : m_engine(engine) {}

    void setEngine(Deep2::Deep2Engine* engine) { m_engine = engine; }

    // Generate completion for a specialist with HexMag repeat tuner profile
    std::string generateForSpecialist(
        const std::string& prompt,
        const SpecialistConfig& specialist,
        const rawrxd::agentic::hexmag::GenProfile& profile);

    // Streaming generation
    void generateForSpecialistStream(
        const std::string& prompt,
        const SpecialistConfig& specialist,
        const rawrxd::agentic::hexmag::GenProfile& profile,
        std::function<void(const std::string& token)> onToken,
        std::function<void(const std::string& fullResponse)> onComplete,
        std::function<void(const std::string& error)> onError);

    // Get model info
    bool isReady() const { return m_engine && m_engine->isModelLoaded(); }
    std::string getModelPath() const { return m_engine ? m_engine->getModelPath() : ""; }

private:
    Deep2::Deep2Engine* m_engine = nullptr;

    Deep2::GenerationOptions profileToOptions(const rawrxd::agentic::hexmag::GenProfile& profile);
    std::string buildSpecialistPrompt(const std::string& userPrompt, const SpecialistConfig& specialist);
};

// =============================================================================
// Swarm Context Manager - Shared Context Across Agents
// =============================================================================
class SwarmContextManager {
public:
    struct SharedContext {
        std::string taskId;
        std::string originalRequest;
        nlohmann::json taskState;
        std::vector<std::string> agentMessages;
        std::vector<std::string> evidence;  // Tool outputs, build logs, test results
        std::unordered_map<std::string, std::string> fileContents;  // Cached file reads
        std::mutex mutex;
    };

    std::shared_ptr<SharedContext> createContext(const std::string& taskId, const std::string& request);
    std::shared_ptr<SharedContext> getContext(const std::string& taskId);
    void removeContext(const std::string& taskId);

    // Context operations
    void addAgentMessage(std::shared_ptr<SharedContext> ctx, const std::string& agentId, const std::string& message);
    void addEvidence(std::shared_ptr<SharedContext> ctx, const std::string& evidence);
    void cacheFileContent(std::shared_ptr<SharedContext> ctx, const std::string& path, const std::string& content);
    std::string getCachedFileContent(std::shared_ptr<SharedContext> ctx, const std::string& path);
    nlohmann::json getTaskState(std::shared_ptr<SharedContext> ctx);
    void updateTaskState(std::shared_ptr<SharedContext> ctx, const nlohmann::json& state);

private:
    std::unordered_map<std::string, std::shared_ptr<SharedContext>> m_contexts;
    std::mutex m_contextsMutex;
};

// =============================================================================
// Conflict Resolver - Detects and Resolves Overlapping Edits
// =============================================================================
class ConflictResolver {
public:
    struct Edit {
        std::string filePath;
        std::string oldContent;
        std::string newContent;
        size_t startLine;
        size_t endLine;
        std::string agentId;
    };

    struct Conflict {
        std::string filePath;
        std::vector<Edit> conflictingEdits;
        std::string resolution;  // "manual", "merge", "first_wins", "last_wins"
    };

    // Detect conflicts between edits from different agents
    std::vector<Conflict> detectConflicts(const std::vector<Edit>& edits);

    // Resolve conflicts using specified strategy
    std::vector<Edit> resolveConflicts(const std::vector<Conflict>& conflicts, const std::string& strategy = "merge");

    // Three-way merge for overlapping edits
    bool threeWayMerge(const std::string& base, const std::string& ours, const std::string& theirs, std::string& merged);

private:
    bool editsOverlap(const Edit& a, const Edit& b);
    std::string mergeEdits(const std::vector<Edit>& edits);
};

// =============================================================================
// IDE Reporter - Exposes Agent Activity to Win32 IDE
// =============================================================================
class IDEReporter {
public:
    virtual ~IDEReporter() = default;

    // Task lifecycle
    virtual void onTaskStarted(const std::string& taskId, const std::string& description) = 0;
    virtual void onTaskProgress(const std::string& taskId, const std::string& stage, float percent, const std::string& detail) = 0;
    virtual void onTaskCompleted(const std::string& taskId, bool success, const std::string& summary) = 0;

    // Agent lifecycle
    virtual void onAgentSpawned(const std::string& agentId, const std::string& parentId, const std::string& description, RawrXD::Agentic::Specialist specialist) = 0;
    virtual void onAgentProgress(const std::string& agentId, float progress, const std::string& status) = 0;
    virtual void onAgentCompleted(const std::string& agentId, bool success, const std::string& result) = 0;

    // Tool activity
    virtual void onToolCall(const std::string& agentId, const std::string& tool, const std::string& args) = 0;
    virtual void onToolResult(const std::string& agentId, const std::string& tool, bool success, const std::string& output) = 0;

    // Build/Test activity
    virtual void onBuildStarted(const std::string& target, const std::string& config) = 0;
    virtual void onBuildCompleted(const std::string& target, bool success, const std::string& output) = 0;
    virtual void onTestStarted(const std::string& suite) = 0;
    virtual void onTestCompleted(const std::string& suite, bool success, const std::string& output) = 0;

    // Swarm activity
    virtual void onSwarmStarted(const std::string& swarmId, int taskCount) = 0;
    virtual void onSwarmProgress(const std::string& swarmId, float progress, int completed, int total) = 0;
    virtual void onSwarmCompleted(const std::string& swarmId, bool allSucceeded, const std::string& mergedResult) = 0;
};

} // namespace HexMag
} // namespace RawrXD