#pragma once

#include "SwarmOrchestrator.hpp"
#include "ArchitectAgent.hpp"
#include "FrontendSquad.hpp"
#include "BackendCore.hpp"
#include "QAHive.hpp"
#include "ReviewerAgents.hpp"
#include "CinematicVibeEngine.hpp"
#include "DeepContextManager.hpp"
#include "OpenClawBridge.hpp"
#include "LegacyRefactorModule.hpp"
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <chrono>

namespace rawrxd {
namespace swarm {

// Kimi K2.6 Swarm Configuration
struct KimiSwarmConfig {
    // Agent counts
    size_t architectCount{1};
    size_t frontendCount{120};
    size_t backendCount{100};
    size_t qaCount{50};
    size_t reviewerCount{29};
    
    // Context settings
    size_t contextWindowSize{256000}; // 256K tokens
    size_t maxConcurrentTasks{300};
    
    // Performance settings
    size_t threadPoolSize{64};
    std::chrono::milliseconds taskTimeout{std::chrono::minutes(5)};
    std::chrono::milliseconds agentTimeout{std::chrono::minutes(10)};
    
    // Protocol settings
    std::string defaultProvider{"ollama"};
    std::string defaultModel{"deepseek-v3"};
    bool enableStreaming{true};
    bool enableToolCalling{true};
    
    // Feature flags
    bool enableVibeEngine{true};
    bool enableDeepContext{true};
    bool enableOpenClaw{true};
    bool enableLegacyRefactor{true};
    bool enableHotReload{true};
};

// Project request
struct ProjectRequest {
    std::string name;
    std::string description;
    std::vector<std::string> features;
    std::string targetPlatform; // "web", "desktop", "mobile", "fullstack"
    std::string scale; // "startup", "enterprise", "personal"
    std::string vibe; // "professional", "playful", "minimal", "bold", "elegant"
    std::vector<std::string> constraints;
    std::vector<std::string> integrations;
    std::string authStrategy{"jwt"};
    bool darkMode{false};
};

// Project result
struct ProjectResult {
    bool success{false};
    std::string errorMessage;
    
    // Generated artifacts
    std::map<std::string, std::string> files; // path -> content
    std::string architectureDoc;
    std::string apiDocumentation;
    std::string deploymentGuide;
    
    // Metrics
    std::chrono::milliseconds totalDuration{0};
    size_t totalFilesGenerated{0};
    size_t totalLinesOfCode{0};
    size_t testCoverage{0};
    
    // Quality metrics
    std::vector<std::string> securityFindings;
    std::vector<std::string> codeReviewComments;
    double codeQualityScore{0.0};
};

// Task for swarm execution
struct KimiTask {
    uint64_t id{0};
    std::string type; // "design", "frontend", "backend", "qa", "review"
    std::string description;
    std::string context;
    std::vector<uint64_t> dependencies;
    std::function<void(const std::string&)> callback;
    std::chrono::steady_clock::time_point created;
    std::chrono::milliseconds maxDuration{std::chrono::minutes(5)};
    int priority{0}; // Higher = more important
};

// Task result
struct KimiTaskResult {
    uint64_t taskId{0};
    bool success{false};
    std::string output;
    std::string error;
    std::chrono::milliseconds duration{0};
    std::string agentType;
    size_t agentId{0};
};

// Agent state
struct AgentState {
    std::string type;
    size_t id{0};
    bool active{false};
    std::string currentTask;
    std::chrono::steady_clock::time_point lastHeartbeat;
    size_t tasksCompleted{0};
    double avgTaskDurationMs{0.0};
};

// Swarm statistics
struct SwarmStats {
    size_t totalAgents{0};
    size_t activeAgents{0};
    size_t idleAgents{0};
    size_t totalTasksCompleted{0};
    size_t totalTasksFailed{0};
    double avgTaskDurationMs{0.0};
    size_t queueDepth{0};
    std::map<std::string, size_t> tasksByType;
};

// Kimi Swarm Orchestrator - 300-agent swarm coordinator
class KimiSwarmOrchestrator {
public:
    KimiSwarmOrchestrator(const KimiSwarmConfig& config = KimiSwarmConfig{});
    ~KimiSwarmOrchestrator();
    
    // Lifecycle
    bool initialize();
    void shutdown();
    bool isRunning() const { return running_.load(); }
    
    // Project generation
    ProjectResult generateProject(const ProjectRequest& request);
    std::future<ProjectResult> generateProjectAsync(const ProjectRequest& request);
    
    // Task management
    uint64_t submitTask(const KimiTask& task);
    std::vector<uint64_t> submitTasks(const std::vector<KimiTask>& tasks);
    bool cancelTask(uint64_t taskId);
    KimiTaskResult getTaskResult(uint64_t taskId);
    std::vector<KimiTaskResult> getTaskResults(const std::vector<uint64_t>& taskIds);
    
    // Dependency graph execution
    std::vector<KimiTaskResult> executeDependencyGraph(
        const std::map<uint64_t, KimiTask>& tasks);
    
    // Agent management
    std::vector<AgentState> getAgentStates() const;
    bool pauseAgent(const std::string& type, size_t id);
    bool resumeAgent(const std::string& type, size_t id);
    bool restartAgent(const std::string& type, size_t id);
    
    // Statistics
    SwarmStats getStats() const;
    void resetStats();
    
    // Configuration
    void updateConfig(const KimiSwarmConfig& config);
    KimiSwarmConfig getConfig() const;
    
    // Component access
    ArchitectAgent* getArchitect() { return architect_.get(); }
    FrontendSquad* getFrontendSquad() { return frontend_.get(); }
    BackendCore* getBackendCore() { return backend_.get(); }
    QAHive* getQAHive() { return qa_.get(); }
    ReviewerAgents* getReviewers() { return reviewers_.get(); }
    CinematicVibeEngine* getVibeEngine() { return vibeEngine_.get(); }
    DeepContextManager* getContextManager() { return contextManager_.get(); }
    OpenClawBridge* getOpenClaw() { return openClaw_.get(); }
    LegacyRefactorModule* getRefactorModule() { return refactorModule_.get(); }
    
    // Hot reload
    bool enableHotReload(const std::string& watchPath);
    bool disableHotReload();
    
    // Message passing
    void broadcastMessage(const std::string& type, const std::string& content);
    void sendMessageToAgent(const std::string& agentType, size_t agentId, 
                            const std::string& message);
    
    // Conflict resolution
    bool detectConflict(const std::string& file1, const std::string& file2);
    std::string resolveConflict(const std::string& file1, const std::string& file2);
    
    // Shared state
    void setSharedState(const std::string& key, const std::string& value);
    std::string getSharedState(const std::string& key) const;
    void clearSharedState();
    
private:
    KimiSwarmConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> nextTaskId_{1};
    
    // Agent components
    std::unique_ptr<ArchitectAgent> architect_;
    std::unique_ptr<FrontendSquad> frontend_;
    std::unique_ptr<BackendCore> backend_;
    std::unique_ptr<QAHive> qa_;
    std::unique_ptr<ReviewerAgents> reviewers_;
    
    // Support components
    std::unique_ptr<CinematicVibeEngine> vibeEngine_;
    std::unique_ptr<DeepContextManager> contextManager_;
    std::unique_ptr<OpenClawBridge> openClaw_;
    std::unique_ptr<LegacyRefactorModule> refactorModule_;
    
    // Thread pool
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> workQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    std::atomic<size_t> activeWorkers_{0};
    
    // Task tracking
    std::map<uint64_t, KimiTask> pendingTasks_;
    std::map<uint64_t, KimiTaskResult> completedTasks_;
    std::map<uint64_t, std::promise<KimiTaskResult>> taskPromises_;
    mutable std::mutex taskMutex_;
    
    // Agent states
    std::map<std::string, std::vector<AgentState>> agentStates_;
    mutable std::mutex agentMutex_;
    
    // Shared state
    std::map<std::string, std::string> sharedState_;
    mutable std::mutex stateMutex_;
    
    // Statistics
    SwarmStats stats_;
    mutable std::mutex statsMutex_;
    
    // Internal methods
    void workerLoop();
    void processTask(const KimiTask& task);
    void updateAgentState(const std::string& type, size_t id, bool active, 
                          const std::string& task = "");
    void recordTaskCompletion(const KimiTaskResult& result);
    std::vector<KimiTask> buildExecutionOrder(const std::map<uint64_t, KimiTask>& tasks);
    
    // Agent-specific task handlers
    KimiTaskResult handleArchitectTask(const KimiTask& task);
    KimiTaskResult handleFrontendTask(const KimiTask& task);
    KimiTaskResult handleBackendTask(const KimiTask& task);
    KimiTaskResult handleQATask(const KimiTask& task);
    KimiTaskResult handleReviewTask(const KimiTask& task);
};

// Global orchestrator instance
KimiSwarmOrchestrator* GetKimiSwarm();
void InitializeKimiSwarm(const KimiSwarmConfig& config = KimiSwarmConfig{});
void ShutdownKimiSwarm();

} // namespace swarm
} // namespace rawrxd
