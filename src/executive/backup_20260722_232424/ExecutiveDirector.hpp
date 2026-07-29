// ============================================================================
// ExecutiveDirector.hpp - The Brain of RawrXD
// Unified autonomous cognitive runtime coordinating all subsystems
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <chrono>

namespace RawrXD {
namespace Executive {

// Forward declarations
class CognitiveMemory;
class WorldModel;
class MetaAgentLayer;
class CapabilityRegistry;
class LearningEngine;
class MultiLevelPlanner;
class AutonomousLoop;
class GoalManager;
class ResourceManager;
class ReflectionEngine;
class RecoveryManager;

// ============================================================================
// Executive State
// ============================================================================
enum class ExecutiveState {
    INITIALIZING,
    OBSERVING,
    THINKING,
    PLANNING,
    EXECUTING,
    REFLECTING,
    LEARNING,
    SLEEPING,
    SHUTTING_DOWN,
    ERROR
};

// ============================================================================
// Mission Context
// ============================================================================
struct MissionContext {
    std::string missionId;
    std::string objective;
    std::string domain;           // "reverse_engineering", "code_analysis", etc.
    float priority = 1.0f;
    float confidenceThreshold = 0.7f;
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point deadline;
    std::vector<std::string> requiredCapabilities;
    std::vector<std::string> constraints;
    
    // Mutable state
    float currentConfidence = 0.0f;
    std::string status = "pending";
    int retryCount = 0;
};

// ============================================================================
// Executive Configuration
// ============================================================================
struct ExecutiveConfig {
    // Timing
    int observationIntervalMs = 100;
    int thinkingIntervalMs = 500;
    int planningIntervalMs = 1000;
    int executionIntervalMs = 50;
    int reflectionIntervalMs = 5000;
    int learningIntervalMs = 30000;
    int sleepIntervalMs = 100;
    
    // Thresholds
    float minConfidenceForExecution = 0.6f;
    float minConfidenceForCompletion = 0.85f;
    float maxRetryCount = 3;
    
    // Memory
    size_t maxEpisodeMemorySize = 10000;
    size_t maxSemanticMemorySize = 100000;
    
    // Autonomy
    bool enableContinuousOperation = true;
    bool enableSelfModification = true;
    bool enablePluginLoading = true;
};

// ============================================================================
// Executive Director - The Central Cognitive Controller
// ============================================================================
class ExecutiveDirector {
public:
    ExecutiveDirector();
    ~ExecutiveDirector();

    // Lifecycle
    bool Initialize(const ExecutiveConfig& config = {});
    void Shutdown();
    
    // Main entry point - starts the autonomous loop
    void StartAutonomousOperation();
    void StopAutonomousOperation();
    bool IsRunning() const { return isRunning_.load(); }
    
    // Mission management
    std::string SubmitMission(const std::string& objective, 
                               const std::string& domain = "general",
                               float priority = 1.0f);
    void CancelMission(const std::string& missionId);
    MissionContext* GetMission(const std::string& missionId);
    std::vector<MissionContext> GetActiveMissions();
    
    // Subsystem access
    CognitiveMemory* GetMemory() { return cognitiveMemory_.get(); }
    WorldModel* GetWorldModel() { return worldModel_.get(); }
    MetaAgentLayer* GetMetaAgentLayer() { return metaAgentLayer_.get(); }
    CapabilityRegistry* GetCapabilityRegistry() { return capabilityRegistry_.get(); }
    LearningEngine* GetLearningEngine() { return learningEngine_.get(); }
    MultiLevelPlanner* GetPlanner() { return planner_.get(); }
    
    // State
    ExecutiveState GetCurrentState() const { return currentState_.load(); }
    std::string GetStateString() const;
    
    // Statistics
    struct Stats {
        uint64_t totalMissions = 0;
        uint64_t completedMissions = 0;
        uint64_t failedMissions = 0;
        uint64_t totalCycles = 0;
        uint64_t learningEvents = 0;
        double averageCycleTimeMs = 0.0;
        double uptimeSeconds = 0.0;
    };
    Stats GetStats() const;

private:
    // Core subsystems
    std::unique_ptr<CognitiveMemory> cognitiveMemory_;
    std::unique_ptr<WorldModel> worldModel_;
    std::unique_ptr<MetaAgentLayer> metaAgentLayer_;
    std::unique_ptr<CapabilityRegistry> capabilityRegistry_;
    std::unique_ptr<LearningEngine> learningEngine_;
    std::unique_ptr<MultiLevelPlanner> planner_;
    std::unique_ptr<AutonomousLoop> autonomousLoop_;
    
    // Management components
    std::unique_ptr<GoalManager> goalManager_;
    std::unique_ptr<ResourceManager> resourceManager_;
    std::unique_ptr<ReflectionEngine> reflectionEngine_;
    std::unique_ptr<RecoveryManager> recoveryManager_;
    
    // State
    std::atomic<ExecutiveState> currentState_{ExecutiveState::INITIALIZING};
    std::atomic<bool> isRunning_{false};
    std::atomic<bool> shouldShutdown_{false};
    
    // Threading
    std::unique_ptr<std::thread> executiveThread_;
    mutable std::mutex stateMutex_;
    std::condition_variable stateCv_;
    
    // Configuration
    ExecutiveConfig config_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    Stats stats_;
    std::chrono::steady_clock::time_point startTime_;
    
    // Internal methods
    void ExecutiveLoop();
    void TransitionTo(ExecutiveState newState);
    bool ValidateSubsystems();
};

// Singleton access
ExecutiveDirector* GetExecutiveDirector();
void InitializeExecutiveDirector(const ExecutiveConfig& config = {});
void ShutdownExecutiveDirector();

} // namespace Executive
} // namespace RawrXD
