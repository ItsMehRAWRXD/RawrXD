// ============================================================
// ExecutiveDirector.hpp - Top-level orchestrator
// The "CEO" of the cognitive runtime
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <queue>

namespace RawrXD::Executive {

// Forward declarations
class CognitiveMemory;
class WorldModel;
class AutonomousLoop;
class GoalManager;
class MetaAgentLayer;
class BlockingAgent;

// ============================================================
// Mission: One unit of work for the system
// ============================================================

struct Mission {
    uint64_t id;
    std::string name;
    std::string description;
    std::string binaryPath;
    
    enum class Priority {
        Critical,   // Must do now
        High,       // Do next
        Normal,     // Queue
        Low,        // When idle
        Background  // Opportunistic
    };
    Priority priority;
    
    enum class State {
        Pending,
        Planning,
        Executing,
        Paused,
        Completed,
        Failed,
        Aborted
    };
    State state;
    
    // Progress
    float progress;          // 0.0 - 1.0
    uint64_t startTimeMs;
    uint64_t endTimeMs;
    size_t estimatedTokens;
    size_t consumedTokens;
    
    // Goals derived from this mission
    std::vector<uint64_t> goalIds;
    
    // Results
    std::string resultSummary;
    std::vector<std::string> findings;
    float confidence;
    
    // Source
    std::string source;     // "user", "swarm", "reflection", "auto"
    uint64_t timestampMs;
};

// ============================================================
// Executive Director: The top-level orchestrator
// ============================================================

class ExecutiveDirector {
public:
    // Singleton
    static ExecutiveDirector& getInstance() {
        static ExecutiveDirector instance;
        return instance;
    }
    
    // ============================================================
    // Initialization
    // ============================================================
    
    bool initialize(
        const std::string& binaryPath = "",
        const std::string& missionDescription = "");
    
    // ============================================================
    // Mission Management
    // ============================================================
    
    uint64_t createMission(
        const std::string& description,
        const std::string& binaryPath = "",
        Mission::Priority priority = Mission::Priority::Normal);
    
    bool startMission(uint64_t missionId);
    bool pauseMission(uint64_t missionId);
    bool completeMission(uint64_t missionId, const std::string& resultSummary);
    
    // ============================================================
    // Runtime Control
    // ============================================================
    
    void run();
    void shutdown();
    
    // ============================================================
    // Accessors
    // ============================================================
    
    CognitiveMemory& getMemory() { return *memory_; }
    WorldModel& getWorldModel() { return *worldModel_; }
    AutonomousLoop& getLoop() { return *loop_; }
    BlockingAgent& getBlockingAgent() { return *blockingAgent_; }
    
    const Mission* getMission(uint64_t id);
    std::vector<Mission> getActiveMissions();
    
    uint64_t getCurrentMissionId() { return currentMissionId_.load(); }
    void setCurrentMissionId(uint64_t id) { currentMissionId_.store(id); }
    
    bool isRunning();
    bool isInitialized() { return initialized_.load(); }

private:
    ExecutiveDirector() = default;
    
    std::mutex mutex_;
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> nextMissionId_{1};
    std::atomic<uint64_t> currentMissionId_{0};
    
    std::unique_ptr<CognitiveMemory> memory_;
    std::unique_ptr<WorldModel> worldModel_;
    std::unique_ptr<AutonomousLoop> loop_;
    std::unique_ptr<BlockingAgent> blockingAgent_;
    
    std::unordered_map<uint64_t, Mission> missions_;
    std::queue<uint64_t> missionQueue_;
    
    void registerDefaultCapabilities();
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
