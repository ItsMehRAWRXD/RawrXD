// ============================================================
// AutonomousLoop.hpp - The while(alive) cognitive loop
// The "brainstem rhythm" of the cognitive runtime
// ============================================================
//
// Each cycle:
//   1. PERCEIVE: Read findings from swarm, sensor data
//   2. THINK: Consult memory + world model + reason about state
//   3. PLAN: Generate goals and sub-goals
//   4. ACT: Dispatch actions to agents/swarm
//   5. REFLECT: Evaluate results, update confidence
//   6. LEARN: Update memory, consolidate, adjust
//
// The loop runs at ~1-10Hz (not too fast to waste tokens,
// not too slow to miss things)
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>
#include <mutex>

namespace RawrXD::Executive {

// Forward declarations
class CognitiveMemory;
class WorldModel;
class ExecutiveDirector;

// ============================================================
// Loop Phase
// ============================================================

enum class LoopPhase {
    Perceive,    // Read input from swarm/sensors
    Think,       // Consult memory + world model
    Plan,        // Generate/update goals
    Act,         // Dispatch to agents
    Reflect,     // Evaluate results
    Learn,       // Update memory + beliefs
    Idle,        // Nothing to do
    Emergency    // Something went wrong
};

// ============================================================
// Loop Cycle Result
// ============================================================

struct CycleResult {
    uint64_t cycleNumber;
    LoopPhase phase;
    uint64_t startTimeMs;
    uint64_t endTimeMs;
    float cycleDurationMs;
    
    // What happened
    std::vector<std::string> findings;       // New findings this cycle
    std::vector<std::string> actions;        // Actions dispatched
    std::vector<std::string> reflections;    // Self-evaluations
    std::vector<std::string> learnings;      // What was learned
    
    // Metrics
    size_t tokensConsumed;
    size_t tokensSaved;
    float efficiency;                       // tokensSaved / (saved + consumed)
    
    // Health
    bool healthy;
    std::string healthNote;
};

// ============================================================
// Autonomous Loop
// ============================================================

class AutonomousLoop {
public:
    AutonomousLoop(CognitiveMemory& memory,
                    WorldModel& worldModel,
                    ExecutiveDirector& director);
    
    ~AutonomousLoop();
    
    // ============================================================
    // Start/Stop
    // ============================================================
    
    void start();
    void stop();
    
    bool isRunning();
    bool isAlive();
    
    // ============================================================
    // Cycle control
    // ============================================================
    
    void setCycleRate(float hz);
    uint64_t getCycleCount();
    LoopPhase getCurrentPhase();

private:
    CognitiveMemory& memory_;
    WorldModel& worldModel_;
    ExecutiveDirector& director_;
    
    std::atomic<bool> alive_{false};
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> cycleCount_{0};
    LoopPhase currentPhase_ = LoopPhase::Idle;
    
    std::thread loopThread_;
    uint64_t cyclePeriodMs_ = 200;  // 5 Hz default
    
    void runLoop();
    
    // Phase implementations
    struct PerceiveResult {
        std::vector<std::string> findings;
        std::vector<std::string> alerts;
        std::vector<std::string> newBeliefs;
    };
    PerceiveResult perceive();
    
    struct ThinkResult {
        std::string currentUnderstanding;
        float overallConfidence;
        std::vector<std::string> relevantBeliefs;
        std::vector<std::string> pendingHypotheses;
        std::string recommendedAction;
    };
    ThinkResult think(const PerceiveResult& perceived);
    
    struct PlanResult {
        std::vector<std::string> actions;
        std::vector<std::string> goals;
        float estimatedCost;
    };
    PlanResult planActions(const ThinkResult& thoughts);
    
    struct ActResult {
        std::vector<std::string> dispatchedActions;
        size_t tokensConsumed;
        size_t tokensSaved;
        float efficiency;
    };
    ActResult act(const PlanResult& plan);
    
    struct ReflectResult {
        std::vector<std::string> notes;
        bool healthy;
        std::string healthNote;
        float performanceScore;
    };
    ReflectResult reflect(const ActResult& actions, const ThinkResult& thoughts);
    
    struct LearnResult {
        std::vector<std::string> notes;
        size_t beliefsUpdated;
        size_t memoriesStored;
    };
    LearnResult learn(const ReflectResult& reflections);
    
    bool hasActiveMissions();
    uint64_t currentTimeMs();
    
    uint64_t lastPerceiveMs_ = 0;
};

} // namespace RawrXD::Executive
