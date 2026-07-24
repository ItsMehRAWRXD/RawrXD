// ============================================================================
// AutonomousLoop.hpp - The Core Cognitive Cycle
// while(alive) { Observe(); Think(); Plan(); Execute(); Learn(); Sleep(); }
// ============================================================================

#pragma once

#include <memory>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;

// ============================================================================
// Cycle Phase
// ============================================================================
enum class CyclePhase {
    OBSERVING,    // Gather information from environment
    THINKING,     // Process information, update beliefs
    PLANNING,     // Generate/update plans
    EXECUTING,    // Execute current actions
    REFLECTING,   // Evaluate performance
    LEARNING,     // Extract patterns, update models
    SLEEPING      // Idle/wait for next cycle
};

// ============================================================================
// Cycle Configuration
// ============================================================================
struct CycleConfig {
    // Phase durations (0 = run until completion)
    int observeDurationMs = 100;
    int thinkDurationMs = 500;
    int planDurationMs = 1000;
    int executeDurationMs = 0;  // Run until actions complete
    int reflectDurationMs = 500;
    int learnDurationMs = 1000;
    int sleepDurationMs = 100;
    
    // Adaptive timing
    bool adaptiveTiming = true;
    float urgencyMultiplier = 1.0f;  // < 1 = faster, > 1 = slower
    
    // Interrupts
    bool allowInterrupts = true;
    std::vector<std::string> interruptTriggers;
};

// ============================================================================
// Cycle Statistics
// ============================================================================
struct CycleStats {
    uint64_t totalCycles = 0;
    uint64_t cyclesByPhase[7] = {0};  // One per CyclePhase
    
    double averageCycleTimeMs = 0.0;
    double minCycleTimeMs = 0.0;
    double maxCycleTimeMs = 0.0;
    
    double averagePhaseTimeMs[7] = {0.0};
    
    uint64_t interruptions = 0;
    uint64_t replannings = 0;
    
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point lastCycleAt;
};

// ============================================================================
// Autonomous Loop - The while(alive) Core
// ============================================================================
class AutonomousLoop {
public:
    AutonomousLoop();
    ~AutonomousLoop();

    bool Initialize(ExecutiveDirector* director, const CycleConfig& config = {});
    void Shutdown();
    
    // Control
    void Start();
    void Stop();
    void Pause();
    void Resume();
    void Interrupt(const std::string& reason);
    
    bool IsRunning() const { return isRunning_.load(); }
    bool IsPaused() const { return isPaused_.load(); }
    CyclePhase GetCurrentPhase() const { return currentPhase_.load(); }
    
    // Phase handlers (can be overridden)
    void SetObserveHandler(std::function<void()> handler);
    void SetThinkHandler(std::function<void()> handler);
    void SetPlanHandler(std::function<void()> handler);
    void SetExecuteHandler(std::function<void()> handler);
    void SetReflectHandler(std::function<void()> handler);
    void SetLearnHandler(std::function<void()> handler);
    void SetSleepHandler(std::function<void()> handler);
    
    // Configuration
    void SetConfig(const CycleConfig& config);
    CycleConfig GetConfig() const;
    void SetUrgency(float urgency);  // 0.1 to 10.0
    
    // Statistics
    CycleStats GetStats() const;
    void ResetStats();
    
    // Diagnostics
    std::string GetPhaseName(CyclePhase phase) const;
    double GetCurrentPhaseElapsedMs() const;
    double GetEstimatedCycleCompletionMs() const;

private:
    void Loop();
    void ExecutePhase(CyclePhase phase);
    void TransitionTo(CyclePhase newPhase);
    
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
    
    std::atomic<bool> isRunning_{false};
    std::atomic<bool> isPaused_{false};
    std::atomic<bool> shouldShutdown_{false};
    std::atomic<CyclePhase> currentPhase_{CyclePhase::SLEEPING};
};

} // namespace Executive
} // namespace RawrXD
