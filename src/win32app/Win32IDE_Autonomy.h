#pragma once

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include <functional>
#include <cstdint>
#include "IDELogger.h"
#include "Win32IDE_AgenticBridge.h"

// AutonomyManager: high-level autonomous orchestration layer.
// Responsibilities:
//  - Maintain goal & working memory
//  - Plan next action (very simple heuristic placeholder)
//  - Rate limit actions (max actions per minute)
//  - Execute actions via AgenticBridge (tool / prompt)
//  - Background loop thread when auto loop enabled
class AutonomyManager {
public:
    explicit AutonomyManager(AgenticBridge* bridge);
    ~AutonomyManager();

    void start();            // start manual autonomy (no loop)
    void stop();             // stop loop & flush state
    bool isRunning() const { return m_running.load(); }

    void enableAutoLoop(bool enable); // toggle background loop
    bool isAutoLoopEnabled() const { return m_autoLoop.load(); }

    void setGoal(const std::string& goal);
    std::string getGoal() const;

    void addObservation(const std::string& obs); // append memory item
    std::vector<std::string> getMemorySnapshot();

    void tick();              // single planning + execution step
    void setMaxActionsPerMinute(int v) { m_maxActionsPerMinute = v; }

    // Hook for external status surface
    std::string getStatus() const;
    bool hasDefinedCriteria() const { return m_criteriaDefined; }

private:
    bool loadAutonomyCriteria();
    static std::string sanitizeGoal(const std::string& goal);
    void loop();
    std::string planNextAction();
    void executeAction(const std::string& action);
    bool rateLimitAllow();

    AgenticBridge* m_bridge;
    std::atomic<bool> m_running;
    std::atomic<bool> m_autoLoop;

    std::string m_goal;
    std::vector<std::string> m_memory;

    std::thread m_loopThread;
    mutable std::mutex m_mutex;

    // Rate limiting
    int m_maxActionsPerMinute;
    int m_actionsThisWindow;
    std::chrono::steady_clock::time_point m_windowStart;

    // Criteria-aware maturity gating + runtime health telemetry
    bool m_criteriaLoaded = false;
    bool m_criteriaDefined = false;
    std::string m_criteriaPath;
    uint64_t m_totalTicks = 0;
    uint64_t m_skippedTicks = 0;
    uint64_t m_failedActions = 0;
    std::string m_lastAction;
    std::string m_lastError;
    std::chrono::steady_clock::time_point m_lastActionTs;
};
