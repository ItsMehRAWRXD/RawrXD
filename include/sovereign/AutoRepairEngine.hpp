#pragma once

#include <cstdint>
#include <functional>
#include <vector>
#include <string>
#include "Beaconism.hpp"

namespace Sovereign {

/**
 * @brief Repair action types
 */
enum class RepairAction : uint32_t {
    None = 0,
    RestartKVCache = 1,
    RestartExpertCache = 2,
    RestartVulkan = 3,
    RestartModelLoader = 4,
    ClearSharedMemory = 5,
    ResetScheduler = 6,
    FullRuntimeRestart = 7
};

/**
 * @brief Repair result
 */
struct RepairResult {
    RepairAction action;
    bool success;
    uint64_t timestamp;
    char message[256];
};

/**
 * @brief Auto-repair handler function type
 */
using RepairHandler = std::function<bool()>;

/**
 * @brief Sovereign Auto-Repair Engine
 * 
 * Automatically detects subsystem failures via Beaconism and executes
 * repair strategies. Maintains repair history and escalation policies.
 */
class AutoRepairEngine {
public:
    static AutoRepairEngine& Instance();

    /**
     * @brief Initialize the auto-repair engine
     */
    void Initialize();

    /**
     * @brief Shutdown the auto-repair engine
     */
    void Shutdown();

    /**
     * @brief Register a repair handler for a specific action
     * @param action The repair action
     * @param handler Function to execute for repair
     */
    void RegisterHandler(RepairAction action, RepairHandler handler);

    /**
     * @brief Process a beacon and trigger repairs if needed
     * @param beacon The beacon to analyze
     */
    void ProcessBeacon(const Beacon& beacon);

    /**
     * @brief Execute a repair action
     * @param action The repair to execute
     * @return true if repair succeeded
     */
    bool ExecuteRepair(RepairAction action);

    /**
     * @brief Get the last repair result
     */
    const RepairResult* GetLastRepair() const;

    /**
     * @brief Get repair history
     */
    const std::vector<RepairResult>& GetRepairHistory() const;

    /**
     * @brief Check if auto-repair is enabled
     */
    bool IsEnabled() const { return m_enabled; }

    /**
     * @brief Enable/disable auto-repair
     */
    void SetEnabled(bool enabled) { m_enabled = enabled; }

    /**
     * @brief Get failure count for a subsystem
     */
    uint32_t GetFailureCount(const std::string& subsystem) const;

    /**
     * @brief Reset all failure counters
     */
    void ResetFailureCounters();

private:
    AutoRepairEngine() = default;
    ~AutoRepairEngine() = default;

    struct SubsystemState {
        std::string name;
        uint64_t lastStartTime;
        uint64_t lastDoneTime;
        uint32_t failureCount;
        bool inProgress;
    };

    std::vector<SubsystemState> m_subsystems;
    std::vector<RepairResult> m_repairHistory;
    RepairResult m_lastRepair{};
    
    // Repair handlers
    std::unordered_map<RepairAction, RepairHandler> m_handlers;
    
    bool m_enabled = true;
    bool m_initialized = false;

    // Thresholds
    static constexpr uint32_t MAX_FAILURES_BEFORE_ESCALATION = 3;
    static constexpr uint64_t TIMEOUT_CYCLES = 5000000000ULL; // ~1.5s @ 3.3GHz

    SubsystemState* FindSubsystem(const std::string& name);
    RepairAction DetermineRepairAction(const std::string& subsystem, uint32_t failureCount);
    void LogRepair(const RepairResult& result);
};

} // namespace Sovereign
