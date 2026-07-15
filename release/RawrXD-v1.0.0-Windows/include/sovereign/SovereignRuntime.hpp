#pragma once

#include <cstdint>

namespace Sovereign {

// Forward declarations
struct SmoketestResults;

/**
 * @brief SovereignRuntime - Core runtime controller for RawrXD
 * 
 * Manages initialization, shutdown, and command processing for all
 * sovereign subsystems. Uses shared memory for IPC with IDE.
 */
class SovereignRuntime {
public:
    /**
     * @brief Initialize all sovereign subsystems
     * 
     * Order of initialization:
     * 1. Beaconism (signaling fabric)
     * 2. Shared memory subsystems (Telemetry, Scheduler, Replay)
     * 3. Command interface
     * 4. Core subsystems (KV, Expert, Vulkan, Model)
     */
    static void Initialize();

    /**
     * @brief Shutdown all subsystems in reverse order
     */
    static void Shutdown();

    /**
     * @brief Process one tick of the runtime loop
     * 
     * Checks for commands from IDE and executes them.
     * Runs continuous maintenance cycle.
     * Call this regularly from the main loop.
     */
    static void Tick();
    
private:
    static void CheckCommands();
    static void RunMaintenanceCycle();

    /**
     * @brief Check if runtime is initialized and running
     */
    static bool IsRunning();

    /**
     * @brief Get results from last smoketest
     */
    static const SmoketestResults* GetSmoketestResults();

private:
    // Command handlers
    static void RunSmoketest();
    static void LoadModel(const wchar_t* path);
    static void HotSwapModel(const wchar_t* path);
    static void QuantizeModel(const wchar_t* path, uint32_t bits);
};

/**
 * @brief Smoketest results structure
 */
struct SmoketestResults {
    uint32_t testsRun;
    uint32_t testsPassed;
    uint32_t testsFailed;
    char lastError[256];
};

} // namespace Sovereign
