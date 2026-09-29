// Rawr hang watchdog authority implementation
// RawrXD RawrHangWatchdogAuthority - Gates rawr hang detection and monitoring

#include "cli/RawrHangWatchdog.h"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

namespace rawrxd::cli
{
    // Global hang watchdog authority state
    struct RawrHangWatchdogAuthorityState
    {
        bool entered = false;
        std::chrono::steady_clock::time_point startTime;
        std::string lastStage;
        std::chrono::steady_clock::time_point lastStageTime;
        uint64_t lastTokenIndex = 0;
        uint64_t generatedTokenCount = 0;
        bool processExited = false;
        bool hangDetected = false;
        uint32_t timeoutSec = 300; // 5 minutes default timeout
        std::string verdict = "PASS";
    };

    // Global state instance
    static RawrHangWatchdogAuthorityState g_hangWatchdogState;

    // Start hang watchdog
    void startHangWatchdog()
    {
        g_hangWatchdogState.entered = true;
        g_hangWatchdogState.startTime = std::chrono::steady_clock::now();
        g_hangWatchdogState.lastStageTime = g_hangWatchdogState.startTime;
        g_hangWatchdogState.lastStage = "COMMAND_START";
        std::cout << "[RawrHangWatchdogAuthority] Hang watchdog started" << std::endl;
    }

    // Record heartbeat
    void heartbeat()
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_hangWatchdogState.startTime).count();
        
        // Check for hang
        auto stageElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_hangWatchdogState.lastStageTime).count();
        if (stageElapsed > g_hangWatchdogState.timeoutSec * 1000) {
            g_hangWatchdogState.hangDetected = true;
            g_hangWatchdogState.verdict = "HANG";
            std::cout << "[RawrHangWatchdogAuthority] HANG DETECTED: Stage " << g_hangWatchdogState.lastStage 
                      << " stalled for " << stageElapsed << "ms (timeout: " << g_hangWatchdogState.timeoutSec << "s)" << std::endl;
        }
        
        g_hangWatchdogState.lastTokenIndex++;
        std::cout << "[RawrHangWatchdogAuthority] Heartbeat: elapsed=" << elapsed << "s, tokens=" << g_hangWatchdogState.generatedTokenCount 
                  << ", lastStage=" << g_hangWatchdogState.lastStage << ", hang=" << (g_hangWatchdogState.hangDetected ? "true" : "false") << std::endl;
    }

    // Stop hang watchdog
    void stopHangWatchdog()
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_hangWatchdogState.startTime).count();
        g_hangWatchdogState.processExited = true;
        std::cout << "[RawrHangWatchdogAuthority] Hang watchdog stopped: elapsed=" << elapsed << "s, tokens=" << g_hangWatchdogState.generatedTokenCount 
                  << ", hangDetected=" << (g_hangWatchdogState.hangDetected ? "true" : "false") << std::endl;
    }

    // Write hang receipt
    void writeHangReceipt()
    {
        std::cout << "[RawrHangWatchdogAuthority] Writing hang receipt:" << std::endl;
        std::cout << "  RAWRXD_RAWR_HANG_WATCHDOG_001=ENTERED" << std::endl;
        std::cout << "  TIMEOUT_SEC=" << g_hangWatchdogState.timeoutSec << std::endl;
        std::cout << "  LAST_STAGE=" << g_hangWatchdogState.lastStage << std::endl;
        std::cout << "  LAST_STAGE_AGE_MS=" 
                  << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - g_hangWatchdogState.lastStageTime).count() << std::endl;
        std::cout << "  LAST_TOKEN_INDEX=" << g_hangWatchdogState.lastTokenIndex << std::endl;
        std::cout << "  GENERATED_TOKEN_COUNT=" << g_hangWatchdogState.generatedTokenCount << std::endl;
        std::cout << "  PROCESS_EXITED=" << (g_hangWatchdogState.processExited ? "1" : "0") << std::endl;
        std::cout << "  HANG_DETECTED=" << (g_hangWatchdogState.hangDetected ? "1" : "0") << std::endl;
        std::cout << "  VERDICT=" << g_hangWatchdogState.verdict << std::endl;
    }
}