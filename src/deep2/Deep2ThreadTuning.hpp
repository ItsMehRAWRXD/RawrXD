#pragma once

#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <cstdio>
#include <chrono>

// Linkage to Deep2ThreadAffinity.asm (kernel32 SetThread/ProcessAffinityMask)
extern "C" {
    uint64_t AssertHardThreadAffinity(HANDLE threadHandle, uint64_t coreBitmask);
    void RestrictOsBackgroundTasks(HANDLE processHandle, uint64_t backgroundMask);
}

class Deep2ThreadTuning {
public:
    /**
     * Hard-pins the active inference loop to a dedicated physical core slot.
     */
    static void LockComputePipeline(uint32_t physicalCoreIndex, bool useSmtHyperThread) {
        if (physicalCoreIndex >= 8) {
            throw std::out_of_range("[!] Topology Error: Target core index sits outside physical 7800X3D CCD layout.");
        }

        uint32_t targetBitShift = (physicalCoreIndex * 2) + (useSmtHyperThread ? 1 : 0);
        uint64_t absoluteAffinityMask = (static_cast<uint64_t>(1) << targetBitShift);

        HANDLE currentThread = GetCurrentThread();
        DWORD_PTR procMask = 0, sysMask = 0;
        GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask);

        uint64_t previousMask = AssertHardThreadAffinity(currentThread, absoluteAffinityMask);
        // Read-back: second set returns current mask if prior set stuck
        uint64_t observedMask = AssertHardThreadAffinity(currentThread, absoluteAffinityMask);

        // #region agent log
        {
            FILE* df = fopen("g:/~dev/debug-1f4d81.log", "a");
            if (df) {
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                fprintf(df,
                    "{\"sessionId\":\"1f4d81\",\"runId\":\"post-fix\",\"hypothesisId\":\"B\","
                    "\"location\":\"Deep2ThreadTuning.hpp:LockComputePipeline\","
                    "\"message\":\"thread_affinity_apply\","
                    "\"data\":{\"tid\":%lu,\"requested\":%llu,\"previous\":%llu,\"observed\":%llu,"
                    "\"procMask\":%llu,\"sysMask\":%llu,\"match\":%d},"
                    "\"timestamp\":%lld}\n",
                    GetCurrentThreadId(),
                    (unsigned long long)absoluteAffinityMask,
                    (unsigned long long)previousMask,
                    (unsigned long long)observedMask,
                    (unsigned long long)procMask,
                    (unsigned long long)sysMask,
                    (observedMask == absoluteAffinityMask) ? 1 : 0,
                    (long long)ms);
                fclose(df);
            }
        }
        // #endregion

        if (previousMask == 0) {
            std::cerr << "[!] Warning: AssertHardThreadAffinity failed.\n";
        }

        if (!SetThreadPriority(currentThread, THREAD_PRIORITY_TIME_CRITICAL)) {
            std::cerr << "[!] Thread Warning: Failed to elevate processing thread to Realtime-Critical priority.\n";
        }

        SetThreadPriorityBoost(currentThread, TRUE);
    }

    /**
     * Isolates and pushes all non-critical background processes away from the processing engine.
     */
    static void VacuumSequestrationOS() {
        HANDLE currentProcess = GetCurrentProcess();
        uint64_t keepMask = static_cast<uint64_t>(0xF);
        DWORD_PTR procBefore = 0, sysBefore = 0;
        GetProcessAffinityMask(currentProcess, &procBefore, &sysBefore);
        RestrictOsBackgroundTasks(currentProcess, keepMask);
        DWORD_PTR procAfter = 0, sysAfter = 0;
        GetProcessAffinityMask(currentProcess, &procAfter, &sysAfter);

        // #region agent log
        {
            FILE* df = fopen("g:/~dev/debug-1f4d81.log", "a");
            if (df) {
                const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                fprintf(df,
                    "{\"sessionId\":\"1f4d81\",\"runId\":\"post-fix\",\"hypothesisId\":\"C\","
                    "\"location\":\"Deep2ThreadTuning.hpp:VacuumSequestrationOS\","
                    "\"message\":\"process_affinity_vacuum\","
                    "\"data\":{\"pid\":%lu,\"requested\":%llu,\"procBefore\":%llu,\"procAfter\":%llu,"
                    "\"sysMask\":%llu,\"match\":%d},"
                    "\"timestamp\":%lld}\n",
                    GetCurrentProcessId(),
                    (unsigned long long)keepMask,
                    (unsigned long long)procBefore,
                    (unsigned long long)procAfter,
                    (unsigned long long)sysAfter,
                    (procAfter == keepMask) ? 1 : 0,
                    (long long)ms);
                fclose(df);
            }
        }
        // #endregion
    }
};
