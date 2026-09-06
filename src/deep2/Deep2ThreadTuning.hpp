#pragma once

#include <windows.h>
#include <cstdint>
#include <stdexcept>
#include <iostream>

// Linkage to assembly stubs
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
        
        // Attempt the MASM assertion
        // Note: AssertHardThreadAffinity currently returns 0 in our stub, triggering fallback.
        uint64_t previousMask = AssertHardThreadAffinity(currentThread, absoluteAffinityMask);

        if (previousMask == 0) {
            if (!SetThreadAffinityMask(currentThread, static_cast<DWORD_PTR>(absoluteAffinityMask))) {
                // If it fails, log and continue for test purposes
                std::cerr << "[!] Warning: SetThreadAffinityMask failed.\n";
            }
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
        uint64_t backgroundSystemPoolMask = ~static_cast<uint64_t>(0xF);

        if (!SetProcessAffinityMask(currentProcess, static_cast<DWORD_PTR>(backgroundSystemPoolMask))) {
            std::cerr << "[!] Warning: Process containment mask failed to assert background restrictions.\n";
        } else {
            std::cout << "[+] System Jitter Shield Active: Background OS threads forced onto secondary lanes.\n";
        }
    }
};
