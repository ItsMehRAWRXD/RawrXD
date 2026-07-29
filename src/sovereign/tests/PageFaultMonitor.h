// PageFaultMonitor.h
// Windows-based Page Fault Monitor for Hybrid Memory Aperture Validation
// Part of the Sovereign Test Suite for Deep2 Engine validation

#ifndef PAGEFAULTMONITOR_H
#define PAGEFAULTMONITOR_H

#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <cstdint>

namespace Sovereign {

/**
 * @class PageFaultMonitor
 * @brief Tracks memory page faults during inference to validate hybrid memory aperture isolation
 * 
 * This class uses GetProcessMemoryInfo to track the memory behavior of the Deep2 kernel
 * as it executes. If the hybrid memory aperture is working correctly, the PageFaultCount
 * should remain near-zero during the forward pass.
 * 
 * Usage:
 *   PageFaultMonitor monitor;
 *   monitor.Snapshot();  // Before inference
 *   engine.RunInference(...);
 *   DWORD faults = monitor.GetFaultDelta();  // Should be 0 for isolated aperture
 */
class PageFaultMonitor {
    PROCESS_MEMORY_COUNTERS_EX counters;
    bool initialized;

public:
    PageFaultMonitor() : initialized(false) {
        ZeroMemory(&counters, sizeof(counters));
    }

    /**
     * @brief Capture baseline memory counters
     * Call this before the operation you want to monitor
     */
    bool Snapshot() {
        if (GetProcessMemoryInfo(GetCurrentProcess(), 
                                 (PROCESS_MEMORY_COUNTERS*)&counters, 
                                 sizeof(counters))) {
            initialized = true;
            return true;
        }
        std::cerr << "[!] PageFaultMonitor: Failed to capture snapshot" << std::endl;
        return false;
    }

    /**
     * @brief Get the delta in page faults since the last Snapshot()
     * @return Number of page faults since snapshot (0 = perfect isolation)
     */
    DWORD GetFaultDelta() {
        if (!initialized) {
            std::cerr << "[!] PageFaultMonitor: Snapshot() not called before GetFaultDelta()" << std::endl;
            return (DWORD)-1;
        }
        
        PROCESS_MEMORY_COUNTERS_EX current;
        ZeroMemory(&current, sizeof(current));
        
        if (!GetProcessMemoryInfo(GetCurrentProcess(), 
                                  (PROCESS_MEMORY_COUNTERS*)&current, 
                                  sizeof(current))) {
            std::cerr << "[!] PageFaultMonitor: Failed to get current counters" << std::endl;
            return (DWORD)-1;
        }
        
        return (current.PageFaultCount - counters.PageFaultCount);
    }

    /**
     * @brief Get detailed memory statistics
     */
    void PrintStats() {
        PROCESS_MEMORY_COUNTERS_EX current;
        if (GetProcessMemoryInfo(GetCurrentProcess(), 
                                 (PROCESS_MEMORY_COUNTERS*)&current, 
                                 sizeof(current))) {
            std::cout << "    Working Set: " << (current.WorkingSetSize / (1024*1024)) << " MB" << std::endl;
            std::cout << "    Peak Working Set: " << (current.PeakWorkingSetSize / (1024*1024)) << " MB" << std::endl;
            std::cout << "    Page Faults (total): " << current.PageFaultCount << std::endl;
        }
    }

    /**
     * @brief Validate that the hybrid memory aperture is isolated
     * @param maxAllowedFaults Maximum acceptable page faults (default: 0)
     * @return true if aperture is isolated (faults <= maxAllowedFaults)
     */
    bool ValidateAperture(DWORD maxAllowedFaults = 0) {
        DWORD faults = GetFaultDelta();
        if (faults == (DWORD)-1) return false;
        
        if (faults > maxAllowedFaults) {
            std::cout << "[!] Hybrid Memory Breach: " << faults << " page faults detected" << std::endl;
            return false;
        }
        
        std::cout << "[+] Hybrid Memory Aperture isolated: " << faults << " faults (<= " << maxAllowedFaults << ")" << std::endl;
        return true;
    }
};

} // namespace Sovereign

#endif // PAGEFAULTMONITOR_H
