/*===========================================================================
 * AdaptiveContextController.cpp
 * VAL-028: Adaptive Runtime Optimization - Implementation
 * 
 * Dynamic context sizing with dedicated monitor thread.
 * Lock-free telemetry using Win32 Interlocked operations.
 *===========================================================================*/

#include "AdaptiveContextController.h"
#include <stdio.h>
#include <stdlib.h>

/*===========================================================================
 * GLOBAL STATE
 *=========================================================================*/
static struct {
    AC_Controller           controller;
    HANDLE                  hMonitorThread;
    HANDLE                  hTimer;
    HANDLE                  hShutdownEvent;
    BOOL                    initialized;
    
    // Dynamically loaded APIs
    HMODULE                 hPsapi;
    typedef BOOL (WINAPI *PFN_GetProcessMemoryInfo)(HANDLE, PPROCESS_MEMORY_COUNTERS, DWORD);
    PFN_GetProcessMemoryInfo pfnGetProcessMemoryInfo;
} g_adaptive;

/*===========================================================================
 * MONITOR THREAD
 *=========================================================================*/

static DWORD WINAPI MonitorThreadProc(LPVOID lpParam) {
    (void)lpParam;
    
    HANDLE handles[2] = { g_adaptive.hTimer, g_adaptive.hShutdownEvent };
    
    while (TRUE) {
        // Wait for timer signal or shutdown
        DWORD waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        
        if (waitResult == WAIT_OBJECT_0 + 1) {
            // Shutdown event signaled
            break;
        }
        
        if (waitResult == WAIT_OBJECT_0) {
            // Timer fired - poll telemetry
            AC_UpdateMemoryMetrics(&g_adaptive.controller);
            
            // Calculate and apply new window if needed
            uint32_t targetWindow = AC_GetTargetWindow(&g_adaptive.controller);
            uint32_t currentWindow = g_adaptive.controller.currentWindow.load();
            
            if (targetWindow != currentWindow && AC_CanChangeState(&g_adaptive.controller)) {
                // Determine new state based on window
                AC_State newState = AC_STATE_DEFAULT;
                if (targetWindow <= AC_WINDOW_EMERGENCY_FLOOR) {
                    newState = AC_STATE_EMERGENCY;
                } else if (targetWindow <= AC_WINDOW_SURVIVAL) {
                    newState = AC_STATE_SURVIVAL;
                } else if (targetWindow <= AC_WINDOW_EFFICIENT) {
                    newState = AC_STATE_EFFICIENT;
                } else if (targetWindow >= AC_WINDOW_PERFORMANCE) {
                    newState = AC_STATE_PERFORMANCE;
                }
                
                // Update state atomically
                g_adaptive.controller.currentState.store(newState);
                g_adaptive.controller.currentWindow.store(targetWindow);
                g_adaptive.controller.lastStateChange.store(
                    (uint64_t)GetTickCount64() * 1000); // Convert to micros approximation
                g_adaptive.controller.lastWindow.store(currentWindow);
                
                // Trigger VirtualUnlock if shrinking
                if (targetWindow < currentWindow) {
                    size_t newSize = (size_t)targetWindow * g_adaptive.controller.bytesPerToken;
                    size_t oldSize = (size_t)currentWindow * g_adaptive.controller.bytesPerToken;
                    VirtualUnlock((char*)NULL + newSize, oldSize - newSize); // Placeholder
                }
            }
        }
    }
    
    return 0;
}

/*===========================================================================
 * LIFECYCLE
 *=========================================================================*/

BOOL AC_Initialize(AC_Controller* ctrl, size_t totalSysMem, uint32_t bytesPerTok) {
    if (g_adaptive.initialized) {
        return TRUE;
    }
    
    ZeroMemory(&g_adaptive, sizeof(g_adaptive));
    ZeroMemory(ctrl, sizeof(AC_Controller));
    
    // Load PSAPI dynamically
    g_adaptive.hPsapi = LoadLibraryA("psapi.dll");
    if (g_adaptive.hPsapi) {
        g_adaptive.pfnGetProcessMemoryInfo = 
            (decltype(g_adaptive.pfnGetProcessMemoryInfo))GetProcAddress(
                g_adaptive.hPsapi, "GetProcessMemoryInfo");
    }
    
    // Detect system memory if not provided
    if (totalSysMem == 0) {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            totalSysMem = (size_t)memStatus.ullTotalPhys;
        } else {
            totalSysMem = 32ULL * 1024 * 1024 * 1024; // Default 32GB
        }
    }
    
    // Initialize controller
    ctrl->memoryPressure.store(0.0f);
    ctrl->acceptanceRate.store(0.5f);
    ctrl->currentFileSize.store(0);
    ctrl->pageFaultRate.store(0);
    ctrl->currentWindow.store(AC_WINDOW_DEFAULT);
    ctrl->currentState.store(AC_STATE_DEFAULT);
    ctrl->lastStateChange.store(0);
    ctrl->lastWindow.store(AC_WINDOW_DEFAULT);
    ctrl->bytesPerToken = bytesPerTok ? bytesPerTok : 128; // Default 128 bytes/token
    ctrl->totalSystemMemory = totalSysMem;
    ctrl->hysteresisEnabled = TRUE;
    ctrl->hysteresisCooldownMs = AC_HYSTERESIS_COOLDOWN_MS;
    ctrl->lastPageFaultCount = 0;
    ctrl->lastMetricsTime = 0;
    
    memcpy(&g_adaptive.controller, ctrl, sizeof(AC_Controller));
    
    // Create shutdown event
    g_adaptive.hShutdownEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_adaptive.hShutdownEvent) {
        return FALSE;
    }
    
    // Create waitable timer
    g_adaptive.hTimer = CreateWaitableTimerA(NULL, FALSE, NULL);
    if (!g_adaptive.hTimer) {
        CloseHandle(g_adaptive.hShutdownEvent);
        return FALSE;
    }
    
    // Set timer for 500ms intervals
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -5000000LL; // 500ms in 100ns units (negative = relative)
    SetWaitableTimer(g_adaptive.hTimer, &dueTime, AC_HYSTERESIS_COOLDOWN_MS / 10, NULL, NULL, FALSE);
    
    // Create monitor thread (low priority)
    g_adaptive.hMonitorThread = CreateThread(NULL, 64 * 1024, MonitorThreadProc, NULL, 
                                               CREATE_SUSPENDED, NULL);
    if (!g_adaptive.hMonitorThread) {
        CloseHandle(g_adaptive.hTimer);
        CloseHandle(g_adaptive.hShutdownEvent);
        return FALSE;
    }
    
    // Set below-normal priority
    SetThreadPriority(g_adaptive.hMonitorThread, THREAD_PRIORITY_BELOW_NORMAL);
    
    // Start the thread
    ResumeThread(g_adaptive.hMonitorThread);
    
    g_adaptive.initialized = TRUE;
    return TRUE;
}

void AC_Shutdown(AC_Controller* ctrl) {
    (void)ctrl;
    
    if (!g_adaptive.initialized) {
        return;
    }
    
    // Signal shutdown
    if (g_adaptive.hShutdownEvent) {
        SetEvent(g_adaptive.hShutdownEvent);
    }
    
    // Cancel timer
    if (g_adaptive.hTimer) {
        CancelWaitableTimer(g_adaptive.hTimer);
    }
    
    // Wait for thread to exit (max 2 seconds)
    if (g_adaptive.hMonitorThread) {
        WaitForSingleObject(g_adaptive.hMonitorThread, 2000);
        CloseHandle(g_adaptive.hMonitorThread);
    }
    
    // Cleanup handles
    if (g_adaptive.hTimer) CloseHandle(g_adaptive.hTimer);
    if (g_adaptive.hShutdownEvent) CloseHandle(g_adaptive.hShutdownEvent);
    
    // Free PSAPI
    if (g_adaptive.hPsapi) {
        FreeLibrary(g_adaptive.hPsapi);
    }
    
    g_adaptive.initialized = FALSE;
}

BOOL AC_IsActive(const AC_Controller* ctrl) {
    (void)ctrl;
    return g_adaptive.initialized;
}

/*===========================================================================
 * TELEMETRY INPUTS
 *=========================================================================*/

void AC_UpdateMemoryMetrics(AC_Controller* ctrl) {
    AC_MemoryMetrics metrics;
    if (!AC_CaptureMemoryMetrics(&metrics)) {
        return;
    }
    
    // Update page fault rate
    DWORD currentFaults = metrics.pageFaultCount;
    if (ctrl->lastPageFaultCount > 0) {
        DWORD delta = currentFaults - ctrl->lastPageFaultCount;
        // Calculate faults per second
        uint64_t now = GetTickCount64();
        uint64_t elapsedMs = now - ctrl->lastMetricsTime;
        if (elapsedMs > 0) {
            uint32_t faultsPerSec = (uint32_t)((delta * 1000ULL) / elapsedMs);
            ctrl->pageFaultRate.store(faultsPerSec);
        }
    }
    ctrl->lastPageFaultCount = currentFaults;
    ctrl->lastMetricsTime = GetTickCount64();
    
    // Calculate memory pressure
    float pressure = AC_CalculatePressure(&metrics, ctrl->totalSystemMemory);
    ctrl->memoryPressure.store(pressure);
}

void AC_SetAcceptanceRate(AC_Controller* ctrl, float rate) {
    if (rate < 0.0f) rate = 0.0f;
    if (rate > 1.0f) rate = 1.0f;
    ctrl->acceptanceRate.store(rate);
}

void AC_SetFileSize(AC_Controller* ctrl, uint32_t lines) {
    ctrl->currentFileSize.store(lines);
}

void AC_SetCurrentWindow(AC_Controller* ctrl, uint32_t tokens) {
    ctrl->currentWindow.store(tokens);
}

/*===========================================================================
 * DECISION OUTPUTS
 *=========================================================================*/

uint32_t AC_GetTargetWindow(const AC_Controller* ctrl) {
    float pressure = ctrl->memoryPressure.load();
    float acceptance = ctrl->acceptanceRate.load();
    uint32_t fileSize = ctrl->currentFileSize.load();
    uint32_t pageFaults = ctrl->pageFaultRate.load();
    
    // Emergency: Critical pressure + high page faults
    if (pressure > AC_PRESSURE_EMERGENCY && pageFaults > AC_PAGEFAULT_THRESHOLD) {
        return AC_WINDOW_EMERGENCY_FLOOR;
    }
    
    // Survival: High pressure
    if (pressure > AC_PRESSURE_SURVIVAL) {
        return AC_WINDOW_SURVIVAL;
    }
    
    // Performance: Low pressure + high acceptance
    if (pressure < AC_PRESSURE_LOW && acceptance > 0.7f) {
        return AC_WINDOW_PERFORMANCE;
    }
    
    // Efficient: Low pressure + small file
    if (pressure < AC_PRESSURE_RESTORE && fileSize < 1000) {
        return AC_WINDOW_EFFICIENT;
    }
    
    // Default
    return AC_WINDOW_DEFAULT;
}

AC_State AC_GetCurrentState(const AC_Controller* ctrl) {
    return ctrl->currentState.load();
}

float AC_GetMemoryPressure(const AC_Controller* ctrl) {
    return ctrl->memoryPressure.load();
}

uint32_t AC_GetPageFaultRate(const AC_Controller* ctrl) {
    return ctrl->pageFaultRate.load();
}

BOOL AC_CanChangeState(const AC_Controller* ctrl) {
    if (!ctrl->hysteresisEnabled) {
        return TRUE;
    }
    
    uint64_t lastChange = ctrl->lastStateChange.load();
    uint64_t now = GetTickCount64();
    
    return (now - lastChange) > ctrl->hysteresisCooldownMs;
}

/*===========================================================================
 * STATE MACHINE
 *=========================================================================*/

void AC_ForceState(AC_Controller* ctrl, AC_State newState) {
    ctrl->currentState.store(newState);
    ctrl->currentWindow.store(AC_GetWindowForState(newState));
    ctrl->lastStateChange.store(GetTickCount64());
}

const char* AC_GetStateName(AC_State state) {
    switch (state) {
        case AC_STATE_PERFORMANCE: return "PERFORMANCE";
        case AC_STATE_DEFAULT:     return "DEFAULT";
        case AC_STATE_EFFICIENT:   return "EFFICIENT";
        case AC_STATE_SURVIVAL:    return "SURVIVAL";
        case AC_STATE_EMERGENCY:   return "EMERGENCY";
        default:                   return "UNKNOWN";
    }
}

uint32_t AC_GetWindowForState(AC_State state) {
    switch (state) {
        case AC_STATE_PERFORMANCE: return AC_WINDOW_PERFORMANCE;
        case AC_STATE_DEFAULT:     return AC_WINDOW_DEFAULT;
        case AC_STATE_EFFICIENT:   return AC_WINDOW_EFFICIENT;
        case AC_STATE_SURVIVAL:    return AC_WINDOW_SURVIVAL;
        case AC_STATE_EMERGENCY:   return AC_WINDOW_EMERGENCY_FLOOR;
        default:                   return AC_WINDOW_DEFAULT;
    }
}

/*===========================================================================
 * MEMORY METRICS HELPERS
 *=========================================================================*/

BOOL AC_CaptureMemoryMetrics(AC_MemoryMetrics* outMetrics) {
    if (!outMetrics) return FALSE;
    
    ZeroMemory(outMetrics, sizeof(AC_MemoryMetrics));
    
    // Use dynamically loaded function if available
    if (g_adaptive.pfnGetProcessMemoryInfo) {
        PROCESS_MEMORY_COUNTERS pmc;
        if (g_adaptive.pfnGetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            outMetrics->pageFaultCount = pmc.PageFaultCount;
            outMetrics->workingSetBytes = pmc.WorkingSetSize;
            outMetrics->peakWorkingSetBytes = pmc.PeakWorkingSetSize;
            outMetrics->pagefileUsage = pmc.PagefileUsage;
            outMetrics->timestampMicros = GetTickCount64() * 1000;
            return TRUE;
        }
    }
    
    return FALSE;
}

float AC_CalculatePressure(const AC_MemoryMetrics* metrics, size_t totalSystemMemory) {
    if (!metrics || totalSystemMemory == 0) return 0.0f;
    
    // Calculate pressure as working set / total physical memory
    float pressure = (float)metrics->workingSetBytes / (float)totalSystemMemory;
    
    // Clamp to 0-1 range
    if (pressure < 0.0f) pressure = 0.0f;
    if (pressure > 1.0f) pressure = 1.0f;
    
    return pressure;
}
