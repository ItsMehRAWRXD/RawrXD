#include "sovereign/SovereignTelemetry.hpp"
#include "sovereign/Beaconism.hpp"
#include <windows.h>
#include <iostream>
#include <atomic>

using namespace Sovereign;

static std::atomic<bool> g_running{true};
static constexpr uint32_t STALL_THRESHOLD_TOKENS = 10;
static constexpr uint32_t THERMAL_THRESHOLD_C = 85;
static constexpr uint32_t LATENCY_THRESHOLD_MS = 100;

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        g_running = false;
        return TRUE;
    }
    return FALSE;
}

int main() {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    std::cout << "Sovereign Watchdog starting...\n";
    
    // Open shared memory
    HANDLE hMMF = OpenFileMappingW(FILE_MAP_READ, FALSE, L"RawrXD_Telemetry_v1");
    if (!hMMF) {
        std::cerr << "Failed to open telemetry shared memory. Is RawrXD running?\n";
        return 1;
    }
    
    auto* shared = (SovereignTelemetry*)MapViewOfFile(
        hMMF, FILE_MAP_READ, 0, 0, sizeof(SovereignTelemetry));
    
    if (!shared) {
        std::cerr << "Failed to map telemetry view\n";
        CloseHandle(hMMF);
        return 1;
    }
    
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    
    uint64_t lastTok = 0;
    uint64_t lastTicks = 0;
    uint32_t stallCount = 0;
    
    std::cout << "Watchdog monitoring active. Press Ctrl+C to stop.\n";
    
    while (g_running) {
        Sleep(1000);
        
        // Read telemetry
        SovereignTelemetry tel = *shared;
        
        // Stall detection
        if (lastTok != 0 && tel.tokensPerSec == lastTok) {
            stallCount++;
            if (stallCount >= 3) {
                std::cerr << "WATCHDOG ALERT: Runtime stalled (no token progress for " 
                          << stallCount << " seconds)\n";
                BeaconismEmitter::Instance().Emit(BeaconID::SmoketestFailed, 0xDEAD);
                
                // Could trigger restart here
                // shared->flags |= 0x4; // Set "needs restart" flag
            }
        } else {
            stallCount = 0;
        }
        lastTok = tel.tokensPerSec;
        
        // Thermal guard
        if (tel.thermalC > THERMAL_THRESHOLD_C) {
            std::cerr << "WATCHDOG ALERT: Thermal limit exceeded (" 
                      << tel.thermalC << "C > " << THERMAL_THRESHOLD_C << "C)\n";
            BeaconismEmitter::Instance().Emit(BeaconID::SmoketestFailed, 0xHOT);
        }
        
        // Latency check
        if (tel.latencyMs > LATENCY_THRESHOLD_MS) {
            std::cerr << "WATCHDOG WARNING: High latency detected (" 
                      << tel.latencyMs << "ms > " << LATENCY_THRESHOLD_MS << "ms)\n";
        }
        
        // Progress indicator
        if (stallCount == 0) {
            std::cout << "[OK] Tok/s: " << tel.tokensPerSec 
                      << " | Latency: " << tel.latencyMs << "ms"
                      << " | Thermal: " << tel.thermalC << "C\r";
        }
    }
    
    std::cout << "\nWatchdog shutting down...\n";
    
    UnmapViewOfFile(shared);
    CloseHandle(hMMF);
    
    return 0;
}
