#include <iostream>
#include <chrono>
#include <thread>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#pragma intrinsic(__rdtsc)
#else
#include <x86intrin.h>
#endif

// Read RDTSC (CPU cycle counter)
inline uint64_t ReadRDTSC() {
    return __rdtsc();
}

static double cycles_per_ms = 0.0;

void CalibrateTiming() {
    // Use QueryPerformanceCounter on Windows for stable timing
    #ifdef _WIN32
    LARGE_INTEGER freq, start_qpc, end_qpc;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start_qpc);
    #else
    auto start_wall = std::chrono::high_resolution_clock::now();
    #endif
    
    const uint64_t start_cycles = ReadRDTSC();
    
    // Busy wait for ~100ms using QPC (more accurate than sleep)
    #ifdef _WIN32
    LARGE_INTEGER current;
    do {
        QueryPerformanceCounter(&current);
    } while ((current.QuadPart - start_qpc.QuadPart) < (freq.QuadPart / 10)); // 100ms
    #else
    auto end_wall = start_wall;
    while (std::chrono::duration<double>(end_wall - start_wall).count() < 0.1) {
        end_wall = std::chrono::high_resolution_clock::now();
    }
    #endif
    
    const uint64_t end_cycles = ReadRDTSC();
    
    #ifdef _WIN32
    QueryPerformanceCounter(&end_qpc);
    double elapsed_ms = (end_qpc.QuadPart - start_qpc.QuadPart) * 1000.0 / freq.QuadPart;
    #else
    auto elapsed_ms = std::chrono::duration<double>(end_wall - start_wall).count() * 1000.0;
    #endif
    
    cycles_per_ms = (end_cycles - start_cycles) / elapsed_ms;
    
    std::cout << "[Calibration] Cycles per ms: " << cycles_per_ms << std::endl;
    std::cout << "[Calibration] CPU Frequency: " << (cycles_per_ms / 1000.0) << " GHz" << std::endl;
}

double CyclesToMilliseconds(uint64_t cycles) {
    return static_cast<double>(cycles) / cycles_per_ms;
}

int main() {
    std::cout << "=== RawrXD Phase 19: Timing Calibration ===" << std::endl;
    
    // Run calibration
    CalibrateTiming();
    
    // Verify with a quick timing test
    std::cout << "\n[Verification] Running quick timing test..." << std::endl;
    
    uint64_t start = ReadRDTSC();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    uint64_t end = ReadRDTSC();
    
    uint64_t cycles = end - start;
    double ms = CyclesToMilliseconds(cycles);
    
    std::cout << "[Verification] 10ms sleep measured: " << ms << " ms (" << cycles << " cycles)" << std::endl;
    
    // Calculate 10ms budget in cycles
    uint64_t budget_10ms = static_cast<uint64_t>(cycles_per_ms * 10.0);
    std::cout << "\n[Budget] 10ms latency budget = " << budget_10ms << " cycles" << std::endl;
    
    return 0;
}
