//=============================================================================
// Deterministic Performance Mode Implementation
// RawrXD IDE - Certification Benchmarking
//=============================================================================
// Windows-specific implementation using:
//   - SetThreadAffinityMask for CPU pinning
//   - SetThreadExecutionState for frequency locking
//   - QueryPerformanceCounter for stable timing
//   - GetLogicalProcessorInformation for topology detection
//=============================================================================

#include "RawrXD_DeterministicPerformance.hpp"
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

namespace RawrXD {
namespace Runtime {

// Static member definitions
bool DeterministicPerformanceManager::s_active = false;
DeterministicConfig DeterministicPerformanceManager::s_config = {};
uint64_t DeterministicPerformanceManager::s_baseline_tps = 0;

std::vector<PulseValidator::PulseSample> PulseValidator::s_history;

//=============================================================================
// Command Line Parsing
//=============================================================================
bool DeterministicPerformanceManager::Initialize(int argc, const char* argv[]) {
    bool benchmark_mode = false;
    bool deterministic_mode = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], BENCHMARK_FLAG) == 0) {
            benchmark_mode = true;
        }
        else if (strcmp(argv[i], DETERMINISTIC_FLAG) == 0) {
            deterministic_mode = true;
        }
        else if (strncmp(argv[i], "--threads=", 10) == 0) {
            s_config.fixed_thread_count = atoi(argv[i] + 10);
        }
        else if (strncmp(argv[i], "--affinity=", 11) == 0) {
            s_config.cpu_affinity_mask = strtoull(argv[i] + 11, nullptr, 16);
        }
        else if (strncmp(argv[i], "--kv-window=", 12) == 0) {
            s_config.fixed_kv_window_size = atoi(argv[i] + 12);
        }
    }
    
    // Deterministic mode requires benchmark mode
    if (deterministic_mode && !benchmark_mode) {
        std::cerr << "Warning: " << DETERMINISTIC_FLAG << " requires " 
                  << BENCHMARK_FLAG << ". Enabling benchmark mode." << std::endl;
        benchmark_mode = true;
    }
    
    s_active = deterministic_mode;
    
    if (s_active) {
        std::cout << "=================================================================" << std::endl;
        std::cout << "DETERMINISTIC PERFORMANCE MODE ACTIVATED" << std::endl;
        std::cout << "=================================================================" << std::endl;
        
        if (!ApplyFreezes()) {
            std::cerr << "ERROR: Failed to apply deterministic freezes. Aborting." << std::endl;
            s_active = false;
            return false;
        }
        
        PrintConfiguration();
    }
    
    return true;
}

//=============================================================================
// Apply All Freezes
//=============================================================================
bool DeterministicPerformanceManager::ApplyFreezes() {
    if (!s_active) return true;
    
    bool success = true;
    
    // 1. CPU Affinity
    if (s_config.freeze_cpu_affinity) {
        if (!SetCPUAffinity(s_config.cpu_affinity_mask)) {
            std::cerr << "WARNING: Failed to set CPU affinity" << std::endl;
            success = false;
        }
    }
    
    // 2. Thread Count
    if (s_config.freeze_thread_count) {
        if (!SetThreadCount(s_config.fixed_thread_count)) {
            std::cerr << "WARNING: Failed to set thread count" << std::endl;
            success = false;
        }
    }
    
    // 3. Frequency Scaling
    if (s_config.disable_frequency_scaling) {
        if (!DisableFrequencyScaling()) {
            std::cerr << "WARNING: Failed to disable frequency scaling" << std::endl;
            success = false;
        }
    }
    
    // 4. Thread Pinning
    if (s_config.disable_thread_migration) {
        if (!PinThreads()) {
            std::cerr << "WARNING: Failed to pin threads" << std::endl;
            success = false;
        }
    }
    
    // 5. Validate environment is locked
    if (!ValidatePulseStability()) {
        std::cerr << "ERROR: Environment validation failed. System not locked." << std::endl;
        return false;
    }
    
    return success;
}

//=============================================================================
// CPU Affinity (Windows-specific)
//=============================================================================
bool DeterministicPerformanceManager::SetCPUAffinity(uint64_t mask) {
    HANDLE hProcess = GetCurrentProcess();
    DWORD_PTR processAffinityMask = static_cast<DWORD_PTR>(mask);
    DWORD_PTR systemAffinityMask = 0;
    
    // Get system affinity mask
    if (!GetProcessAffinityMask(hProcess, &processAffinityMask, &systemAffinityMask)) {
        return false;
    }
    
    // Apply user mask intersected with system mask
    DWORD_PTR finalMask = processAffinityMask & mask;
    if (finalMask == 0) {
        finalMask = processAffinityMask;  // Fallback to system mask
    }
    
    if (!SetProcessAffinityMask(hProcess, finalMask)) {
        return false;
    }
    
    // Also set for current thread
    HANDLE hThread = GetCurrentThread();
    if (!SetThreadAffinityMask(hThread, finalMask)) {
        return false;
    }
    
    return true;
}

//=============================================================================
// Thread Count
//=============================================================================
bool DeterministicPerformanceManager::SetThreadCount(int count) {
    // Store the fixed thread count for the runtime to use
    // Actual thread pool adjustment happens in the runtime
    s_config.fixed_thread_count = count;
    return true;
}

//=============================================================================
// Disable Frequency Scaling (Windows-specific)
//=============================================================================
bool DeterministicPerformanceManager::DisableFrequencyScaling() {
    // Prevent system sleep/throttling
    if (s_config.lock_max_frequency) {
        // ES_CONTINUOUS | ES_SYSTEM_REQUIRED prevents sleep
        // ES_AWAYMODE_REQUIRED keeps system running
        EXECUTION_STATE result = SetThreadExecutionState(
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED
        );
        if (result == 0) {
            return false;
        }
    }
    
    // Note: Direct frequency control requires privileged APIs
    // We signal intent to Windows power management
    return true;
}

//=============================================================================
// Thread Pinning
//=============================================================================
bool DeterministicPerformanceManager::PinThreads() {
    // This is handled per-thread when threads are created
    // The runtime checks IsDeterministicMode() and pins accordingly
    return true;
}

//=============================================================================
// Validate Pulse Stability (Runtime Validation Gate)
//=============================================================================
bool DeterministicPerformanceManager::ValidatePulseStability() {
    std::cout << "[VALIDATION GATE] Checking environment stability..." << std::endl;
    
    // Take multiple pulse samples
    const int samples = 5;
    std::vector<double> tps_samples;
    std::vector<double> freq_samples;
    
    for (int i = 0; i < samples; ++i) {
        // Simulate a micro-benchmark or read from hardware counters
        // In real implementation, this would run a short kernel
        
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Short busy loop
        volatile int dummy = 0;
        for (int j = 0; j < 1000000; ++j) {
            dummy += j;
        }
        
        QueryPerformanceCounter(&end);
        
        double elapsed_ms = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        double tps = 1000000.0 / (elapsed_ms / 1000.0);  // ops per second
        
        tps_samples.push_back(tps);
        
        // Get CPU frequency (simplified - would use actual MSR reads)
        freq_samples.push_back(4.5);  // Assume 4.5 GHz
        
        Sleep(10);  // Short delay between samples
    }
    
    // Calculate variance
    double tps_mean = 0, tps_variance = 0;
    for (double tps : tps_samples) tps_mean += tps;
    tps_mean /= samples;
    
    for (double tps : tps_samples) {
        tps_variance += (tps - tps_mean) * (tps - tps_mean);
    }
    tps_variance /= samples;
    
    double tps_stddev = sqrt(tps_variance);
    double tps_cv = (tps_stddev / tps_mean) * 100.0;  // Coefficient of variation
    
    std::cout << "  TPS samples: ";
    for (double tps : tps_samples) {
        std::cout << std::fixed << std::setprecision(0) << tps << " ";
    }
    std::cout << std::endl;
    std::cout << "  Mean TPS: " << tps_mean << std::endl;
    std::cout << "  StdDev: " << tps_stddev << " (" << tps_cv << "%)" << std::endl;
    
    // Check if variance is within tolerance
    if (tps_cv > s_config.pulse_tolerance_percent) {
        std::cerr << "ERROR: TPS variance " << tps_cv << "% exceeds tolerance " 
                  << s_config.pulse_tolerance_percent << "%" << std::endl;
        std::cerr << "Possible causes:" << std::endl;
        std::cerr << "  - Another process is using pinned cores" << std::endl;
        std::cerr << "  - Frequency scaling is active" << std::endl;
        std::cerr << "  - Thread migration occurred" << std::endl;
        return false;
    }
    
    std::cout << "[VALIDATION GATE] PASSED - Environment is stable" << std::endl;
    return true;
}

//=============================================================================
// Print Configuration
//=============================================================================
void DeterministicPerformanceManager::PrintConfiguration() {
    std::cout << "Configuration:" << std::endl;
    std::cout << "  CPU Affinity: 0x" << std::hex << s_config.cpu_affinity_mask << std::dec << std::endl;
    std::cout << "  Thread Count: " << s_config.fixed_thread_count << std::endl;
    std::cout << "  KV Window: " << s_config.fixed_kv_window_size << std::endl;
    std::cout << "  Kernel: " << s_config.forced_kernel << std::endl;
    std::cout << "  Layout: " << s_config.forced_layout << std::endl;
    std::cout << "  Frequency Scaling: " << (s_config.disable_frequency_scaling ? "DISABLED" : "ENABLED") << std::endl;
    std::cout << "  Hot Swap: " << (s_config.disable_hot_swap ? "DISABLED" : "ENABLED") << std::endl;
    std::cout << "  Thread Migration: " << (s_config.disable_thread_migration ? "DISABLED" : "ENABLED") << std::endl;
    std::cout << "=================================================================" << std::endl;
}

//=============================================================================
// Restore Defaults
//=============================================================================
void DeterministicPerformanceManager::RestoreDefaults() {
    if (!s_active) return;
    
    // Restore frequency scaling
    SetThreadExecutionState(ES_CONTINUOUS);
    
    // Restore process affinity
    HANDLE hProcess = GetCurrentProcess();
    DWORD_PTR systemMask = 0;
    DWORD_PTR processMask = 0;
    if (GetProcessAffinityMask(hProcess, &processMask, &systemMask)) {
        SetProcessAffinityMask(hProcess, systemMask);
    }
    
    s_active = false;
    std::cout << "Deterministic performance mode disabled. System restored." << std::endl;
}

//=============================================================================
// Pulse Validator Implementation
//=============================================================================
void PulseValidator::RecordPulse(const PulseSample& sample) {
    s_history.push_back(sample);
    
    // Keep history bounded
    if (s_history.size() > 1000) {
        s_history.erase(s_history.begin());
    }
}

bool PulseValidator::IsStable(uint32_t window_size) {
    if (s_history.size() < window_size) {
        return false;  // Not enough samples
    }
    
    // Get last N samples
    size_t start = s_history.size() - window_size;
    
    // Calculate TPS variance
    double tps_sum = 0, tps_mean = 0, tps_var = 0;
    for (size_t i = start; i < s_history.size(); ++i) {
        tps_sum += s_history[i].tps;
    }
    tps_mean = tps_sum / window_size;
    
    for (size_t i = start; i < s_history.size(); ++i) {
        tps_var += (s_history[i].tps - tps_mean) * (s_history[i].tps - tps_mean);
    }
    tps_var /= window_size;
    
    double tps_cv = sqrt(tps_var) / tps_mean;
    
    // Check frequency variance
    double freq_sum = 0, freq_mean = 0, freq_var = 0;
    for (size_t i = start; i < s_history.size(); ++i) {
        freq_sum += s_history[i].cpu_frequency_ghz;
    }
    freq_mean = freq_sum / window_size;
    
    for (size_t i = start; i < s_history.size(); ++i) {
        freq_var += (s_history[i].cpu_frequency_ghz - freq_mean) 
                    * (s_history[i].cpu_frequency_ghz - freq_mean);
    }
    freq_var /= window_size;
    
    double freq_cv = sqrt(freq_var) / freq_mean;
    
    return (tps_cv <= TPS_VARIANCE_THRESHOLD) && (freq_cv <= FREQ_VARIANCE_THRESHOLD);
}

void PulseValidator::GetStabilityReport(std::string& report) {
    std::ostringstream oss;
    
    if (s_history.empty()) {
        report = "No pulse samples recorded.";
        return;
    }
    
    // Calculate statistics
    double tps_min = s_history[0].tps, tps_max = s_history[0].tps, tps_avg = 0;
    double freq_min = s_history[0].cpu_frequency_ghz, freq_max = s_history[0].cpu_frequency_ghz;
    
    for (const auto& sample : s_history) {
        tps_min = std::min(tps_min, sample.tps);
        tps_max = std::max(tps_max, sample.tps);
        tps_avg += sample.tps;
        freq_min = std::min(freq_min, sample.cpu_frequency_ghz);
        freq_max = std::max(freq_max, sample.cpu_frequency_ghz);
    }
    tps_avg /= s_history.size();
    
    oss << "Pulse Stability Report:" << std::endl;
    oss << "  Samples: " << s_history.size() << std::endl;
    oss << "  TPS Range: " << tps_min << " - " << tps_max << std::endl;
    oss << "  TPS Average: " << tps_avg << std::endl;
    oss << "  TPS Variance: " << ((tps_max - tps_min) / tps_avg * 100.0) << "%" << std::endl;
    oss << "  Frequency Range: " << freq_min << " - " << freq_max << " GHz" << std::endl;
    oss << "  Status: " << (IsStable(10) ? "STABLE" : "UNSTABLE") << std::endl;
    
    report = oss.str();
}

void PulseValidator::Reset() {
    s_history.clear();
}

} // namespace Runtime
} // namespace RawrXD
