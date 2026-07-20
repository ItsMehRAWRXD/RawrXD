//=============================================================================
// Deterministic Performance Mode
// RawrXD IDE - Certification Benchmarking
//=============================================================================
// Freezes all performance-sensitive parameters to eliminate benchmark noise
// Usage: rawrxd.exe --benchmark --deterministic-performance
//=============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace RawrXD {
namespace Runtime {

//=============================================================================
// Deterministic Performance Configuration
//=============================================================================
struct DeterministicConfig {
    // CPU Affinity
    bool freeze_cpu_affinity = true;
    uint64_t cpu_affinity_mask = 0xFFFFFFFF;  // Use first 32 cores
    
    // Threading
    bool freeze_thread_count = true;
    int32_t fixed_thread_count = 8;  // Match physical cores
    
    // Kernel Selection
    bool freeze_kernel_selection = true;
    const char* forced_kernel = "AVX512_FusedQ4";  // Disable adaptive switching
    
    // KV Cache
    bool freeze_kv_allocator = true;
    uint32_t fixed_kv_window_size = 2048;
    bool disable_cache_eviction = true;
    
    // Memory Layout
    bool freeze_memory_layout = true;
    const char* forced_layout = "NHWC";  // Force NHWC, disable runtime detection
    
    // Frequency Scaling
    bool disable_frequency_scaling = true;
    bool lock_max_frequency = true;
    
    // Hot Swap
    bool disable_hot_swap = true;
    bool disable_adaptive_kernels = true;
    
    // Thread Migration
    bool disable_thread_migration = true;
    bool pin_threads_to_cores = true;
    
    // Validation
    bool enable_pulse_validation = true;  // Check for state transitions
    uint32_t pulse_tolerance_percent = 5;   // TPS variance threshold
};

//=============================================================================
// Deterministic Performance Manager
//=============================================================================
class DeterministicPerformanceManager {
public:
    // Initialize from command line
    static bool Initialize(int argc, const char* argv[]);
    
    // Check if deterministic mode is active
    static bool IsDeterministicMode() { return s_active; }
    
    // Apply all freezes
    static bool ApplyFreezes();
    
    // Validate no state transitions occurred
    static bool ValidatePulseStability();
    
    // Get current configuration
    static const DeterministicConfig& GetConfig() { return s_config; }
    
    // Report configuration status
    static void PrintConfiguration();
    
    // Restore system defaults (cleanup)
    static void RestoreDefaults();

private:
    static bool s_active;
    static DeterministicConfig s_config;
    static uint64_t s_baseline_tps;
    
    // Platform-specific implementations
    static bool SetCPUAffinity(uint64_t mask);
    static bool SetThreadCount(int count);
    static bool DisableFrequencyScaling();
    static bool PinThreads();
};

//=============================================================================
// Pulse Stability Validator
//=============================================================================
class PulseValidator {
public:
    struct PulseSample {
        uint64_t timestamp;
        double tps;
        uint32_t sequence_length;
        uint64_t cache_misses;
        double cpu_frequency_ghz;
    };
    
    // Record a pulse sample
    static void RecordPulse(const PulseSample& sample);
    
    // Check if pulses are stable (no state transitions)
    static bool IsStable(uint32_t window_size = 10);
    
    // Get stability report
    static void GetStabilityReport(std::string& report);
    
    // Clear history
    static void Reset();

private:
    static std::vector<PulseSample> s_history;
    static constexpr double TPS_VARIANCE_THRESHOLD = 0.05;  // 5%
    static constexpr double FREQ_VARIANCE_THRESHOLD = 0.01; // 1%
};

//=============================================================================
// Command Line Integration
//=============================================================================
#define DETERMINISTIC_FLAG "--deterministic-performance"
#define BENCHMARK_FLAG "--benchmark"

// Macros for deterministic mode checks
#ifdef RAWRXD_DETERMINISTIC_MODE
    #define IF_DETERMINISTIC(code) code
    #define IF_ADAPTIVE(code)
#else
    #define IF_DETERMINISTIC(code)
    #define IF_ADAPTIVE(code) code
#endif

} // namespace Runtime
} // namespace RawrXD
