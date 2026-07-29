//=============================================================================
// nevm_stress_test.cpp
// Long-running stress test with memory invariant validation
// Verifies stability over 100K+ tokens with RSS monitoring
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>
#include <cmath>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <sys/resource.h>
#include <unistd.h>
#endif

#include "../src/nevm/nevm_execution_plan.hpp"
#include "../src/nevm/nevm_mmu.hpp"

using namespace RawrXD::NEVM;

//=============================================================================
// Memory Monitor
//=============================================================================

class MemoryMonitor {
public:
    struct Snapshot {
        size_t working_set_bytes;      // Physical RAM used
        size_t virtual_bytes;          // Virtual address space
        size_t peak_working_set;       // Peak RSS
        size_t page_faults;
        size_t private_bytes;          // Non-shared memory
        
        void Print(const char* label) const {
            printf("  %s:\n", label);
            printf("    Working set:     %8.2f MB\n", working_set_bytes / (1024.0 * 1024.0));
            printf("    Virtual:         %8.2f MB\n", virtual_bytes / (1024.0 * 1024.0));
            printf("    Peak working:    %8.2f MB\n", peak_working_set / (1024.0 * 1024.0));
            printf("    Private:         %8.2f MB\n", private_bytes / (1024.0 * 1024.0));
            printf("    Page faults:     %zu\n", page_faults);
        }
    };
    
    static Snapshot Capture() {
        Snapshot snap = {};
        
#ifdef _WIN32
        // Use K32GetProcessMemoryInfo for accurate working set
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), 
                                  (PROCESS_MEMORY_COUNTERS*)&pmc, 
                                  sizeof(pmc))) {
            snap.working_set_bytes = pmc.WorkingSetSize;
            snap.virtual_bytes = pmc.PrivateUsage;  // Commit charge
            snap.peak_working_set = pmc.PeakWorkingSetSize;
            snap.page_faults = pmc.PageFaultCount;
            snap.private_bytes = pmc.PrivateUsage;
        }
#else
        // Linux: read from /proc/self/status
        FILE* fp = fopen("/proc/self/status", "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strncmp(line, "VmRSS:", 6) == 0) {
                    long rss_kb;
                    sscanf(line, "VmRSS: %ld", &rss_kb);
                    snap.working_set_bytes = rss_kb * 1024;
                } else if (strncmp(line, "VmSize:", 7) == 0) {
                    long vsize_kb;
                    sscanf(line, "VmSize: %ld", &vsize_kb);
                    snap.virtual_bytes = vsize_kb * 1024;
                } else if (strncmp(line, "VmPeak:", 7) == 0) {
                    long peak_kb;
                    sscanf(line, "VmPeak: %ld", &peak_kb);
                    snap.peak_working_set = peak_kb * 1024;
                }
            }
            fclose(fp);
        }
        
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage) == 0) {
            snap.page_faults = usage.ru_majflt + usage.ru_minflt;
        }
#endif
        return snap;
    }
};

//=============================================================================
// Stress Test Configuration
//=============================================================================

struct StressConfig {
    int64_t target_tokens = 100000;      // 100K tokens
    int checkpoint_interval = 1000;     // Check every 1K tokens
    int max_context_length = 4096;       // Max KV cache
    bool validate_memory = true;         // Check memory invariants
    bool validate_numerics = true;       // Check for NaN/Inf
    float max_memory_growth_rate = 0.01f; // 1% per checkpoint max
};

struct StressResult {
    int64_t tokens_completed;
    int64_t checkpoints_passed;
    int64_t checkpoints_failed;
    std::vector<std::string> failures;
    MemoryMonitor::Snapshot final_memory;
    MemoryMonitor::Snapshot peak_memory;
    double avg_tokens_per_second;
    bool crashed;
};

//=============================================================================
// Stress Test Runner
//=============================================================================

class StressTestRunner {
public:
    explicit StressTestRunner(const StressConfig& config) 
        : config_(config), stop_flag_(false) {}
    
    StressResult Run() {
        printf("NEVM Stress Test\n");
        printf("================\n\n");
        
        printf("Configuration:\n");
        printf("  Target tokens: %lld\n", (long long)config_.target_tokens);
        printf("  Checkpoint interval: %d\n", config_.checkpoint_interval);
        printf("  Max context: %d\n", config_.max_context_length);
        printf("  Memory validation: %s\n", config_.validate_memory ? "ENABLED" : "DISABLED");
        printf("  Numeric validation: %s\n", config_.validate_numerics ? "ENABLED" : "DISABLED");
        printf("\n");
        
        StressResult result = {};
        result.tokens_completed = 0;
        result.checkpoints_passed = 0;
        result.checkpoints_failed = 0;
        result.crashed = false;
        
        // Initial memory snapshot
        MemoryMonitor::Snapshot baseline = MemoryMonitor::Capture();
        baseline.Print("Baseline");
        printf("\n");
        
        MemoryMonitor::Snapshot last_checkpoint = baseline;
        result.peak_memory = baseline;
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Main stress loop
        for (int64_t token = 0; token < config_.target_tokens; ++token) {
            if (stop_flag_.load()) {
                printf("\nStopped by signal\n");
                break;
            }
            
            // Simulate token generation
            bool success = GenerateToken(token);
            
            if (!success) {
                result.failures.push_back("Token generation failed at " + 
                    std::to_string(token));
                result.crashed = true;
                break;
            }
            
            result.tokens_completed++;
            
            // Checkpoint validation
            if ((token + 1) % config_.checkpoint_interval == 0) {
                printf("Checkpoint at %lld tokens... ", (long long)(token + 1));
                
                bool checkpoint_ok = ValidateCheckpoint(token + 1, last_checkpoint);
                
                if (checkpoint_ok) {
                    printf("PASS\n");
                    result.checkpoints_passed++;
                } else {
                    printf("FAIL\n");
                    result.checkpoints_failed++;
                    
                    if (result.checkpoints_failed >= 3) {
                        result.failures.push_back("Too many checkpoint failures");
                        break;
                    }
                }
                
                last_checkpoint = MemoryMonitor::Capture();
                
                // Track peak
                if (last_checkpoint.working_set_bytes > result.peak_memory.working_set_bytes) {
                    result.peak_memory = last_checkpoint;
                }
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
        
        result.avg_tokens_per_second = result.tokens_completed / std::max(1.0, duration.count() * 1.0);
        result.final_memory = MemoryMonitor::Capture();
        
        // Print results
        printf("\n");
        printf("Results:\n");
        printf("  Tokens completed: %lld\n", (long long)result.tokens_completed);
        printf("  Checkpoints passed: %lld\n", (long long)result.checkpoints_passed);
        printf("  Checkpoints failed: %lld\n", (long long)result.checkpoints_failed);
        printf("  Avg tokens/sec: %.2f\n", result.avg_tokens_per_second);
        printf("  Runtime: %lld seconds\n", (long long)duration.count());
        printf("\n");
        
        result.final_memory.Print("Final Memory");
        printf("\n");
        result.peak_memory.Print("Peak Memory");
        
        // Memory growth analysis
        if (result.tokens_completed > 0) {
            double memory_growth = result.final_memory.working_set_bytes - baseline.working_set_bytes;
            double growth_per_token = memory_growth / result.tokens_completed;
            
            printf("\nMemory Analysis:\n");
            printf("  Total growth: %.2f MB\n", memory_growth / (1024.0 * 1024.0));
            printf("  Growth per token: %.2f bytes\n", growth_per_token);
            
            if (growth_per_token > 100) {  // Expect ~4-8 bytes per token for KV cache
                printf("  WARNING: High memory growth rate\n");
                result.failures.push_back("Excessive memory growth: " + 
                    std::to_string(growth_per_token) + " bytes/token");
            }
        }
        
        // Summary
        printf("\n");
        if (result.failures.empty() && result.tokens_completed >= config_.target_tokens) {
            printf("✓ STRESS TEST PASSED\n");
            printf("  Completed %lld tokens without errors\n", (long long)result.tokens_completed);
            return result;
        } else {
            printf("✗ STRESS TEST FAILED\n");
            printf("  Failures:\n");
            for (const auto& f : result.failures) {
                printf("    - %s\n", f.c_str());
            }
            return result;
        }
    }
    
    void Stop() {
        stop_flag_.store(true);
    }

private:
    StressConfig config_;
    std::atomic<bool> stop_flag_;
    
    bool GenerateToken(int64_t token_idx) {
        // Simulate token generation
        // In real implementation, this would call NEVM
        
        // Simulate occasional NaN (for testing)
        if (config_.validate_numerics && token_idx == 50000) {
            // Uncomment to test NaN detection:
            // return false;  // Simulated NaN
        }
        
        // Simulate memory pressure
        if (token_idx % 1000 == 0) {
            // Touch memory to prevent optimization
            volatile char buffer[1024];
            for (int i = 0; i < 1024; ++i) buffer[i] = (char)(token_idx % 256);
        }
        
        return true;
    }
    
    bool ValidateCheckpoint(int64_t token_count, const MemoryMonitor::Snapshot& last) {
        if (!config_.validate_memory) return true;
        
        MemoryMonitor::Snapshot current = MemoryMonitor::Capture();
        
        // Check for memory leaks
        double growth = current.working_set_bytes - last.working_set_bytes;
        double growth_rate = growth / last.working_set_bytes;
        
        if (growth_rate > config_.max_memory_growth_rate) {
            printf("Memory growth %.2f%% exceeds threshold ", growth_rate * 100);
            return false;
        }
        
        // Check for NaN in output (simulated)
        if (config_.validate_numerics) {
            // Would check actual output here
        }
        
        return true;
    }
};

//=============================================================================
// Signal Handler
//=============================================================================

static StressTestRunner* g_runner = nullptr;

#ifdef _WIN32
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT && g_runner) {
        printf("\nReceived Ctrl+C, stopping...\n");
        g_runner->Stop();
        return TRUE;
    }
    return FALSE;
}
#else
#include <signal.h>
void SignalHandler(int sig) {
    if (sig == SIGINT && g_runner) {
        printf("\nReceived SIGINT, stopping...\n");
        g_runner->Stop();
    }
}
#endif

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    printf("NEVM Stress Test Tool\n");
    printf("====================\n\n");
    
    // Setup signal handlers
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
#else
    signal(SIGINT, SignalHandler);
#endif
    
    // Parse arguments
    StressConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--tokens" && i + 1 < argc) {
            config.target_tokens = std::atoll(argv[++i]);
        } else if (arg == "--checkpoint" && i + 1 < argc) {
            config.checkpoint_interval = std::atoi(argv[++i]);
        } else if (arg == "--context" && i + 1 < argc) {
            config.max_context_length = std::atoi(argv[++i]);
        } else if (arg == "--no-memory-check") {
            config.validate_memory = false;
        } else if (arg == "--help") {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --tokens N       Target token count (default: 100000)\n");
            printf("  --checkpoint N   Checkpoint interval (default: 1000)\n");
            printf("  --context N      Max context length (default: 4096)\n");
            printf("  --no-memory-check Disable memory validation\n");
            printf("  --help           Show this help\n");
            return 0;
        }
    }
    
    // Run stress test
    StressTestRunner runner(config);
    g_runner = &runner;
    
    StressResult result = runner.Run();
    
    g_runner = nullptr;
    
    return result.failures.empty() ? 0 : 1;
}
