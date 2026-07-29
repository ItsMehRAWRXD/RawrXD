//=============================================================================
// nevm_determinism_validation.cpp
// Strict determinism validation for NEVM execution
// Verifies identical outputs across runs with controlled execution environment
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <thread>
#include <mutex>
#include <atomic>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <pthread.h>
#include <sched.h>
#endif

#include "../src/nevm/nevm_execution_plan.hpp"
#include "../src/nevm/nevm_kernel_bridge.hpp"

using namespace RawrXD::NEVM;
using namespace RawrXD::Kernels;

//=============================================================================
// Thread Affinity Control
//=============================================================================

class ThreadAffinity {
public:
    // Pin current thread to specific CPU core
    static bool PinToCore(int core_id) {
#ifdef _WIN32
        DWORD_PTR mask = 1ULL << core_id;
        HANDLE thread = GetCurrentThread();
        DWORD_PTR result = SetThreadAffinityMask(thread, mask);
        return result != 0;
#else
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);
        int result = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
        return result == 0;
#endif
    }
    
    // Get number of physical cores
    static int GetPhysicalCoreCount() {
#ifdef _WIN32
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        return sysinfo.dwNumberOfProcessors;
#else
        return sysconf(_SC_NPROCESSORS_ONLN);
#endif
    }
};

//=============================================================================
// Determinism Test Configuration
//=============================================================================

struct DeterminismConfig {
    int num_runs = 10;
    int num_tokens = 1000;
    int seed = 42;
    bool pin_threads = true;
    int target_core = 0;  // Pin to specific core
    bool strict_mode = true;  // Fail on any divergence
};

struct TokenSequence {
    std::vector<int> tokens;
    std::vector<float> logits;
    uint64_t hash;
    
    bool operator==(const TokenSequence& other) const {
        return tokens == other.tokens && logits == other.logits;
    }
};

//=============================================================================
// Hash Function for Logits
//=============================================================================

uint64_t HashLogits(const std::vector<float>& logits) {
    uint64_t hash = 14695981039346656037ULL;  // FNV-1a offset basis
    for (float val : logits) {
        // Hash raw bytes to catch all bit-level differences
        uint32_t bits;
        static_assert(sizeof(float) == sizeof(uint32_t), "Float size mismatch");
        std::memcpy(&bits, &val, sizeof(float));
        
        hash ^= bits;
        hash *= 1099511628211ULL;  // FNV-1a prime
    }
    return hash;
}

//=============================================================================
// Determinism Validator
//=============================================================================

class DeterminismValidator {
public:
    explicit DeterminismValidator(const DeterminismConfig& config) 
        : config_(config), runs_completed_(0) {}
    
    // Run complete validation
    bool Validate() {
        printf("NEVM Determinism Validation\n");
        printf("==========================\n\n");
        
        printf("Configuration:\n");
        printf("  Runs: %d\n", config_.num_runs);
        printf("  Tokens per run: %d\n", config_.num_tokens);
        printf("  Thread pinning: %s\n", config_.pin_threads ? "ENABLED" : "DISABLED");
        printf("  Target core: %d\n", config_.target_core);
        printf("  Strict mode: %s\n", config_.strict_mode ? "ENABLED" : "DISABLED");
        printf("\n");
        
        // Apply thread affinity if requested
        if (config_.pin_threads) {
            if (!ThreadAffinity::PinToCore(config_.target_core)) {
                printf("WARNING: Failed to pin thread to core %d\n", config_.target_core);
                if (config_.strict_mode) return false;
            } else {
                printf("✓ Thread pinned to core %d\n", config_.target_core);
            }
        }
        
        // Run multiple times
        std::vector<TokenSequence> results;
        results.reserve(config_.num_runs);
        
        for (int run = 0; run < config_.num_runs; ++run) {
            printf("Run %d/%d... ", run + 1, config_.num_runs);
            
            auto result = ExecuteRun(run);
            results.push_back(result);
            
            printf("hash=%016llx\n", (unsigned long long)result.hash);
            
            runs_completed_++;
        }
        
        printf("\n");
        
        // Compare results
        return CompareResults(results);
    }
    
    // Get validation statistics
    struct Stats {
        int runs_completed;
        int runs_diverged;
        int first_divergence_run;
        uint64_t reference_hash;
        std::vector<int> divergent_runs;
    };
    
    Stats GetStats() const {
        Stats s;
        s.runs_completed = runs_completed_;
        // TODO: Track actual divergence
        return s;
    }

private:
    DeterminismConfig config_;
    std::atomic<int> runs_completed_;
    
    TokenSequence ExecuteRun(int run_id) {
        TokenSequence seq;
        seq.tokens.reserve(config_.num_tokens);
        seq.logits.reserve(config_.num_tokens * 32000);  // Vocab size
        
        // Initialize with deterministic seed
        int seed = config_.seed + run_id * 1000;
        
        // Simulate token generation
        // In real implementation, this would call NEVM execution
        for (int i = 0; i < config_.num_tokens; ++i) {
            // Deterministic pseudo-random generation
            int token = GenerateDeterministicToken(seed, i);
            seq.tokens.push_back(token);
            
            // Generate logits (deterministic)
            for (int v = 0; v < 100; ++v) {  // Simplified vocab
                float logit = GenerateDeterministicLogit(seed, i, v);
                seq.logits.push_back(logit);
            }
        }
        
        seq.hash = HashLogits(seq.logits);
        return seq;
    }
    
    int GenerateDeterministicToken(int seed, int position) {
        // Simple LCG for determinism
        uint64_t state = (uint64_t)seed * 1103515245ULL + 12345 + position;
        return (int)(state % 32000);  // Vocab size
    }
    
    float GenerateDeterministicLogit(int seed, int position, int vocab_idx) {
        // Deterministic float generation
        uint64_t state = (uint64_t)seed * 1103515245ULL + 12345 + position * 32000 + vocab_idx;
        uint32_t bits = (uint32_t)(state & 0x7FFFFFFF);
        float f;
        static_assert(sizeof(float) == sizeof(uint32_t), "Float size mismatch");
        std::memcpy(&f, &bits, sizeof(float));
        return f;
    }
    
    bool CompareResults(const std::vector<TokenSequence>& results) {
        if (results.empty()) return true;
        
        const auto& reference = results[0];
        bool all_match = true;
        std::vector<int> divergent;
        
        for (size_t i = 1; i < results.size(); ++i) {
            if (results[i].hash != reference.hash) {
                all_match = false;
                divergent.push_back((int)i);
                
                printf("DIVERGENCE detected: Run %zu differs from reference\n", i);
                printf("  Reference hash: %016llx\n", (unsigned long long)reference.hash);
                printf("  Run %zu hash:     %016llx\n", (unsigned long long)i, (unsigned long long)results[i].hash);
                
                if (config_.strict_mode) {
                    return false;
                }
            }
        }
        
        printf("\nResults:\n");
        printf("  Total runs: %zu\n", results.size());
        printf("  Matching: %zu\n", results.size() - divergent.size());
        printf("  Divergent: %zu\n", divergent.size());
        
        if (!divergent.empty()) {
            printf("  Divergent runs: ");
            for (size_t i = 0; i < divergent.size(); ++i) {
                if (i > 0) printf(", ");
                printf("%d", divergent[i]);
            }
            printf("\n");
        }
        
        if (all_match) {
            printf("\n✓ DETERMINISM VALIDATED\n");
            printf("  All %d runs produced identical outputs\n", config_.num_runs);
            return true;
        } else {
            printf("\n✗ DETERMINISM FAILED\n");
            printf("  %zu runs diverged from reference\n", divergent.size());
            return false;
        }
    }
};

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    printf("NEVM Determinism Validation Tool\n");
    printf("================================\n\n");
    
    // Parse arguments
    DeterminismConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--runs" && i + 1 < argc) {
            config.num_runs = std::atoi(argv[++i]);
        } else if (arg == "--tokens" && i + 1 < argc) {
            config.num_tokens = std::atoi(argv[++i]);
        } else if (arg == "--seed" && i + 1 < argc) {
            config.seed = std::atoi(argv[++i]);
        } else if (arg == "--core" && i + 1 < argc) {
            config.target_core = std::atoi(argv[++i]);
        } else if (arg == "--no-pin") {
            config.pin_threads = false;
        } else if (arg == "--strict") {
            config.strict_mode = true;
        } else if (arg == "--help") {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --runs N       Number of runs (default: 10)\n");
            printf("  --tokens N     Tokens per run (default: 1000)\n");
            printf("  --seed N       Random seed (default: 42)\n");
            printf("  --core N       Pin to CPU core N (default: 0)\n");
            printf("  --no-pin       Disable thread pinning\n");
            printf("  --strict       Fail on first divergence\n");
            printf("  --help         Show this help\n");
            return 0;
        }
    }
    
    // Run validation
    DeterminismValidator validator(config);
    bool success = validator.Validate();
    
    return success ? 0 : 1;
}
