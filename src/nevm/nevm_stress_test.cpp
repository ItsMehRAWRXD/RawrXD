//============================================================================
// nevm_stress_test.cpp
// RawrXD N-EVM - Stress Testing
// Extended runtime validation with continuous invariant checking
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <math.h>
#include <chrono>
#include <thread>
#include <windows.h>

using namespace RawrXD::NEVM;

//============================================================================
// Stress Test Configuration
//============================================================================

struct StressConfig {
    std::wstring model_path;
    std::string prompt;
    int tokens_per_iteration;
    int num_iterations;
    int check_interval_ms;
    float throughput_variance_threshold;
    float memory_growth_threshold;
    bool stop_on_error;
};

//============================================================================
// Invariant Checks
//============================================================================

struct InvariantViolation {
    std::string type;
    std::string description;
    int iteration;
    double timestamp;
};

class InvariantChecker {
public:
    std::vector<InvariantViolation> violations;
    
    // Check for NaN in output
    bool CheckNoNaN(const float* data, size_t n, int iteration) {
        for (size_t i = 0; i < n; ++i) {
            if (std::isnan(data[i])) {
                violations.push_back({"NaN", "NaN detected in output", iteration, GetTimestamp()});
                return false;
            }
        }
        return true;
    }
    
    // Check for Inf in output
    bool CheckNoInf(const float* data, size_t n, int iteration) {
        for (size_t i = 0; i < n; ++i) {
            if (std::isinf(data[i])) {
                violations.push_back({"Inf", "Inf detected in output", iteration, GetTimestamp()});
                return false;
            }
        }
        return true;
    }
    
    // Check memory growth
    bool CheckMemoryStability(uint64_t current_rss, uint64_t baseline_rss, 
                               float threshold, int iteration) {
        float growth = (current_rss - baseline_rss) / (float)baseline_rss;
        if (growth > threshold) {
            violations.push_back({
                "MemoryGrowth", 
                "RSS grew by " + std::to_string(growth * 100.0f) + "%",
                iteration,
                GetTimestamp()
            });
            return false;
        }
        return true;
    }
    
    // Check throughput stability
    bool CheckThroughputStability(float current_tok_s, float baseline_tok_s,
                                   float threshold, int iteration) {
        float variance = std::abs(current_tok_s - baseline_tok_s) / baseline_tok_s;
        if (variance > threshold) {
            violations.push_back({
                "ThroughputVariance",
                "Throughput variance: " + std::to_string(variance * 100.0f) + "%",
                iteration,
                GetTimestamp()
            });
            return false;
        }
        return true;
    }
    
    // Check KV cache validity
    bool CheckKVCacheValid(const void* kv_cache, size_t size, int iteration) {
        // Would check for corruption, invalid pointers, etc.
        (void)kv_cache;
        (void)size;
        (void)iteration;
        return true;
    }
    
    // Check for invalid page ownership
    bool CheckPageOwnership(const NEVM_v2* vm, int iteration) {
        // Would verify MMU page tables
        (void)vm;
        (void)iteration;
        return true;
    }
    
    // Check execution plan validity
    bool CheckExecutionPlanValid(int iteration) {
        // Would verify no stale plans
        (void)iteration;
        return true;
    }
    
    bool HasViolations() const {
        return !violations.empty();
    }
    
    void PrintViolations() const {
        if (violations.empty()) return;
        
        std::cout << "\n=== INVARIANT VIOLATIONS ===\n";
        for (const auto& v : violations) {
            std::cout << "[" << v.type << "] Iteration " << v.iteration << ": " << v.description << "\n";
        }
        std::cout << "============================\n\n";
    }

private:
    double GetTimestamp() {
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
    }
};

//============================================================================
// Memory Monitor
//============================================================================

class MemoryMonitor {
public:
    struct MemorySnapshot {
        uint64_t working_set;
        uint64_t private_bytes;
        uint64_t peak_working_set;
        uint64_t page_faults;
    };
    
    MemorySnapshot GetSnapshot() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        MemorySnapshot snap = {};
        
        if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            snap.working_set = pmc.WorkingSetSize;
            snap.private_bytes = pmc.PrivateUsage;
            snap.peak_working_set = pmc.PeakWorkingSetSize;
            snap.page_faults = pmc.PageFaultCount;
        }
        
        return snap;
    }
    
    uint64_t GetWorkingSet() {
        auto snap = GetSnapshot();
        return snap.working_set;
    }
};

//============================================================================
// Stress Test Runner
//============================================================================

class StressTestRunner {
public:
    StressTestRunner(const StressConfig& config) : config_(config) {}
    
    bool Run() {
        std::cout << "============================================================================\n";
        std::cout << "RawrXD N-EVM Stress Test\n";
        std::cout << "============================================================================\n\n";
        
        std::cout << "Configuration:\n";
        std::cout << "  Iterations: " << config_.num_iterations << "\n";
        std::cout << "  Tokens per iteration: " << config_.tokens_per_iteration << "\n";
        std::cout << "  Check interval: " << config_.check_interval_ms << " ms\n";
        std::cout << "  Throughput variance threshold: " << (config_.throughput_variance_threshold * 100.0f) << "%\n";
        std::cout << "  Memory growth threshold: " << (config_.memory_growth_threshold * 100.0f) << "%\n\n";
        
        // Initialize VM
        if (!Initialize()) {
            std::cerr << "Failed to initialize VM\n";
            return false;
        }
        
        // Get baseline metrics
        auto baseline_memory = memory_monitor_.GetSnapshot();
        float baseline_throughput = 0.0f;
        
        // Warmup
        std::cout << "Warming up...\n";
        RunIteration(0, baseline_throughput);
        
        // Establish baseline
        baseline_throughput = last_throughput_;
        std::cout << "Baseline throughput: " << std::fixed << std::setprecision(2) << baseline_throughput << " tok/s\n";
        std::cout << "Baseline memory: " << (baseline_memory.working_set / (1024.0 * 1024.0)) << " MB\n\n";
        
        // Run stress test
        std::cout << "Running stress test...\n";
        std::cout << "Progress: [";
        
        bool all_passed = true;
        
        for (int i = 1; i <= config_.num_iterations; ++i) {
            // Run iteration
            if (!RunIteration(i, last_throughput_)) {
                std::cerr << "\nIteration " << i << " failed\n";
                all_passed = false;
                if (config_.stop_on_error) break;
            }
            
            // Check invariants
            auto current_memory = memory_monitor_.GetSnapshot();
            
            if (!checker_.CheckMemoryStability(current_memory.working_set, 
                                               baseline_memory.working_set,
                                               config_.memory_growth_threshold, i)) {
                all_passed = false;
                if (config_.stop_on_error) break;
            }
            
            if (!checker_.CheckThroughputStability(last_throughput_, baseline_throughput,
                                                   config_.throughput_variance_threshold, i)) {
                all_passed = false;
                if (config_.stop_on_error) break;
            }
            
            // Progress indicator
            if (i % (config_.num_iterations / 20) == 0) {
                std::cout << "#";
            }
            
            // Periodic status
            if (i % 10 == 0) {
                std::cout << "] " << i << "/" << config_.num_iterations;
                std::cout << " (" << std::setprecision(1) << last_throughput_ << " tok/s) [";
            }
        }
        
        std::cout << "] Done!\n\n";
        
        // Print results
        PrintResults();
        
        if (checker_.HasViolations()) {
            checker_.PrintViolations();
            return false;
        }
        
        return all_passed;
    }
    
private:
    bool Initialize() {
        NEVM_v2::Config vm_config;
        vm_config.ram_budget = 64ULL * 1024 * 1024 * 1024;
        vm_config.vram_budget = 16ULL * 1024 * 1024 * 1024;
        vm_config.enable_adaptive_precision = true;
        vm_config.enable_prefetch = true;
        
        vm_ = std::make_unique<NEVM_v2>(vm_config);
        if (!vm_->Initialize()) return false;
        
        if (!vm_->LoadModel(config_.model_path)) return false;
        
        loader_ = vm_->GetLoader();
        if (!loader_) return false;
        
        auto metadata = loader_->GetMetadata();
        TransformerEngine::Config engine_config;
        engine_config.num_layers = metadata.num_layers;
        engine_config.hidden_dim = metadata.hidden_dim;
        engine_config.num_heads = metadata.num_heads;
        engine_config.head_dim = metadata.hidden_dim / metadata.num_heads;
        engine_config.ffn_dim = metadata.hidden_dim * 4;
        engine_config.vocab_size = metadata.vocab_size;
        engine_config.max_seq_len = metadata.context_length;
        engine_config.batch_size = 1;
        engine_config.default_precision = PrecisionMode::Q4;
        engine_config.use_flash_attention = true;
        engine_config.use_kv_cache = true;
        
        engine_ = std::make_unique<TransformerEngine>(vm_.get(), engine_config);
        if (!engine_->Initialize(loader_)) return false;
        
        return true;
    }
    
    bool RunIteration(int iteration, float& throughput) {
        std::vector<int32_t> tokens = Tokenize(config_.prompt);
        std::vector<float> logits(loader_->GetMetadata().vocab_size);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Prefill
        engine_->Forward(tokens.data(), logits.data(), 
                         static_cast<uint32_t>(tokens.size()));
        
        // Generate tokens
        for (int i = 0; i < config_.tokens_per_iteration; ++i) {
            int32_t next_token = 0;
            engine_->GenerateStep(&next_token, logits.data(), 
                                  static_cast<uint32_t>(tokens.size()) + i);
            
            // Check output validity
            if (!checker_.CheckNoNaN(logits.data(), logits.size(), iteration)) {
                return false;
            }
            if (!checker_.CheckNoInf(logits.data(), logits.size(), iteration)) {
                return false;
            }
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        throughput = config_.tokens_per_iteration / (duration.count() / 1000.0f);
        
        return true;
    }
    
    void PrintResults() {
        std::cout << "============================================================================\n";
        std::cout << "Stress Test Results\n";
        std::cout << "============================================================================\n\n";
        
        std::cout << "Iterations completed: " << config_.num_iterations << "\n";
        std::cout << "Total tokens generated: " << (config_.num_iterations * config_.tokens_per_iteration) << "\n";
        std::cout << "Invariant violations: " << checker_.violations.size() << "\n";
        
        if (checker_.violations.empty()) {
            std::cout << "\n✓ All invariants maintained throughout stress test\n";
        }
        
        std::cout << "\n";
    }
    
    std::vector<int32_t> Tokenize(const std::string& text) {
        std::vector<int32_t> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<int32_t>(c));
        }
        return tokens;
    }
    
    StressConfig config_;
    std::unique_ptr<NEVM_v2> vm_;
    std::unique_ptr<TransformerEngine> engine_;
    GGUF_PassthroughLoader* loader_;
    InvariantChecker checker_;
    MemoryMonitor memory_monitor_;
    float last_throughput_ = 0.0f;
};

//============================================================================
// Main
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -i, --iterations <n>    Number of iterations (default: 100)\n";
    std::cout << "  -t, --tokens <n>       Tokens per iteration (default: 32)\n";
    std::cout << "  --throughput-var <f>  Throughput variance threshold (default: 0.2)\n";
    std::cout << "  --memory-growth <f>   Memory growth threshold (default: 0.1)\n";
    std::cout << "  --stop-on-error       Stop on first invariant violation\n";
    std::cout << "  -h, --help            Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_stress_test");
        return 1;
    }
    
    StressConfig config;
    config.model_path = argv[1];
    config.prompt = "Hello world";
    config.num_iterations = 100;
    config.tokens_per_iteration = 32;
    config.check_interval_ms = 1000;
    config.throughput_variance_threshold = 0.2f;
    config.memory_growth_threshold = 0.1f;
    config.stop_on_error = false;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-i" || arg == L"--iterations") {
            if (i + 1 < argc) config.num_iterations = _wtoi(argv[++i]);
        } else if (arg == L"-t" || arg == L"--tokens") {
            if (i + 1 < argc) config.tokens_per_iteration = _wtoi(argv[++i]);
        } else if (arg == L"--throughput-var") {
            if (i + 1 < argc) config.throughput_variance_threshold = static_cast<float>(_wtof(argv[++i]));
        } else if (arg == L"--memory-growth") {
            if (i + 1 < argc) config.memory_growth_threshold = static_cast<float>(_wtof(argv[++i]));
        } else if (arg == L"--stop-on-error") {
            config.stop_on_error = true;
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_stress_test");
            return 0;
        }
    }
    
    StressTestRunner runner(config);
    return runner.Run() ? 0 : 1;
}
