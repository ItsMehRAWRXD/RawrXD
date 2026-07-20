//============================================================================
// nevm_ab_testing.cpp
// RawrXD N-EVM - A/B Testing Framework
// Compares configurations to isolate feature contributions
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <json/json.h>

using namespace RawrXD::NEVM;

//============================================================================
// Test Configuration
//============================================================================

enum class Feature {
    BASELINE,              // No NEVM features
    KERNEL_REGISTRY,       // + Kernel selection
    MMU,                   // + Memory management
    ADAPTIVE_PRECISION,    // + Dynamic precision
    RESIDENCY,             // + Residency management
    FULL_NEVM             // + All features
};

struct ABTestConfig {
    std::wstring model_path;
    std::string prompt;
    int num_tokens;
    int num_warmup;
    Feature feature_set;
    std::string name;
};

struct ABTestResult {
    std::string config_name;
    float throughput_tok_s;
    float memory_mb;
    float ttft_ms;
    float latency_p99_ms;
    bool passed;
    std::string notes;
};

//============================================================================
// Feature Configuration
//============================================================================

class FeatureConfigurator {
public:
    static void Configure(NEVM_v2::Config& config, Feature f) {
        // Reset to baseline
        config.enable_adaptive_precision = false;
        config.enable_prefetch = false;
        config.enable_tracing = false;
        
        switch (f) {
            case Feature::BASELINE:
                // Minimal configuration
                config.ram_budget = 64ULL * 1024 * 1024 * 1024;
                config.vram_budget = 16ULL * 1024 * 1024 * 1024;
                break;
                
            case Feature::KERNEL_REGISTRY:
                // Baseline + kernel registry
                config.ram_budget = 64ULL * 1024 * 1024 * 1024;
                config.vram_budget = 16ULL * 1024 * 1024 * 1024;
                // Kernel registry is always on, but we can disable dispatch optimization
                break;
                
            case Feature::MMU:
                // + MMU with TLB
                config.ram_budget = 64ULL * 1024 * 1024 * 1024;
                config.vram_budget = 16ULL * 1024 * 1024 * 1024;
                config.l3_cache_size = 32 * 1024 * 1024;
                break;
                
            case Feature::ADAPTIVE_PRECISION:
                // + Precision controller
                config.ram_budget = 64ULL * 1024 * 1024 * 1024;
                config.vram_budget = 16ULL * 1024 * 1024 * 1024;
                config.enable_adaptive_precision = true;
                break;
                
            case Feature::RESIDENCY:
                // + Residency + Prefetch
                config.ram_budget = 64ULL * 1024 * 1024 * 1024;
                config.vram_budget = 16ULL * 1024 * 1024 * 1024;
                config.enable_prefetch = true;
                config.max_prefetch_threads = 4;
                break;
                
            case Feature::FULL_NEVM:
                // Everything enabled
                config.ram_budget = 64ULL * 1024 * 1024 * 1024;
                config.vram_budget = 16ULL * 1024 * 1024 * 1024;
                config.l3_cache_size = 32 * 1024 * 1024;
                config.enable_adaptive_precision = true;
                config.enable_prefetch = true;
                config.max_prefetch_threads = 4;
                config.enable_tracing = false;
                break;
        }
    }
    
    static const char* GetFeatureName(Feature f) {
        switch (f) {
            case Feature::BASELINE: return "Baseline";
            case Feature::KERNEL_REGISTRY: return "+ Kernel Registry";
            case Feature::MMU: return "+ MMU";
            case Feature::ADAPTIVE_PRECISION: return "+ Adaptive Precision";
            case Feature::RESIDENCY: return "+ Residency";
            case Feature::FULL_NEVM: return "Full NEVM";
        }
        return "Unknown";
    }
};

//============================================================================
// A/B Test Runner
//============================================================================

class ABTestRunner {
public:
    ABTestRunner() = default;
    
    ABTestResult RunTest(const ABTestConfig& config) {
        ABTestResult result;
        result.config_name = config.name;
        result.passed = false;
        
        std::cout << "Running: " << config.name << "\n";
        
        // Configure VM
        NEVM_v2::Config vm_config;
        FeatureConfigurator::Configure(vm_config, config.feature_set);
        
        // Create and initialize VM
        auto vm = std::make_unique<NEVM_v2>(vm_config);
        if (!vm->Initialize()) {
            result.notes = "Failed to initialize VM";
            return result;
        }
        
        if (!vm->LoadModel(config.model_path)) {
            result.notes = "Failed to load model";
            return result;
        }
        
        auto loader = vm->GetLoader();
        if (!loader) {
            result.notes = "Failed to get loader";
            return result;
        }
        
        // Create transformer engine
        auto metadata = loader->GetMetadata();
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
        
        auto engine = std::make_unique<TransformerEngine>(vm.get(), engine_config);
        if (!engine->Initialize(loader)) {
            result.notes = "Failed to initialize engine";
            return result;
        }
        
        // Tokenize
        std::vector<int32_t> tokens = Tokenize(config.prompt);
        
        // Warmup
        std::vector<float> logits(metadata.vocab_size);
        for (int i = 0; i < config.num_warmup; ++i) {
            engine->Forward(tokens.data(), logits.data(), 
                          static_cast<uint32_t>(tokens.size()));
        }
        
        // Benchmark
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<float> latencies;
        latencies.reserve(config.num_tokens);
        
        for (int i = 0; i < config.num_tokens; ++i) {
            auto token_start = std::chrono::high_resolution_clock::now();
            
            int32_t next_token = 0;
            engine->GenerateStep(&next_token, logits.data(), 
                                static_cast<uint32_t>(tokens.size()) + i);
            
            auto token_end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                token_end - token_start);
            latencies.push_back(duration.count() / 1000.0f);
            
            tokens.push_back(next_token);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start);
        
        // Calculate metrics
        result.throughput_tok_s = config.num_tokens / (total_duration.count() / 1000.0f);
        
        auto stats = vm->GetStats();
        result.memory_mb = (stats.vram_used + stats.ram_used) / (1024.0f * 1024.0f);
        
        // TTFT (first token time - approximate)
        result.ttft_ms = latencies.empty() ? 0.0f : latencies[0];
        
        // P99 latency
        std::sort(latencies.begin(), latencies.end());
        size_t p99_idx = static_cast<size_t>(latencies.size() * 0.99f);
        if (p99_idx >= latencies.size()) p99_idx = latencies.size() - 1;
        result.latency_p99_ms = latencies[p99_idx];
        
        result.passed = true;
        result.notes = "Success";
        
        return result;
    }
    
    void PrintComparisonTable(const std::vector<ABTestResult>& results) {
        std::cout << "\n";
        std::cout << "============================================================================\n";
        std::cout << "A/B Test Results\n";
        std::cout << "============================================================================\n\n";
        
        // Header
        std::cout << std::left << std::setw(25) << "Configuration"
                  << std::setw(12) << "Tok/s"
                  << std::setw(12) << "Memory(MB)"
                  << std::setw(12) << "TTFT(ms)"
                  << std::setw(12) << "P99(ms)"
                  << std::setw(10) << "Status"
                  << "\n";
        std::cout << std::string(90, '-') << "\n";
        
        // Results
        for (const auto& r : results) {
            std::cout << std::left << std::setw(25) << r.config_name
                      << std::setw(12) << std::fixed << std::setprecision(2) << r.throughput_tok_s
                      << std::setw(12) << std::setprecision(1) << r.memory_mb
                      << std::setw(12) << std::setprecision(2) << r.ttft_ms
                      << std::setw(12) << r.latency_p99_ms
                      << std::setw(10) << (r.passed ? "PASS" : "FAIL")
                      << "\n";
        }
        
        // Calculate improvements
        if (results.size() >= 2 && results[0].passed && results.back().passed) {
            const auto& baseline = results[0];
            const auto& full = results.back();
            
            float speedup = full.throughput_tok_s / baseline.throughput_tok_s;
            float memory_reduction = (baseline.memory_mb - full.memory_mb) / baseline.memory_mb * 100.0f;
            
            std::cout << "\n";
            std::cout << "Improvement (Full NEVM vs Baseline):\n";
            std::cout << "  Throughput: " << std::fixed << std::setprecision(2) << speedup << "x\n";
            std::cout << "  Memory:     " << std::setprecision(1) << memory_reduction << "% reduction\n";
        }
        
        std::cout << "\n";
    }
    
    void ExportResults(const std::vector<ABTestResult>& results, 
                      const std::string& path) {
        Json::Value root;
        
        for (const auto& r : results) {
            Json::Value entry;
            entry["name"] = r.config_name;
            entry["throughput_tok_s"] = r.throughput_tok_s;
            entry["memory_mb"] = r.memory_mb;
            entry["ttft_ms"] = r.ttft_ms;
            entry["latency_p99_ms"] = r.latency_p99_ms;
            entry["passed"] = r.passed;
            entry["notes"] = r.notes;
            root["results"].append(entry);
        }
        
        std::ofstream file(path);
        if (file.is_open()) {
            Json::StreamWriterBuilder builder;
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(root, &file);
        }
    }

private:
    std::vector<int32_t> Tokenize(const std::string& text) {
        std::vector<int32_t> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<int32_t>(c));
        }
        return tokens;
    }
};

//============================================================================
// Main
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -n, --tokens <n>      Tokens per config (default: 128)\n";
    std::cout << "  -w, --warmup <n>      Warmup tokens (default: 10)\n";
    std::cout << "  -p, --prompt <text>   Prompt text\n";
    std::cout << "  -o, --output <file>   Export results to JSON\n";
    std::cout << "  --skip-baseline       Skip baseline test\n";
    std::cout << "  --skip-full           Skip full NEVM test\n";
    std::cout << "  -h, --help            Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_ab_testing");
        return 1;
    }
    
    std::wstring model_path = argv[1];
    int num_tokens = 128;
    int num_warmup = 10;
    std::string prompt = "Hello world";
    std::string output_path;
    bool skip_baseline = false;
    bool skip_full = false;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-n" || arg == L"--tokens") {
            if (i + 1 < argc) num_tokens = _wtoi(argv[++i]);
        } else if (arg == L"-w" || arg == L"--warmup") {
            if (i + 1 < argc) num_warmup = _wtoi(argv[++i]);
        } else if (arg == L"-p" || arg == L"--prompt") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                prompt.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    prompt[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-o" || arg == L"--output") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                output_path.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    output_path[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"--skip-baseline") {
            skip_baseline = true;
        } else if (arg == L"--skip-full") {
            skip_full = true;
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_ab_testing");
            return 0;
        }
    }
    
    std::cout << "============================================================================\n";
    std::cout << "RawrXD N-EVM A/B Testing Framework\n";
    std::cout << "============================================================================\n\n";
    
    // Build test list
    std::vector<ABTestConfig> tests;
    
    if (!skip_baseline) {
        tests.push_back({model_path, prompt, num_tokens, num_warmup, 
                        Feature::BASELINE, "Baseline"});
    }
    
    tests.push_back({model_path, prompt, num_tokens, num_warmup,
                    Feature::KERNEL_REGISTRY, "+ Kernel Registry"});
    tests.push_back({model_path, prompt, num_tokens, num_warmup,
                    Feature::MMU, "+ MMU"});
    tests.push_back({model_path, prompt, num_tokens, num_warmup,
                    Feature::ADAPTIVE_PRECISION, "+ Adaptive Precision"});
    tests.push_back({model_path, prompt, num_tokens, num_warmup,
                    Feature::RESIDENCY, "+ Residency"});
    
    if (!skip_full) {
        tests.push_back({model_path, prompt, num_tokens, num_warmup,
                        Feature::FULL_NEVM, "Full NEVM"});
    }
    
    // Run tests
    ABTestRunner runner;
    std::vector<ABTestResult> results;
    
    for (const auto& test : tests) {
        auto result = runner.RunTest(test);
        results.push_back(result);
        
        if (!result.passed) {
            std::cerr << "Test failed: " << result.notes << "\n";
        }
        std::cout << "\n";
    }
    
    // Print results
    runner.PrintComparisonTable(results);
    
    // Export if requested
    if (!output_path.empty()) {
        runner.ExportResults(results, output_path);
        std::cout << "Results exported to: " << output_path << "\n";
    }
    
    // Return success if all passed
    for (const auto& r : results) {
        if (!r.passed) return 1;
    }
    
    return 0;
}
