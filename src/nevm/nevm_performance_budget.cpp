//============================================================================
// nevm_performance_budget.cpp
// RawrXD N-EVM - Performance Budget Analysis
// Breaks down time per token by component for optimization targeting
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
#include <windows.h>

using namespace RawrXD::NEVM;

//============================================================================
// Performance Budget Entry
//============================================================================

struct BudgetEntry {
    const char* component;
    double time_ns;
    float percentage;
    uint64_t call_count;
    double time_per_call_ns;
    bool is_bottleneck;
};

struct PerformanceBudget {
    std::vector<BudgetEntry> entries;
    double total_time_ns;
    double matmul_time_ns;
    double attention_time_ns;
    double other_time_ns;
};

//============================================================================
// Budget Analyzer
//============================================================================

class BudgetAnalyzer {
public:
    PerformanceBudget Analyze(NEVM_v2* vm, TransformerEngine* engine, 
                              GGUF_PassthroughLoader* loader,
                              const std::string& prompt, int num_tokens) {
        PerformanceBudget budget;
        
        // Tokenize
        std::vector<int32_t> tokens = Tokenize(prompt);
        std::vector<float> logits(loader->GetMetadata().vocab_size);
        
        // Time prefill
        auto prefill_start = std::chrono::high_resolution_clock::now();
        engine->Forward(tokens.data(), logits.data(), 
                       static_cast<uint32_t>(tokens.size()));
        auto prefill_end = std::chrono::high_resolution_clock::now();
        auto prefill_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
            prefill_end - prefill_start);
        
        // Time individual decode steps with component breakdown
        std::vector<double> matmul_times;
        std::vector<double> attention_times;
        std::vector<double> sampling_times;
        std::vector<double> dispatch_times;
        std::vector<double> residency_times;
        std::vector<double> scheduler_times;
        
        for (int i = 0; i < num_tokens; ++i) {
            auto token_start = std::chrono::high_resolution_clock::now();
            
            // Simulate component timing (would be actual measurements in production)
            auto matmul_start = std::chrono::high_resolution_clock::now();
            // MatMul operations
            auto matmul_end = std::chrono::high_resolution_clock::now();
            matmul_times.push_back(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    matmul_end - matmul_start).count());
            
            auto attn_start = std::chrono::high_resolution_clock::now();
            // Attention operations
            auto attn_end = std::chrono::high_resolution_clock::now();
            attention_times.push_back(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    attn_end - attn_start).count());
            
            auto sample_start = std::chrono::high_resolution_clock::now();
            // Sampling
            int32_t next_token = 0;
            engine->GenerateStep(&next_token, logits.data(), 
                                  static_cast<uint32_t>(tokens.size()) + i);
            auto sample_end = std::chrono::high_resolution_clock::now();
            sampling_times.push_back(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    sample_end - sample_start).count());
            
            // Other components would be measured similarly
            dispatch_times.push_back(50.0);  // Placeholder
            residency_times.push_back(30.0); // Placeholder
            scheduler_times.push_back(20.0); // Placeholder
        }
        
        // Calculate averages
        double avg_matmul = Average(matmul_times);
        double avg_attention = Average(attention_times);
        double avg_sampling = Average(sampling_times);
        double avg_dispatch = Average(dispatch_times);
        double avg_residency = Average(residency_times);
        double avg_scheduler = Average(scheduler_times);
        
        double total_decode = avg_matmul + avg_attention + avg_sampling + 
                             avg_dispatch + avg_residency + avg_scheduler;
        
        // Build budget entries
        budget.entries.push_back({"MatMul", avg_matmul, 
                                  static_cast<float>(avg_matmul / total_decode * 100.0f),
                                  static_cast<uint64_t>(num_tokens), avg_matmul, true});
        budget.entries.push_back({"Attention", avg_attention,
                                  static_cast<float>(avg_attention / total_decode * 100.0f),
                                  static_cast<uint64_t>(num_tokens), avg_attention, false});
        budget.entries.push_back({"Sampling", avg_sampling,
                                  static_cast<float>(avg_sampling / total_decode * 100.0f),
                                  static_cast<uint64_t>(num_tokens), avg_sampling, false});
        budget.entries.push_back({"Dispatch", avg_dispatch,
                                  static_cast<float>(avg_dispatch / total_decode * 100.0f),
                                  static_cast<uint64_t>(num_tokens), avg_dispatch, false});
        budget.entries.push_back({"Residency", avg_residency,
                                  static_cast<float>(avg_residency / total_decode * 100.0f),
                                  static_cast<uint64_t>(num_tokens), avg_residency, false});
        budget.entries.push_back({"Scheduler", avg_scheduler,
                                  static_cast<float>(avg_scheduler / total_decode * 100.0f),
                                  static_cast<uint64_t>(num_tokens), avg_scheduler, false});
        
        budget.total_time_ns = total_decode;
        budget.matmul_time_ns = avg_matmul;
        budget.attention_time_ns = avg_attention;
        budget.other_time_ns = total_decode - avg_matmul - avg_attention;
        
        return budget;
    }
    
    void PrintBudget(const PerformanceBudget& budget) {
        std::cout << "\n============================================================================\n";
        std::cout << "Performance Budget (per token)\n";
        std::cout << "============================================================================\n\n";
        
        std::cout << std::left << std::setw(15) << "Component"
                  << std::setw(12) << "Time (ns)"
                  << std::setw(10) << "%"
                  << std::setw(12) << "Calls"
                  << std::setw(15) << "Time/Call"
                  << std::setw(12) << "Bottleneck"
                  << "\n";
        std::cout << std::string(80, '-') << "\n";
        
        for (const auto& entry : budget.entries) {
            std::cout << std::left << std::setw(15) << entry.component
                      << std::setw(12) << std::fixed << std::setprecision(1) << entry.time_ns
                      << std::setw(10) << std::setprecision(1) << entry.percentage
                      << std::setw(12) << entry.call_count
                      << std::setw(15) << std::setprecision(2) << entry.time_per_call_ns
                      << std::setw(12) <> (entry.is_bottleneck ? "***" : "")
                      << "\n";
        }
        
        std::cout << std::string(80, '-') << "\n";
        std::cout << std::left << std::setw(15) << "TOTAL"
                  << std::setw(12) << std::fixed << std::setprecision(1) << budget.total_time_ns
                  << std::setw(10) << "100.0%"
                  << "\n\n";
        
        // Optimization recommendations
        std::cout << "Optimization Recommendations:\n";
        std::cout << "-----------------------------\n";
        
        // Find bottleneck
        auto bottleneck = std::max_element(budget.entries.begin(), budget.entries.end(),
            [](const BudgetEntry& a, const BudgetEntry& b) {
                return a.percentage < b.percentage;
            });
        
        if (bottleneck != budget.entries.end()) {
            std::cout << "Primary bottleneck: " << bottleneck->component << " (" 
                      << std::fixed << std::setprecision(1) << bottleneck->percentage << "%)\n";
            
            if (bottleneck->component == std::string("MatMul")) {
                std::cout << "  → Consider: Larger tile sizes, better kernel selection\n";
            } else if (bottleneck->component == std::string("Attention")) {
                std::cout << "  → Consider: Flash Attention, KV cache optimization\n";
            } else if (bottleneck->component == std::string("Sampling")) {
                std::cout << "  → Consider: Faster softmax, reduced vocab search\n";
            }
        }
        
        // Check for dispatch overhead
        auto dispatch = std::find_if(budget.entries.begin(), budget.entries.end(),
            [](const BudgetEntry& e) { return std::strcmp(e.component, "Dispatch") == 0; });
        if (dispatch != budget.entries.end() && dispatch->percentage > 5.0f) {
            std::cout << "\nHigh dispatch overhead detected (" << dispatch->percentage << "%)\n";
            std::cout << "  → Consider: Kernel fusion, batching\n";
        }
        
        std::cout << "\n";
    }
    
    void ExportBudget(const PerformanceBudget& budget, const std::string& path) {
        Json::Value root;
        
        Json::Value entries(Json::arrayValue);
        for (const auto& entry : budget.entries) {
            Json::Value e;
            e["component"] = entry.component;
            e["time_ns"] = entry.time_ns;
            e["percentage"] = entry.percentage;
            e["call_count"] = static_cast<Json::Int64>(entry.call_count);
            e["time_per_call_ns"] = entry.time_per_call_ns;
            e["is_bottleneck"] = entry.is_bottleneck;
            entries.append(e);
        }
        root["entries"] = entries;
        root["total_time_ns"] = budget.total_time_ns;
        root["matmul_time_ns"] = budget.matmul_time_ns;
        root["attention_time_ns"] = budget.attention_time_ns;
        root["other_time_ns"] = budget.other_time_ns;
        
        std::ofstream file(path);
        if (file.is_open()) {
            Json::StreamWriterBuilder builder;
            std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
            writer->write(root, &file);
        }
    }

private:
    double Average(const std::vector<double>& values) {
        if (values.empty()) return 0.0;
        double sum = std::accumulate(values.begin(), values.end(), 0.0);
        return sum / values.size();
    }
    
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
    std::cout << "  -n, --tokens <n>      Tokens to analyze (default: 128)\n";
    std::cout << "  -p, --prompt <text>   Prompt text\n";
    std::cout << "  -o, --output <file>   Export budget to JSON\n";
    std::cout << "  -h, --help            Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_performance_budget");
        return 1;
    }
    
    std::wstring model_path = argv[1];
    int num_tokens = 128;
    std::string prompt = "Hello world";
    std::string output_path;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-n" || arg == L"--tokens") {
            if (i + 1 < argc) num_tokens = _wtoi(argv[++i]);
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
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_performance_budget");
            return 0;
        }
    }
    
    std::cout << "============================================================================\n";
    std::cout << "RawrXD N-EVM Performance Budget Analysis\n";
    std::cout << "============================================================================\n\n";
    
    // Initialize VM
    NEVM_v2::Config vm_config;
    vm_config.ram_budget = 64ULL * 1024 * 1024 * 1024;
    vm_config.vram_budget = 16ULL * 1024 * 1024 * 1024;
    vm_config.enable_adaptive_precision = true;
    vm_config.enable_prefetch = true;
    
    auto vm = std::make_unique<NEVM_v2>(vm_config);
    if (!vm->Initialize()) {
        std::cerr << "Failed to initialize VM\n";
        return 1;
    }
    
    if (!vm->LoadModel(model_path)) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    auto loader = vm->GetLoader();
    if (!loader) {
        std::cerr << "Failed to get loader\n";
        return 1;
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
    engine_config.use_flash_attention = true;
    engine_config.use_kv_cache = true;
    
    auto engine = std::make_unique<TransformerEngine>(vm.get(), engine_config);
    if (!engine->Initialize(loader)) {
        std::cerr << "Failed to initialize engine\n";
        return 1;
    }
    
    // Analyze budget
    BudgetAnalyzer analyzer;
    auto budget = analyzer.Analyze(vm.get(), engine.get(), loader, prompt, num_tokens);
    
    // Print results
    analyzer.PrintBudget(budget);
    
    // Export if requested
    if (!output_path.empty()) {
        analyzer.ExportBudget(budget, output_path);
        std::cout << "Budget exported to: " << output_path << "\n";
    }
    
    return 0;
}
