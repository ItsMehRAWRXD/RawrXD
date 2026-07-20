//============================================================================
// nevm_determinism_validation.cpp
// RawrXD N-EVM - Determinism Validation
// Verifies reproducible outputs across multiple runs
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <sstream>
#include <json/json.h>

using namespace RawrXD::NEVM;

//============================================================================
// Determinism Test Configuration
//============================================================================

struct DeterminismConfig {
    std::wstring model_path;
    std::string prompt;
    int num_tokens;
    int num_runs;
    uint32_t seed;
    bool use_fixed_seed;
    std::string output_path;
};

struct DeterminismResult {
    bool passed;
    int num_runs;
    int identical_runs;
    float agreement_rate;
    std::vector<std::vector<int32_t>> all_outputs;
    std::vector<float> run_latencies;
    std::string error_message;
};

//============================================================================
// Determinism Validator
//============================================================================

class DeterminismValidator {
public:
    DeterminismValidator(const DeterminismConfig& config) : config_(config) {}
    
    DeterminismResult Validate() {
        DeterminismResult result;
        result.num_runs = config_.num_runs;
        result.passed = false;
        
        std::cout << "============================================================================\n";
        std::cout << "RawrXD N-EVM Determinism Validation\n";
        std::cout << "============================================================================\n\n";
        
        std::cout << "Configuration:\n";
        std::cout << "  Runs: " << config_.num_runs << "\n";
        std::cout << "  Tokens per run: " << config_.num_tokens << "\n";
        std::cout << "  Fixed seed: " << (config_.use_fixed_seed ? "Yes" : "No") << "\n";
        if (config_.use_fixed_seed) {
            std::cout << "  Seed: " << config_.seed << "\n";
        }
        std::cout << "\n";
        
        // Run multiple times
        for (int run = 0; run < config_.num_runs; ++run) {
            std::cout << "Run " << (run + 1) << "/" << config_.num_runs << "...\n";
            
            auto output = RunInference(run);
            if (output.empty()) {
                result.error_message = "Inference failed on run " + std::to_string(run);
                return result;
            }
            
            result.all_outputs.push_back(output);
        }
        
        // Compare outputs
        std::cout << "\nComparing outputs...\n";
        result.identical_runs = CountIdenticalRuns(result.all_outputs);
        result.agreement_rate = static_cast<float>(result.identical_runs) / config_.num_runs;
        
        // Check token-level agreement
        auto token_agreement = CalculateTokenAgreement(result.all_outputs);
        
        // Print results
        PrintResults(result, token_agreement);
        
        // Pass if all runs agree
        result.passed = (result.identical_runs == config_.num_runs);
        
        return result;
    }
    
private:
    std::vector<int32_t> RunInference(int run_id) {
        std::vector<int32_t> output_tokens;
        
        // Configure VM with deterministic settings
        NEVM_v2::Config vm_config;
        vm_config.ram_budget = 64ULL * 1024 * 1024 * 1024;
        vm_config.vram_budget = 16ULL * 1024 * 1024 * 1024;
        vm_config.enable_adaptive_precision = false;  // Fixed precision for determinism
        vm_config.enable_prefetch = false;            // No prefetch (timing variation)
        vm_config.enable_tracing = false;
        
        auto vm = std::make_unique<NEVM_v2>(vm_config);
        if (!vm->Initialize()) return output_tokens;
        
        if (!vm->LoadModel(config_.model_path)) return output_tokens;
        
        auto loader = vm->GetLoader();
        if (!loader) return output_tokens;
        
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
        engine_config.use_flash_attention = false;  // Disable for determinism
        engine_config.use_kv_cache = true;
        
        auto engine = std::make_unique<TransformerEngine>(vm.get(), engine_config);
        if (!engine->Initialize(loader)) return output_tokens;
        
        // Tokenize
        std::vector<int32_t> tokens = Tokenize(config_.prompt);
        
        // Generate tokens
        std::vector<float> logits(metadata.vocab_size);
        
        // Prefill
        engine->Forward(tokens.data(), logits.data(), 
                       static_cast<uint32_t>(tokens.size()));
        
        // Generate
        for (int i = 0; i < config_.num_tokens; ++i) {
            int32_t next_token = 0;
            
            // Greedy sampling (deterministic)
            next_token = static_cast<int32_t>(
                std::max_element(logits.begin(), logits.end()) - logits.begin());
            
            output_tokens.push_back(next_token);
            tokens.push_back(next_token);
            
            // Forward
            engine->GenerateStep(&next_token, logits.data(), 
                                  static_cast<uint32_t>(tokens.size()));
        }
        
        return output_tokens;
    }
    
    int CountIdenticalRuns(const std::vector<std::vector<int32_t>>& outputs) {
        if (outputs.empty()) return 0;
        
        const auto& first = outputs[0];
        int identical = 1;
        
        for (size_t i = 1; i < outputs.size(); ++i) {
            if (outputs[i] == first) {
                identical++;
            }
        }
        
        return identical;
    }
    
    struct TokenAgreement {
        std::vector<float> agreement_per_position;
        float mean_agreement;
        float min_agreement;
        int first_divergence;
    };
    
    TokenAgreement CalculateTokenAgreement(const std::vector<std::vector<int32_t>>& outputs) {
        TokenAgreement result;
        
        if (outputs.empty() || outputs[0].empty()) return result;
        
        size_t num_tokens = outputs[0].size();
        result.agreement_per_position.resize(num_tokens);
        
        for (size_t pos = 0; pos < num_tokens; ++pos) {
            std::map<int32_t, int> token_counts;
            
            for (const auto& output : outputs) {
                if (pos < output.size()) {
                    token_counts[output[pos]]++;
                }
            }
            
            // Find most common token
            int max_count = 0;
            for (const auto& [token, count] : token_counts) {
                max_count = std::max(max_count, count);
            }
            
            result.agreement_per_position[pos] = 
                static_cast<float>(max_count) / outputs.size();
        }
        
        // Calculate statistics
        float sum = 0.0f;
        result.min_agreement = 1.0f;
        result.first_divergence = -1;
        
        for (size_t i = 0; i < result.agreement_per_position.size(); ++i) {
            float agr = result.agreement_per_position[i];
            sum += agr;
            result.min_agreement = std::min(result.min_agreement, agr);
            
            if (agr < 1.0f && result.first_divergence < 0) {
                result.first_divergence = static_cast<int>(i);
            }
        }
        
        result.mean_agreement = sum / result.agreement_per_position.size();
        
        return result;
    }
    
    void PrintResults(const DeterminismResult& result, const TokenAgreement& agr) {
        std::cout << "\n============================================================================\n";
        std::cout << "Determinism Results\n";
        std::cout << "============================================================================\n\n";
        
        std::cout << "Overall Agreement:\n";
        std::cout << "  Identical runs: " << result.identical_runs << "/" << result.num_runs << "\n";
        std::cout << "  Agreement rate: " << std::fixed << std::setprecision(2) << (result.agreement_rate * 100.0f) << "%\n";
        std::cout << "  Status: " << (result.passed ? "PASS" : "FAIL") << "\n\n";
        
        std::cout << "Token-Level Agreement:\n";
        std::cout << "  Mean: " << std::setprecision(4) << (agr.mean_agreement * 100.0f) << "%\n";
        std::cout << "  Min:  " << (agr.min_agreement * 100.0f) << "%\n";
        if (agr.first_divergence >= 0) {
            std::cout << "  First divergence: token " << agr.first_divergence << "\n";
        } else {
            std::cout << "  No divergence detected\n";
        }
        
        // Show per-token agreement for first 20 tokens
        if (!agr.agreement_per_position.empty()) {
            std::cout << "\nPer-token agreement (first 20):\n";
            for (size_t i = 0; i < std::min(size_t(20), agr.agreement_per_position.size()); ++i) {
                std::cout << "  Token " << std::setw(3) << i << ": " << std::setw(6) << std::setprecision(1) << (agr.agreement_per_position[i] * 100.0f) << "%";
                if (agr.agreement_per_position[i] < 1.0f) {
                    std::cout << " [DIVERGENCE]";
                }
                std::cout << "\n";
            }
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
    
    DeterminismConfig config_;
};

//============================================================================
// Main
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -n, --tokens <n>      Tokens per run (default: 32)\n";
    std::cout << "  -r, --runs <n>        Number of runs (default: 5)\n";
    std::cout << "  -s, --seed <n>        Fixed random seed\n";
    std::cout << "  -p, --prompt <text>   Prompt text\n";
    std::cout << "  -o, --output <file>   Export results to JSON\n";
    std::cout << "  -h, --help            Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_determinism_validation");
        return 1;
    }
    
    DeterminismConfig config;
    config.model_path = argv[1];
    config.prompt = "Hello world";
    config.num_tokens = 32;
    config.num_runs = 5;
    config.seed = 42;
    config.use_fixed_seed = false;
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-n" || arg == L"--tokens") {
            if (i + 1 < argc) config.num_tokens = _wtoi(argv[++i]);
        } else if (arg == L"-r" || arg == L"--runs") {
            if (i + 1 < argc) config.num_runs = _wtoi(argv[++i]);
        } else if (arg == L"-s" || arg == L"--seed") {
            if (i + 1 < argc) {
                config.seed = static_cast<uint32_t>(_wtoi(argv[++i]));
                config.use_fixed_seed = true;
            }
        } else if (arg == L"-p" || arg == L"--prompt") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.prompt.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.prompt[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_determinism_validation");
            return 0;
        }
    }
    
    DeterminismValidator validator(config);
    auto result = validator.Validate();
    
    return result.passed ? 0 : 1;
}
