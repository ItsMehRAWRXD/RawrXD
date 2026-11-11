//============================================================================
// nevm_logit_validation.cpp
// RawrXD N-EVM - Logit Validation Against Reference (llama.cpp)
// Compares numerical output for correctness verification
//============================================================================

#include "nevm_v2.hpp"
#include "nevm_transformer_engine.hpp"
#include "nevm_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>

using namespace RawrXD::NEVM;

//============================================================================
// Logit Comparison Metrics
//============================================================================

struct LogitMetrics {
    float max_abs_error;
    float mean_abs_error;
    float rmse;
    float cosine_similarity;
    float kl_divergence;
    float relative_error_percent;
    bool passed;
};

struct ValidationConfig {
    std::wstring model_path;
    std::string reference_logits_path;  // Path to llama.cpp output
    std::string prompt;
    int num_tokens;
    float tolerance_max_abs_error;
    float tolerance_mean_abs_error;
    float tolerance_cosine_similarity;
    bool generate_reference;  // If true, export logits instead of comparing
    std::string output_path;
};

//============================================================================
// Metric Calculations
//============================================================================

float CalculateMaxAbsError(const float* a, const float* b, size_t n) {
    float max_error = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        max_error = std::max(max_error, std::abs(a[i] - b[i]));
    }
    return max_error;
}

float CalculateMeanAbsError(const float* a, const float* b, size_t n) {
    double sum = 0.0;
    for (size_t i = 0; i < n; ++i) {
        sum += std::abs(a[i] - b[i]);
    }
    return static_cast<float>(sum / n);
}

float CalculateRMSE(const float* a, const float* b, size_t n) {
    double sum_sq = 0.0;
    for (size_t i = 0; i < n; ++i) {
        float diff = a[i] - b[i];
        sum_sq += diff * diff;
    }
    return static_cast<float>(std::sqrt(sum_sq / n));
}

float CalculateCosineSimilarity(const float* a, const float* b, size_t n) {
    double dot = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (size_t i = 0; i < n; ++i) {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    
    if (norm_a == 0.0 || norm_b == 0.0) return 0.0f;
    
    return static_cast<float>(dot / (std::sqrt(norm_a) * std::sqrt(norm_b)));
}

float CalculateKLDivergence(const float* p, const float* q, size_t n) {
    // Convert to probabilities using softmax
    std::vector<float> p_softmax(n);
    std::vector<float> q_softmax(n);
    
    // Softmax for p
    float max_p = *std::max_element(p, p + n);
    float sum_p = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        p_softmax[i] = std::exp(p[i] - max_p);
        sum_p += p_softmax[i];
    }
    for (size_t i = 0; i < n; ++i) {
        p_softmax[i] /= sum_p;
    }
    
    // Softmax for q
    float max_q = *std::max_element(q, q + n);
    float sum_q = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        q_softmax[i] = std::exp(q[i] - max_q);
        sum_q += q_softmax[i];
    }
    for (size_t i = 0; i < n; ++i) {
        q_softmax[i] /= sum_q;
    }
    
    // KL(P || Q) = sum(P * log(P/Q))
    double kl = 0.0;
    for (size_t i = 0; i < n; ++i) {
        if (p_softmax[i] > 1e-10f) {
            kl += p_softmax[i] * std::log(p_softmax[i] / q_softmax[i]);
        }
    }
    
    return static_cast<float>(kl);
}

float CalculateRelativeError(const float* a, const float* b, size_t n) {
    double sum_rel = 0.0;
    size_t count = 0;
    
    for (size_t i = 0; i < n; ++i) {
        float denom = std::max(std::abs(a[i]), std::abs(b[i]));
        if (denom > 1e-6f) {
            sum_rel += std::abs(a[i] - b[i]) / denom;
            count++;
        }
    }
    
    return count > 0 ? static_cast<float>(sum_rel / count * 100.0) : 0.0f;
}

//============================================================================
// Logit I/O
//============================================================================

bool ExportLogits(const std::string& path, const std::vector<float>& logits,
                  int num_tokens, int vocab_size) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Header: magic, num_tokens, vocab_size
    uint32_t magic = 0x4C4F4749;  // "LOGI"
    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    file.write(reinterpret_cast<const char*>(&num_tokens), sizeof(num_tokens));
    file.write(reinterpret_cast<const char*>(&vocab_size), sizeof(vocab_size));
    
    // Data
    file.write(reinterpret_cast<const char*>(logits.data()), 
               logits.size() * sizeof(float));
    
    return true;
}

bool LoadLogits(const std::string& path, std::vector<float>& logits,
                int& num_tokens, int& vocab_size) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    
    // Header
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != 0x4C4F4749) return false;
    
    file.read(reinterpret_cast<char*>(&num_tokens), sizeof(num_tokens));
    file.read(reinterpret_cast<char*>(&vocab_size), sizeof(vocab_size));
    
    // Data
    size_t total = num_tokens * vocab_size;
    logits.resize(total);
    file.read(reinterpret_cast<char*>(logits.data()), total * sizeof(float));
    
    return true;
}

//============================================================================
// Validation Runner
//============================================================================

class LogitValidator {
public:
    LogitValidator(const ValidationConfig& config) : config_(config) {}
    
    bool RunValidation() {
        std::cout << "============================================================================\n";
        std::cout << "RawrXD N-EVM Logit Validation\n";
        std::cout << "============================================================================\n\n";
        
        // Initialize NEVM
        if (!InitializeNEVM()) {
            std::cerr << "Failed to initialize NEVM\n";
            return false;
        }
        
        // Generate or compare
        if (config_.generate_reference) {
            return GenerateReferenceLogits();
        } else {
            return CompareWithReference();
        }
    }
    
private:
    bool InitializeNEVM() {
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
        
        // Create transformer engine
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
        
        engine_ = std::make_unique<TransformerEngine>(vm_.get(), engine_config);
        if (!engine_->Initialize(loader_)) return false;
        
        vocab_size_ = metadata.vocab_size;
        return true;
    }
    
    bool GenerateReferenceLogits() {
        std::cout << "Generating reference logits...\n";
        
        // Tokenize prompt
        std::vector<int32_t> tokens = Tokenize(config_.prompt);
        std::cout << "Prompt tokens: " << tokens.size() << "\n";
        
        // Allocate output buffer
        std::vector<float> logits(config_.num_tokens * vocab_size_);
        
        // Run inference
        std::vector<float> output_logits(vocab_size_);
        
        for (int i = 0; i < config_.num_tokens; ++i) {
            // Forward pass
            engine_->Forward(tokens.data(), output_logits.data(), 
                             static_cast<uint32_t>(tokens.size()));
            
            // Store logits
            std::copy(output_logits.begin(), output_logits.end(),
                     logits.begin() + i * vocab_size_);
            
            // Sample next token (greedy for consistency)
            int next_token = static_cast<int>(
                std::max_element(output_logits.begin(), output_logits.end()) - 
                output_logits.begin());
            tokens.push_back(next_token);
            
            if ((i + 1) % 10 == 0) {
                std::cout << "  Generated " << (i + 1) << "/" << config_.num_tokens << " tokens\n";
            }
        }
        
        // Export
        if (ExportLogits(config_.output_path, logits, config_.num_tokens, vocab_size_)) {
            std::cout << "Reference logits exported to: " << config_.output_path << "\n";
            return true;
        }
        
        return false;
    }
    
    bool CompareWithReference() {
        std::cout << "Loading reference logits from: " << config_.reference_logits_path << "\n";
        
        // Load reference
        std::vector<float> reference_logits;
        int ref_tokens, ref_vocab;
        if (!LoadLogits(config_.reference_logits_path, reference_logits, ref_tokens, ref_vocab)) {
            std::cerr << "Failed to load reference logits\n";
            return false;
        }
        
        std::cout << "Reference: " << ref_tokens << " tokens, vocab=" << ref_vocab << "\n\n";
        
        // Generate NEVM logits
        std::cout << "Generating NEVM logits...\n";
        std::vector<float> nevm_logits;
        if (!GenerateNEVMLogits(nevm_logits, ref_tokens)) {
            std::cerr << "Failed to generate NEVM logits\n";
            return false;
        }
        
        // Compare
        std::cout << "\nComparing logits...\n";
        std::cout << "============================================================================\n";
        
        bool all_passed = true;
        
        for (int i = 0; i < ref_tokens; ++i) {
            const float* ref = reference_logits.data() + i * ref_vocab;
            const float* nevm = nevm_logits.data() + i * ref_vocab;
            
            LogitMetrics metrics;
            metrics.max_abs_error = CalculateMaxAbsError(ref, nevm, ref_vocab);
            metrics.mean_abs_error = CalculateMeanAbsError(ref, nevm, ref_vocab);
            metrics.rmse = CalculateRMSE(ref, nevm, ref_vocab);
            metrics.cosine_similarity = CalculateCosineSimilarity(ref, nevm, ref_vocab);
            metrics.kl_divergence = CalculateKLDivergence(ref, nevm, ref_vocab);
            metrics.relative_error_percent = CalculateRelativeError(ref, nevm, ref_vocab);
            
            metrics.passed = (metrics.max_abs_error <= config_.tolerance_max_abs_error &&
                             metrics.mean_abs_error <= config_.tolerance_mean_abs_error &&
                             metrics.cosine_similarity >= config_.tolerance_cosine_similarity);
            
            PrintTokenMetrics(i, metrics);
            
            if (!metrics.passed) {
                all_passed = false;
                std::cout << "  [FAIL] Token " << i << " exceeded tolerance\n";
            }
        }
        
        std::cout << "============================================================================\n";
        std::cout << (all_passed ? "All tokens passed validation!\n" : "Some tokens failed validation.\n");
        
        return all_passed;
    }
    
    bool GenerateNEVMLogits(std::vector<float>& logits, int num_tokens) {
        std::vector<int32_t> tokens = Tokenize(config_.prompt);
        logits.resize(num_tokens * vocab_size_);
        
        std::vector<float> output_logits(vocab_size_);
        
        for (int i = 0; i < num_tokens; ++i) {
            engine_->Forward(tokens.data(), output_logits.data(),
                             static_cast<uint32_t>(tokens.size()));
            
            std::copy(output_logits.begin(), output_logits.end(),
                     logits.begin() + i * vocab_size_);
            
            int next_token = static_cast<int>(
                std::max_element(output_logits.begin(), output_logits.end()) - 
                output_logits.begin());
            tokens.push_back(next_token);
        }
        
        return true;
    }
    
    void PrintTokenMetrics(int token_idx, const LogitMetrics& m) {
        std::cout << "Token " << std::setw(3) << token_idx << ": ";
        std::cout << "max_err=" << std::scientific << std::setprecision(3) << m.max_abs_error;
        std::cout << ", mean_err=" << m.mean_abs_error;
        std::cout << ", rmse=" << m.rmse;
        std::cout << ", cos=" << std::fixed << std::setprecision(6) << m.cosine_similarity;
        std::cout << ", kl=" << std::scientific << m.kl_divergence;
        std::cout << ", rel=" << std::fixed << m.relative_error_percent << "%";
        std::cout << (m.passed ? " [OK]" : " [FAIL]") << "\n";
    }
    
    std::vector<int32_t> Tokenize(const std::string& text) {
        // Simplified tokenization
        std::vector<int32_t> tokens;
        for (char c : text) {
            tokens.push_back(static_cast<int32_t>(c));
        }
        return tokens;
    }
    
    ValidationConfig config_;
    std::unique_ptr<NEVM_v2> vm_;
    std::unique_ptr<TransformerEngine> engine_;
    GGUF_PassthroughLoader* loader_;
    int vocab_size_;
};

//============================================================================
// Main
//============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -r, --reference <file>    Compare against reference logits\n";
    std::cout << "  -g, --generate          Generate reference logits\n";
    std::cout << "  -o, --output <file>     Output file for generated logits\n";
    std::cout << "  -n, --tokens <n>        Number of tokens (default: 10)\n";
    std::cout << "  -p, --prompt <text>     Prompt text\n";
    std::cout << "  --max-error <f>        Max abs error tolerance (default: 0.01)\n";
    std::cout << "  --mean-error <f>       Mean abs error tolerance (default: 0.001)\n";
    std::cout << "  --cosine <f>           Cosine similarity tolerance (default: 0.999)\n";
    std::cout << "  -h, --help              Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage("nevm_logit_validation");
        return 1;
    }
    
    ValidationConfig config;
    config.model_path = argv[1];
    config.prompt = "Hello world";
    config.num_tokens = 10;
    config.tolerance_max_abs_error = 0.01f;
    config.tolerance_mean_abs_error = 0.001f;
    config.tolerance_cosine_similarity = 0.999f;
    config.generate_reference = false;
    config.output_path = "nevm_logits.bin";
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-r" || arg == L"--reference") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.reference_logits_path.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.reference_logits_path[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-g" || arg == L"--generate") {
            config.generate_reference = true;
        } else if (arg == L"-o" || arg == L"--output") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.output_path.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.output_path[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"-n" || arg == L"--tokens") {
            if (i + 1 < argc) config.num_tokens = _wtoi(argv[++i]);
        } else if (arg == L"-p" || arg == L"--prompt") {
            if (i + 1 < argc) {
                size_t len = wcslen(argv[i + 1]);
                config.prompt.resize(len);
                for (size_t j = 0; j < len; ++j) {
                    config.prompt[j] = static_cast<char>(argv[i + 1][j]);
                }
                ++i;
            }
        } else if (arg == L"--max-error") {
            if (i + 1 < argc) config.tolerance_max_abs_error = static_cast<float>(_wtof(argv[++i]));
        } else if (arg == L"--mean-error") {
            if (i + 1 < argc) config.tolerance_mean_abs_error = static_cast<float>(_wtof(argv[++i]));
        } else if (arg == L"--cosine") {
            if (i + 1 < argc) config.tolerance_cosine_similarity = static_cast<float>(_wtof(argv[++i]));
        } else if (arg == L"-h" || arg == L"--help") {
            PrintUsage("nevm_logit_validation");
            return 0;
        }
    }
    
    LogitValidator validator(config);
    return validator.RunValidation() ? 0 : 1;
}
