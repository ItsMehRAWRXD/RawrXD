// ============================================================================
// Unified Inference Engine Implementation
// ============================================================================

#include "unified_inference.hpp"
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <math>

namespace RawrXD {
namespace Inference {

// ============================================================================
// BPETokenizer Implementation
// ============================================================================

BPETokenizer::BPETokenizer() = default;
BPETokenizer::~BPETokenizer() = default;

bool BPETokenizer::LoadVocab(const char* vocab_path) {
    std::ifstream file(vocab_path);
    if (!file) return false;
    
    std::string line;
    int32_t id = 0;
    while (std::getline(file, line)) {
        // Simple vocab format: one token per line
        vocab_.push_back(line);
        token_to_id_[line] = id++;
    }
    
    return !vocab_.empty();
}

bool BPETokenizer::LoadVocab(const wchar_t* vocab_path) {
    // Convert to UTF-8 path
    int len = WideCharToMultiByte(CP_UTF8, 0, vocab_path, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    
    std::vector<char> path(len);
    WideCharToMultiByte(CP_UTF8, 0, vocab_path, -1, path.data(), len, nullptr, nullptr);
    
    return LoadVocab(path.data());
}

std::vector<int32_t> BPETokenizer::Encode(const std::string& text) const {
    std::vector<int32_t> tokens;
    
    // Simple word-level tokenization (placeholder for full BPE)
    std::string word;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!word.empty()) {
                auto it = token_to_id_.find(word);
                if (it != token_to_id_.end()) {
                    tokens.push_back(it->second);
                } else {
                    // Byte fallback
                    for (char wc : word) {
                        tokens.push_back(static_cast<uint8_t>(wc) + 3);  // Offset for special tokens
                    }
                }
                word.clear();
            }
        } else {
            word += c;
        }
    }
    
    if (!word.empty()) {
        auto it = token_to_id_.find(word);
        if (it != token_to_id_.end()) {
            tokens.push_back(it->second);
        }
    }
    
    return tokens;
}

std::string BPETokenizer::Decode(const std::vector<int32_t>& tokens) const {
    std::string result;
    for (int32_t token : tokens) {
        if (token >= 0 && token < static_cast<int32_t>(vocab_.size())) {
            result += vocab_[token];
        }
    }
    return result;
}

std::string BPETokenizer::Decode(int32_t token) const {
    if (token >= 0 && token < static_cast<int32_t>(vocab_.size())) {
        return vocab_[token];
    }
    return "";
}

// ============================================================================
// Sampler Implementation
// ============================================================================

Sampler::Sampler(uint32_t seed) : seed_(seed), rng_state_(seed) {
    probs_buffer_.reserve(128000);
    sorted_indices_.reserve(128000);
}

uint32_t Sampler::RandomInt() {
    // xorshift64* RNG
    rng_state_ ^= rng_state_ >> 12;
    rng_state_ ^= rng_state_ << 25;
    rng_state_ ^= rng_state_ >> 27;
    return static_cast<uint32_t>(rng_state_ * 0x2545F4914F6CDD1DULL);
}

float Sampler::RandomFloat() {
    return static_cast<float>(RandomInt()) / static_cast<float>(UINT32_MAX);
}

int32_t Sampler::Sample(const float* logits, uint32_t vocab_size, const GenerationConfig& config) {
    if (config.temperature <= 0.0f) {
        return SampleGreedy(logits, vocab_size);
    }
    return SampleTopPTopK(logits, vocab_size, config.temperature, config.top_p, 
                          static_cast<int>(config.top_k));
}

int32_t Sampler::SampleGreedy(const float* logits, uint32_t vocab_size) {
    int32_t max_idx = 0;
    float max_val = logits[0];
    for (uint32_t i = 1; i < vocab_size; ++i) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = static_cast<int32_t>(i);
        }
    }
    return max_idx;
}

int32_t Sampler::SampleTopPTopK(const float* logits, uint32_t vocab_size,
                                float temperature, float top_p, int top_k) {
    // Apply temperature
    probs_buffer_.resize(vocab_size);
    for (uint32_t i = 0; i < vocab_size; ++i) {
        probs_buffer_[i] = logits[i] / temperature;
    }
    
    // Softmax
    float max_logit = *std::max_element(probs_buffer_.begin(), probs_buffer_.end());
    float sum = 0.0f;
    for (auto& p : probs_buffer_) {
        p = std::exp(p - max_logit);
        sum += p;
    }
    for (auto& p : probs_buffer_) {
        p /= sum;
    }
    
    // Top-k filtering
    sorted_indices_.clear();
    for (uint32_t i = 0; i < vocab_size; ++i) {
        sorted_indices_.push_back({probs_buffer_[i], i});
    }
    
    std::partial_sort(sorted_indices_.begin(),
                      sorted_indices_.begin() + std::min(top_k, static_cast<int>(vocab_size)),
                      sorted_indices_.end(),
                      std::greater<>());
    
    // Top-p (nucleus) filtering
    float cumsum = 0.0f;
    uint32_t cutoff = vocab_size;
    for (uint32_t i = 0; i < vocab_size && i < static_cast<uint32_t>(top_k); ++i) {
        cumsum += sorted_indices_[i].first;
        if (cumsum >= top_p) {
            cutoff = i + 1;
            break;
        }
    }
    
    // Renormalize
    sum = 0.0f;
    for (uint32_t i = 0; i < cutoff; ++i) {
        sum += sorted_indices_[i].first;
    }
    
    // Sample
    float r = RandomFloat() * sum;
    cumsum = 0.0f;
    for (uint32_t i = 0; i < cutoff; ++i) {
        cumsum += sorted_indices_[i].first;
        if (cumsum >= r) {
            return static_cast<int32_t>(sorted_indices_[i].second);
        }
    }
    
    return static_cast<int32_t>(sorted_indices_[0].second);
}

void Sampler::Reset() {
    rng_state_ = seed_;
}

// ============================================================================
// UnifiedInferenceEngine Implementation
// ============================================================================

UnifiedInferenceEngine::UnifiedInferenceEngine() = default;
UnifiedInferenceEngine::~UnifiedInferenceEngine() = default;

bool UnifiedInferenceEngine::Initialize(const char* model_path) {
    // Open and parse GGUF
    if (!loader_.Open(model_path)) {
        return false;
    }
    if (!loader_.ParseHeader()) {
        return false;
    }
    
    // Get architecture
    arch_ = loader_.GetArchitecture();
    
    // Load weights
    if (!weights_.LoadFrom(loader_, arch_)) {
        return false;
    }
    
    // Prepare transformer
    if (!PrepareTransformer()) {
        return false;
    }
    
    // Allocate buffers
    logits_buffer_.resize(arch_.vocab_size);
    
    return true;
}

bool UnifiedInferenceEngine::Initialize(const wchar_t* model_path) {
    // Convert to UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, model_path, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return false;
    
    std::vector<char> path(len);
    WideCharToMultiByte(CP_UTF8, 0, model_path, -1, path.data(), len, nullptr, nullptr);
    
    return Initialize(path.data());
}

bool UnifiedInferenceEngine::PrepareTransformer() {
    // Configure transformer
    tf_config_.num_layers = arch_.num_layers;
    tf_config_.num_heads = arch_.num_heads;
    tf_config_.head_dim = arch_.head_dim;
    tf_config_.hidden_size = arch_.hidden_size;
    tf_config_.intermediate_size = arch_.intermediate_size;
    tf_config_.vocab_size = arch_.vocab_size;
    tf_config_.max_seq_len = arch_.context_length;
    tf_config_.batch_size = 1;
    
    return transformer_.Initialize(tf_config_);
}

GenerationResult UnifiedInferenceEngine::Generate(const std::string& prompt,
                                                   const GenerationConfig& config) {
    GenerationResult result;
    
    if (!is_generating_) {
        return result;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Encode prompt
    current_tokens_ = tokenizer_.Encode(prompt);
    if (current_tokens_.empty()) {
        current_tokens_.push_back(tokenizer_.GetBOSToken());
    }
    
    // Add BOS if needed
    if (current_tokens_[0] != tokenizer_.GetBOSToken()) {
        current_tokens_.insert(current_tokens_.begin(), tokenizer_.GetBOSToken());
    }
    
    // Reset state
    transformer_.Reset();
    sampler_.Reset();
    should_stop_ = false;
    is_generating_ = true;
    
    // Process prompt
    auto prompt_start = std::chrono::high_resolution_clock::now();
    
    // Forward through transformer
    if (!transformer_.Forward(current_tokens_.data(), weights_.token_embeddings,
                               weights_.lm_head, nullptr, logits_buffer_.data(),
                               static_cast<uint32_t>(current_tokens_.size()))) {
        result.finish_reason = "error";
        is_generating_ = false;
        return result;
    }
    
    auto prompt_end = std::chrono::high_resolution_clock::now();
    float ttft_ms = std::chrono::duration<float, std::milli>(prompt_end - prompt_start).count();
    
    // Generate tokens
    auto gen_start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < config.max_tokens && !should_stop_; ++i) {
        // Sample next token
        int32_t next_token = sampler_.Sample(logits_buffer_.data(), arch_.vocab_size, config);
        
        // Check for EOS
        if (next_token == tokenizer_.GetEOSToken()) {
            result.finish_reason = "stop";
            break;
        }
        
        // Add token
        current_tokens_.push_back(next_token);
        result.tokens_generated++;
        
        // Decode and append
        std::string token_str = tokenizer_.Decode(next_token);
        result.text += token_str;
        
        // Forward single token
        if (!transformer_.Forward(&current_tokens_.back(), weights_.token_embeddings,
                                   weights_.lm_head, nullptr, logits_buffer_.data(), 1)) {
            result.finish_reason = "error";
            break;
        }
    }
    
    auto gen_end = std::chrono::high_resolution_clock::now();
    float gen_time_s = std::chrono::duration<float>(gen_end - gen_start).count();
    
    if (result.finish_reason.empty()) {
        result.finish_reason = "length";
    }
    
    result.finished = true;
    result.tokens_per_second = result.tokens_generated / gen_time_s;
    
    // Update stats
    UpdatePerfStats(result.tokens_per_second, ttft_ms);
    
    is_generating_ = false;
    return result;
}

void UnifiedInferenceEngine::GenerateStream(const std::string& prompt,
                                             const GenerationConfig& config,
                                             TokenCallback callback) {
    if (!callback) return;
    
    // Encode prompt
    current_tokens_ = tokenizer_.Encode(prompt);
    if (current_tokens_.empty()) {
        current_tokens_.push_back(tokenizer_.GetBOSToken());
    }
    
    // Reset state
    transformer_.Reset();
    sampler_.Reset();
    should_stop_ = false;
    is_generating_ = true;
    
    // Process prompt
    if (!transformer_.Forward(current_tokens_.data(), weights_.token_embeddings,
                               weights_.lm_head, nullptr, logits_buffer_.data(),
                               static_cast<uint32_t>(current_tokens_.size()))) {
        callback("", 0, true);
        is_generating_ = false;
        return;
    }
    
    // Generate tokens
    for (uint32_t i = 0; i < config.max_tokens && !should_stop_; ++i) {
        int32_t next_token = sampler_.Sample(logits_buffer_.data(), arch_.vocab_size, config);
        
        if (next_token == tokenizer_.GetEOSToken()) {
            callback("", next_token, true);
            break;
        }
        
        current_tokens_.push_back(next_token);
        
        std::string token_str = tokenizer_.Decode(next_token);
        bool is_last = (i == config.max_tokens - 1) || should_stop_;
        callback(token_str, next_token, is_last);
        
        if (!transformer_.Forward(&current_tokens_.back(), weights_.token_embeddings,
                                   weights_.lm_head, nullptr, logits_buffer_.data(), 1)) {
            break;
        }
    }
    
    is_generating_ = false;
}

void UnifiedInferenceEngine::UpdatePerfStats(float tok_per_sec, float ttft_ms) {
    perf_stats_.total_tokens_generated += static_cast<uint64_t>(tok_per_sec * 10);  // Approximate
    perf_stats_.total_prompts++;
    
    // Running average
    float alpha = 0.1f;
    perf_stats_.avg_tok_per_sec = (1.0f - alpha) * perf_stats_.avg_tok_per_sec + alpha * tok_per_sec;
    perf_stats_.avg_ttft_ms = (1.0f - alpha) * perf_stats_.avg_ttft_ms + alpha * ttft_ms;
}

size_t UnifiedInferenceEngine::GetMemoryUsage() const {
    return weights_.GetMemoryUsage() + transformer_.GetMemoryUsage();
}

float UnifiedInferenceEngine::GetModelSizeGB() const {
    return static_cast<float>(weights_.GetMemoryUsage()) / (1024.0f * 1024.0f * 1024.0f);
}

void UnifiedInferenceEngine::ClearKVCache() {
    transformer_.Reset();
}

size_t UnifiedInferenceEngine::GetKVCacheUsage() const {
    // Approximate based on current sequence length
    return 0;  // Would need to track from transformer
}

void UnifiedInferenceEngine::ResetPerfStats() {
    perf_stats_ = {};
}

bool UnifiedInferenceEngine::IsGenerating() const {
    return is_generating_;
}

void UnifiedInferenceEngine::StopGeneration() {
    should_stop_ = true;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::string Complete(const std::string& prompt, const char* model_path,
                     const GenerationConfig& config) {
    UnifiedInferenceEngine engine;
    if (!engine.Initialize(model_path)) {
        return "Error: Failed to load model";
    }
    
    GenerationResult result = engine.Generate(prompt, config);
    return result.text;
}

void CompleteStream(const std::string& prompt, const char* model_path,
                    TokenCallback callback, const GenerationConfig& config) {
    UnifiedInferenceEngine engine;
    if (!engine.Initialize(model_path)) {
        callback("Error: Failed to load model", 0, true);
        return;
    }
    
    engine.GenerateStream(prompt, config, callback);
}

std::string FormatChat(const std::vector<Message>& messages, const std::string& format) {
    std::string result;
    
    if (format == "llama") {
        for (const auto& msg : messages) {
            if (msg.role == "system") {
                result += "<<SYS>>\n" + msg.content + "\n<</SYS>>\n\n";
            } else if (msg.role == "user") {
                result += "[INST] " + msg.content + " [/INST]\n";
            } else if (msg.role == "assistant") {
                result += msg.content + "\n";
            }
        }
    } else if (format == "chatml") {
        for (const auto& msg : messages) {
            result += "<|im_start|>" + msg.role + "\n" + msg.content + "<|im_end|>\n";
        }
        result += "<|im_start|>assistant\n";
    } else {
        // Simple format
        for (const auto& msg : messages) {
            result += msg.role + ": " + msg.content + "\n";
        }
        result += "assistant: ";
    }
    
    return result;
}

} // namespace Inference
} // namespace RawrXD
