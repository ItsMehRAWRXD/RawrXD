// ============================================================================
// C6: Autoregressive Generator Implementation
// ============================================================================

#include "autoregressive_generator.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>
#include <cmath>

namespace RawrXD {
namespace Inference {

// ============================================================================
// F16 to F32 conversion (shared)
// ============================================================================
static inline float F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    float val = 1.0f + mant / 1024.0f;
    int32_t exp32 = exp - 15 + 127;
    uint32_t f32 = (sign << 31) | (exp32 << 23) | (mant << 13);
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

// ============================================================================
// Q4_0 Dequantization (shared)
// ============================================================================
static std::vector<float> DequantizeQ4_0(const uint8_t* data, size_t num_weights) {
    std::vector<float> result;
    result.reserve(num_weights);
    
    size_t blocks = num_weights / 32;
    for (size_t b = 0; b < blocks; b++) {
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(data + b * 18);
        float scale = F16ToF32(scale_f16);
        
        for (int i = 0; i < 16; i++) {
            uint8_t byte = data[b * 18 + 2 + i];
            int8_t nibble0 = (byte & 0x0F) - 8;
            int8_t nibble1 = ((byte >> 4) & 0x0F) - 8;
            result.push_back(nibble0 * scale);
            result.push_back(nibble1 * scale);
        }
    }
    return result;
}

// ============================================================================
// ASCIITokenizer Implementation
// ============================================================================
std::vector<int> ASCIITokenizer::Encode(const std::string& text) {
    std::vector<int> tokens;
    for (char c : text) {
        if (c == ' ') tokens.push_back(220);  // GPT-2 space token
        else if (c >= 33 && c <= 126) tokens.push_back(static_cast<unsigned char>(c));
        else if (c == '\n') tokens.push_back(201);  // Newline
    }
    return tokens;
}

std::string ASCIITokenizer::Decode(const std::vector<int>& tokens) {
    std::string text;
    for (int tok : tokens) {
        text += Decode(tok);
    }
    return text;
}

std::string ASCIITokenizer::Decode(int token) {
    if (token == 220) return " ";
    if (token == 201) return "\n";
    if (token >= 33 && token <= 126) return std::string(1, static_cast<char>(token));
    return "";  // Unknown token
}

// ============================================================================
// EmbeddingTable Implementation
// ============================================================================
bool EmbeddingTable::LoadFromGGUF(Runtime::StreamingGGUFLoader& loader,
                                  const std::string& tensor_name,
                                  uint32_t vocab_size,
                                  uint32_t hidden_size) {
    vocab_size_ = vocab_size;
    hidden_size_ = hidden_size;
    
    // Load token embeddings
    Runtime::TensorInfo embed_info;
    if (!loader.GetTensor("token_embd.weight", embed_info)) {
        std::cerr << "Failed to load token embeddings" << std::endl;
        return false;
    }
    
    embeddings_ = DequantizeQ4_0(loader.GetTensorData(embed_info), 
                                   embed_info.NumElements());
    
    // For tied weights, LM head is transpose of embeddings
    // For now, we'll use the same weights (simplified)
    lm_head_ = embeddings_;
    
    return true;
}

void EmbeddingTable::Lookup(int token_id, float* output) const {
    if (token_id < 0 || token_id >= static_cast<int>(vocab_size_)) {
        token_id = 0;  // Unknown token -> padding
    }
    
    const float* embed = embeddings_.data() + token_id * hidden_size_;
    std::memcpy(output, embed, hidden_size_ * sizeof(float));
}

void EmbeddingTable::ProjectToLogits(const float* hidden, float* logits) const {
    // logits[vocab] = hidden[hidden_size] @ lm_head[hidden_size, vocab]
    for (uint32_t v = 0; v < vocab_size_; v++) {
        float sum = 0.0f;
        for (uint32_t h = 0; h < hidden_size_; h++) {
            // Simplified: using embeddings as LM head (tied weights)
            sum += hidden[h] * embeddings_[v * hidden_size_ + h];
        }
        logits[v] = sum;
    }
}

// ============================================================================
// AutoregressiveGenerator Implementation
// ============================================================================
AutoregressiveGenerator::AutoregressiveGenerator(const TransformerConfig& config,
                                               const GenerationConfig& gen_config)
    : transformer_config_(config), gen_config_(gen_config) {
    
    // Initialize buffers
    hidden_buffer_.resize(config.hidden_size);
    output_buffer_.resize(config.hidden_size);
    logits_.resize(32000);  // Default vocab size
    
    // Initialize RNG
    if (gen_config.seed != 0) {
        rng_.seed(gen_config.seed);
    } else {
        rng_.seed(std::chrono::steady_clock::now().time_since_epoch().count());
    }
}

bool AutoregressiveGenerator::Initialize(Runtime::StreamingGGUFLoader& loader,
                                         std::unique_ptr<Tokenizer> tokenizer) {
    tokenizer_ = std::move(tokenizer);
    
    // Load embeddings
    embeddings_ = std::make_unique<EmbeddingTable>();
    if (!embeddings_->LoadFromGGUF(loader, "token_embd.weight", 32000, 
                                    transformer_config_.hidden_size)) {
        std::cerr << "Failed to load embeddings" << std::endl;
        return false;
    }
    
    // Resize logits to actual vocab size
    logits_.resize(embeddings_->VocabSize());
    
    // Load transformer layer weights
    if (!LoadLayerWeights(loader)) {
        std::cerr << "Failed to load layer weights" << std::endl;
        return false;
    }
    
    // Initialize KV caches for all layers
    kv_caches_.clear();
    for (uint32_t i = 0; i < transformer_config_.num_layers; i++) {
        KVCache cache;
        cache.k_cache.resize(4096 * transformer_config_.num_kv_heads * 
                            transformer_config_.head_dim);
        cache.v_cache.resize(4096 * transformer_config_.num_kv_heads * 
                            transformer_config_.head_dim);
        cache.cache_len = 0;
        kv_caches_.push_back(std::move(cache));
    }
    
    return true;
}

bool AutoregressiveGenerator::LoadLayerWeights(Runtime::StreamingGGUFLoader& loader) {
    layer_weights_.clear();
    
    for (uint32_t layer_idx = 0; layer_idx < transformer_config_.num_layers; 
         layer_idx++) {
        std::string prefix = "blk." + std::to_string(layer_idx) + ".";
        
        Runtime::TensorInfo q_t, k_t, v_t, o_t, an_t, fg_t, fu_t, fd_t, fn_t;
        
        if (!loader.GetTensor(prefix + "attn_q.weight", q_t) ||
            !loader.GetTensor(prefix + "attn_k.weight", k_t) ||
            !loader.GetTensor(prefix + "attn_v.weight", v_t) ||
            !loader.GetTensor(prefix + "attn_output.weight", o_t) ||
            !loader.GetTensor(prefix + "attn_norm.weight", an_t) ||
            !loader.GetTensor(prefix + "ffn_gate.weight", fg_t) ||
            !loader.GetTensor(prefix + "ffn_up.weight", fu_t) ||
            !loader.GetTensor(prefix + "ffn_down.weight", fd_t) ||
            !loader.GetTensor(prefix + "ffn_norm.weight", fn_t)) {
            std::cerr << "Failed to load layer " << layer_idx << std::endl;
            return false;
        }
        
        LayerWeights lw;
        lw.q_weight = DequantizeQ4_0(loader.GetTensorData(q_t), q_t.NumElements());
        lw.k_weight = DequantizeQ4_0(loader.GetTensorData(k_t), k_t.NumElements());
        lw.v_weight = DequantizeQ4_0(loader.GetTensorData(v_t), v_t.NumElements());
        lw.o_weight = DequantizeQ4_0(loader.GetTensorData(o_t), o_t.NumElements());
        lw.attn_norm = DequantizeQ4_0(loader.GetTensorData(an_t), an_t.NumElements());
        lw.ffn_gate = DequantizeQ4_0(loader.GetTensorData(fg_t), fg_t.NumElements());
        lw.ffn_up = DequantizeQ4_0(loader.GetTensorData(fu_t), fu_t.NumElements());
        lw.ffn_down = DequantizeQ4_0(loader.GetTensorData(fd_t), fd_t.NumElements());
        lw.ffn_norm = DequantizeQ4_0(loader.GetTensorData(fn_t), fn_t.NumElements());
        
        layer_weights_.push_back(std::move(lw));
    }
    
    // Create transformer layers
    layers_.clear();
    for (auto& lw : layer_weights_) {
        auto layer = std::make_unique<TransformerLayer>(transformer_config_);
        layer->LoadWeights(lw.q_weight.data(), lw.k_weight.data(), lw.v_weight.data(), lw.o_weight.data(),
                          lw.attn_norm.data(), lw.ffn_gate.data(), lw.ffn_up.data(),
                          lw.ffn_down.data(), lw.ffn_norm.data());
        layers_.push_back(std::move(layer));
    }
    
    return true;
}

bool AutoregressiveGenerator::ForwardPass(const float* input_embedding, 
                                          float* output_hidden,
                                          uint32_t position) {
    // Copy input to hidden buffer
    std::memcpy(hidden_buffer_.data(), input_embedding, 
               transformer_config_.hidden_size * sizeof(float));
    
    // Forward through all layers
    for (size_t i = 0; i < layers_.size(); i++) {
        bool success = layers_[i]->Forward(hidden_buffer_.data(), 
                                          output_buffer_.data(),
                                          kv_caches_[i], position);
        if (!success) {
            std::cerr << "Layer " << i << " forward failed" << std::endl;
            return false;
        }
        
        // Swap buffers for next layer
        std::swap(hidden_buffer_, output_buffer_);
    }
    
    // Final hidden state is in hidden_buffer_ (due to swap)
    std::memcpy(output_hidden, hidden_buffer_.data(), 
               transformer_config_.hidden_size * sizeof(float));
    
    return true;
}

int AutoregressiveGenerator::GenerateNextToken(const float* hidden, 
                                               const std::vector<int>& context) {
    // Project to logits
    embeddings_->ProjectToLogits(hidden, logits_.data());
    
    // Apply repetition penalty
    if (gen_config_.repetition_penalty != 1.0f) {
        for (int token_id : token_history_) {
            if (token_id >= 0 && token_id < static_cast<int>(logits_.size())) {
                if (logits_[token_id] > 0) {
                    logits_[token_id] /= gen_config_.repetition_penalty;
                } else {
                    logits_[token_id] *= gen_config_.repetition_penalty;
                }
            }
        }
    }
    
    // Sample next token using SEG token sampling
    SEG::SamplingConfig sampling_config;
    sampling_config.temperature = gen_config_.temperature;
    sampling_config.top_k = gen_config_.top_k;
    sampling_config.top_p = gen_config_.top_p;
    sampling_config.repetition_penalty = gen_config_.repetition_penalty;
    sampling_config.seed = rng_();
    
    SEG::SamplingContext sampler(sampling_config);
    return sampler.Sample(logits_.data(), logits_.size());
}

std::string AutoregressiveGenerator::Generate(const std::string& prompt) {
    return Generate(prompt, nullptr);
}

std::string AutoregressiveGenerator::Generate(const std::string& prompt, 
                                              TokenCallback callback) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Reset state
    Reset();
    
    // Tokenize prompt
    std::vector<int> tokens = tokenizer_->Encode(prompt);
    stats_.prompt_tokens = tokens.size();
    token_history_ = tokens;
    
    std::cout << "Prompt tokens: " << tokens.size() << std::endl;
    
    // Process prompt tokens (prefill)
    for (size_t i = 0; i < tokens.size(); i++) {
        float embedding[transformer_config_.hidden_size];
        embeddings_->Lookup(tokens[i], embedding);
        
        if (!ForwardPass(embedding, hidden_buffer_.data(), i)) {
            std::cerr << "Forward pass failed at position " << i << std::endl;
            return "";
        }
    }
    
    // Generate new tokens
    std::vector<int> generated_tokens;
    int next_token = -1;
    
    for (uint32_t i = 0; i < gen_config_.max_tokens; i++) {
        uint32_t position = tokens.size() + i;
        
        // Get embedding for next token (last generated or last prompt token)
        int input_token = (next_token >= 0) ? next_token : tokens.back();
        float embedding[transformer_config_.hidden_size];
        embeddings_->Lookup(input_token, embedding);
        
        // Forward pass
        if (!ForwardPass(embedding, hidden_buffer_.data(), position)) {
            std::cerr << "Forward pass failed at generation step " << i << std::endl;
            break;
        }
        
        // Sample next token
        std::vector<int> context(tokens.begin(), tokens.end());
        context.insert(context.end(), generated_tokens.begin(), generated_tokens.end());
        next_token = GenerateNextToken(hidden_buffer_.data(), context);
        
        // Check for EOS
        if (next_token == gen_config_.eos_token_id) {
            std::cout << "EOS token reached" << std::endl;
            break;
        }
        
        generated_tokens.push_back(next_token);
        token_history_.push_back(next_token);
        
        // Callback for streaming
        if (callback) {
            callback(tokenizer_->Decode(next_token), next_token);
        }
    }
    
    // Calculate stats
    auto end_time = std::chrono::high_resolution_clock::now();
    stats_.time_seconds = std::chrono::duration<float>(end_time - start_time).count();
    stats_.tokens_generated = generated_tokens.size();
    stats_.tokens_per_second = stats_.tokens_generated / stats_.time_seconds;
    
    // Decode and return
    return tokenizer_->Decode(generated_tokens);
}

void AutoregressiveGenerator::Reset() {
    // Reset KV caches
    for (auto& cache : kv_caches_) {
        cache.cache_len = 0;
    }
    
    // Clear history
    token_history_.clear();
    
    // Reset stats
    stats_ = GenerationStats{};
}

// ============================================================================
// Convenience Functions
// ============================================================================
std::string GenerateText(const std::string& model_path,
                         const std::string& prompt,
                         const GenerationConfig& config) {
    // Load model
    Runtime::StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        std::cerr << "Failed to load model: " << model_path << std::endl;
        return "";
    }
    
    // Create generator
    TransformerConfig tconfig;
    tconfig.hidden_size = 4096;
    tconfig.num_heads = 32;
    tconfig.num_kv_heads = 8;
    tconfig.head_dim = 128;
    tconfig.intermediate_size = 14336;
    tconfig.num_layers = 34;  // ministral3
    tconfig.rms_norm_eps = 1e-5f;
    
    AutoregressiveGenerator generator(tconfig, config);
    
    if (!generator.Initialize(loader, std::make_unique<ASCIITokenizer>())) {
        std::cerr << "Failed to initialize generator" << std::endl;
        return "";
    }
    
    // Generate
    return generator.Generate(prompt);
}

} // namespace Inference
} // namespace RawrXD
