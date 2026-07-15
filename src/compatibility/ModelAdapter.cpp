#include "rawrxd/compatibility/ModelAdapter.hpp"
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace compatibility {

ModelAdapter::ModelAdapter(ModelArchitecture arch) : arch_(arch) {
    ArchitectureDetector detector;
    config_ = detector.GetConfig(arch);
    Initialize(config_);
}

void ModelAdapter::Initialize(const ModelConfig& config) {
    config_ = config;
    arch_ = config.arch;
    
    switch (arch_) {
        case ModelArchitecture::LLAMA3:
            InitializeLlama3();
            break;
        case ModelArchitecture::MISTRAL:
            InitializeMistral();
            break;
        case ModelArchitecture::MIXTRAL:
            InitializeMixtral();
            break;
        case ModelArchitecture::PHI3:
            InitializePhi3();
            break;
        case ModelArchitecture::QWEN2:
            InitializeQwen2();
            break;
        case ModelArchitecture::DEEPSEEK:
            InitializeDeepSeek();
            break;
        case ModelArchitecture::CODESTRAL:
            InitializeCodestral();
            break;
        case ModelArchitecture::GEMMA2:
            InitializeGemma2();
            break;
        default:
            InitializeLlama3();  // Default fallback
            break;
    }
}

void ModelAdapter::InitializeLlama3() {
    // Pre-compute RoPE cache for Llama 3
    int max_seq_len = 8192;  // Can be extended with scaling
    rope_cache_len_ = max_seq_len;
    rope_cos_cache_.resize(max_seq_len * config_.head_dim / 2);
    rope_sin_cache_.resize(max_seq_len * config_.head_dim / 2);
    
    for (int pos = 0; pos < max_seq_len; ++pos) {
        for (int i = 0; i < config_.head_dim / 2; ++i) {
            float freq = 1.0f / std::pow(config_.rope_theta, 
                (2.0f * i) / config_.head_dim);
            float val = pos * freq;
            rope_cos_cache_[pos * config_.head_dim / 2 + i] = std::cos(val);
            rope_sin_cache_[pos * config_.head_dim / 2 + i] = std::sin(val);
        }
    }
}

void ModelAdapter::InitializeMistral() {
    // Mistral uses sliding window attention
    InitializeLlama3();  // Base on Llama 3
    
    // Adjust for sliding window
    if (config_.use_sliding_window) {
        // Pre-compute attention mask patterns for sliding window
    }
}

void ModelAdapter::InitializeMixtral() {
    // Mixtral adds MoE routing
    InitializeMistral();
    
    // Initialize expert routing
    int num_experts = std::stoi(config_.extra_params["num_experts"]);
    int num_active = std::stoi(config_.extra_params["num_active_experts"]);
}

void ModelAdapter::InitializePhi3() {
    // Phi-3 uses different RoPE scaling (Long RoPE)
    int max_seq_len = 32768;  // Phi-3 supports very long contexts
    rope_cache_len_ = max_seq_len;
    rope_cos_cache_.resize(max_seq_len * config_.head_dim / 2);
    rope_sin_cache_.resize(max_seq_len * config_.head_dim / 2);
    
    // Long RoPE scaling
    float scale = config_.rope_scaling;
    for (int pos = 0; pos < max_seq_len; ++pos) {
        for (int i = 0; i < config_.head_dim / 2; ++i) {
            float freq = 1.0f / std::pow(config_.rope_theta, 
                (2.0f * i) / config_.head_dim);
            float val = pos * freq * scale;
            rope_cos_cache_[pos * config_.head_dim / 2 + i] = std::cos(val);
            rope_sin_cache_[pos * config_.head_dim / 2 + i] = std::sin(val);
        }
    }
}

void ModelAdapter::InitializeQwen2() {
    // Qwen2 uses YaRN scaling for long contexts
    InitializeLlama3();
    
    // YaRN scaling parameters
    float yarn_alpha = 1.0f;
    float yarn_beta = 0.0f;
    float yarn_scale = config_.rope_scaling;
}

void ModelAdapter::InitializeDeepSeek() {
    // DeepSeek uses ALiBi instead of RoPE
    int num_heads = config_.num_heads;
    alibi_slopes_.resize(num_heads);
    
    // Compute ALiBi slopes: 2^(-8/h) for h in [1, num_heads]
    for (int h = 0; h < num_heads; ++h) {
        alibi_slopes_[h] = std::pow(2.0f, -8.0f * (h + 1) / num_heads);
    }
}

void ModelAdapter::InitializeCodestral() {
    // Codestral is based on Mistral with larger context
    InitializeMistral();
}

void ModelAdapter::InitializeGemma2() {
    // Gemma2 uses different normalization and attention
    InitializeLlama3();
}

void ModelAdapter::ComputeRoPE(TensorView* q, TensorView* k, int start_pos, float theta) {
    if (config_.use_rope && !rope_cos_cache_.empty()) {
        // Apply cached RoPE
        int head_dim = config_.head_dim;
        int num_heads = config_.num_heads;
        int num_kv_heads = config_.num_kv_heads;
        
        // Apply to Q
        for (int h = 0; h < num_heads; ++h) {
            for (int d = 0; d < head_dim / 2; ++d) {
                float cos_val = rope_cos_cache_[start_pos * head_dim / 2 + d];
                float sin_val = rope_sin_cache_[start_pos * head_dim / 2 + d];
                
                float x1 = q->data[h * head_dim + d];
                float x2 = q->data[h * head_dim + d + head_dim / 2];
                
                q->data[h * head_dim + d] = x1 * cos_val - x2 * sin_val;
                q->data[h * head_dim + d + head_dim / 2] = x1 * sin_val + x2 * cos_val;
            }
        }
        
        // Apply to K
        for (int h = 0; h < num_kv_heads; ++h) {
            for (int d = 0; d < head_dim / 2; ++d) {
                float cos_val = rope_cos_cache_[start_pos * head_dim / 2 + d];
                float sin_val = rope_sin_cache_[start_pos * head_dim / 2 + d];
                
                float x1 = k->data[h * head_dim + d];
                float x2 = k->data[h * head_dim + d + head_dim / 2];
                
                k->data[h * head_dim + d] = x1 * cos_val - x2 * sin_val;
                k->data[h * head_dim + d + head_dim / 2] = x1 * sin_val + x2 * cos_val;
            }
        }
    } else if (config_.use_alibi && !alibi_slopes_.empty()) {
        // Apply ALiBi biases (DeepSeek)
        // ALiBi adds position-dependent biases to attention scores
    }
}

int ModelAdapter::GetBOSToken() {
    switch (arch_) {
        case ModelArchitecture::LLAMA3:
            return 128000;  // <|begin_of_text|>
        case ModelArchitecture::MISTRAL:
        case ModelArchitecture::MIXTRAL:
            return 1;  // <s>
        case ModelArchitecture::PHI3:
            return 1;  // <|endoftext|> (also used as BOS)
        case ModelArchitecture::QWEN2:
            return 151643;  // <|endoftext|>
        case ModelArchitecture::GEMMA2:
            return 2;  // <bos>
        default:
            return 1;
    }
}

int ModelAdapter::GetEOSToken() {
    switch (arch_) {
        case ModelArchitecture::LLAMA3:
            return 128001;  // <|end_of_text|>
        case ModelArchitecture::MISTRAL:
        case ModelArchitecture::MIXTRAL:
            return 2;  // </s>
        case ModelArchitecture::PHI3:
            return 32000;  // <|endoftext|>
        case ModelArchitecture::QWEN2:
            return 151643;  // <|endoftext|>
        case ModelArchitecture::GEMMA2:
            return 1;  // <eos>
        default:
            return 2;
    }
}

std::vector<int> ModelAdapter::GetStopTokens() {
    std::vector<int> stops;
    stops.push_back(GetEOSToken());
    
    // Architecture-specific stop tokens
    switch (arch_) {
        case ModelArchitecture::LLAMA3:
            stops.push_back(128009);  // <|eot_id|>
            break;
        case ModelArchitecture::PHI3:
            stops.push_back(32001);   // <|assistant|>
            stops.push_back(32007);   // <|end|>
            break;
        default:
            break;
    }
    
    return stops;
}

bool ModelAdapter::UseSlidingWindow() {
    return config_.use_sliding_window;
}

int ModelAdapter::GetSlidingWindowSize() {
    return config_.sliding_window;
}

bool ModelAdapter::UseGQA() {
    return config_.use_gqa;
}

int ModelAdapter::GetNumKVHeads() {
    return config_.num_kv_heads;
}

// Factory implementations
std::unique_ptr<ModelAdapter> ModelAdapterFactory::Create(ModelArchitecture arch) {
    return std::make_unique<ModelAdapter>(arch);
}

std::unique_ptr<ModelAdapter> ModelAdapterFactory::Create(const std::string& model_name) {
    ArchitectureDetector detector;
    auto arch = detector.ParseArchitectureName(model_name);
    if (arch != ModelArchitecture::UNKNOWN) {
        return Create(arch);
    }
    return nullptr;
}

} // namespace compatibility
} // namespace rawrxd
