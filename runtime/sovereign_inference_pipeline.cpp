// ============================================================================
// sovereign_inference_pipeline.cpp - End-to-End Sovereign Inference
// ============================================================================

#include "sovereign_inference_pipeline.hpp"
#include "telemetry_ids.hpp"
#include <algorithm>
#include <cmath>
#include <random>
#include <iostream>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Constructor / Destructor
// ============================================================================
SovereignInferencePipeline::SovereignInferencePipeline() = default;
SovereignInferencePipeline::~SovereignInferencePipeline() = default;

// ============================================================================
// Initialize Pipeline
// ============================================================================
bool SovereignInferencePipeline::Initialize(
    const std::string& tokenizer_path,
    const std::string& model_path
) {
    // Initialize telemetry
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x01);
    
    // Load tokenizer
    m_tokenizer = std::make_unique<SovereignTokenizer>();
    if (!m_tokenizer->Load(tokenizer_path)) {
        Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x02);
        return false;
    }
    
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x03);
    
    // Load model
    m_loader = std::make_unique<StreamingGGUFLoader>();
    if (!m_loader->Open(model_path)) {
        Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x04);
        return false;
    }
    
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x05);
    
    // Initialize backend
    m_backend = std::make_unique<StreamingMultiLayerBackend>();
    if (!m_backend->Initialize(*m_loader)) {
        Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x06);
        return false;
    }
    
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x07);
    
    m_initialized = true;
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x08);
    
    return true;
}

// ============================================================================
// Generate Text from Prompt
// ============================================================================
std::string SovereignInferencePipeline::Generate(
    const std::string& prompt,
    const GenerationConfig& config
) {
    if (!m_initialized) {
        return "";
    }
    
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x10);
    
    // Encode prompt
    std::vector<uint32_t> prompt_tokens = m_tokenizer->Encode(prompt, config.add_bos, false);
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x11 + static_cast<uint32_t>(prompt_tokens.size()));
    
    // Generate tokens
    std::vector<uint32_t> output_tokens;
    if (!m_backend->Generate(prompt_tokens, output_tokens, config.max_new_tokens, 
                               config.temperature, config.top_k)) {
        Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x13);
        return "";
    }
    
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x14 + static_cast<uint32_t>(output_tokens.size()));
    
    // Decode output
    std::string output = m_tokenizer->Decode(output_tokens);
    
    Telemetry::Telemetry_Log(Telemetry::TELEMETRY_GGUF_INIT_START, 0x15);
    
    return output;
}

// ============================================================================
// Generate with Streaming Output
// ============================================================================
void SovereignInferencePipeline::GenerateStreaming(
    const std::string& prompt,
    const GenerationConfig& config,
    std::string& output_accumulator
) {
    if (!m_initialized) {
        return;
    }
    
    // Encode prompt
    std::vector<uint32_t> prompt_tokens = m_tokenizer->Encode(prompt, config.add_bos, false);
    
    // Feed prompt through model
    std::vector<float> logits(m_backend->GetVocabSize());
    for (size_t i = 0; i < prompt_tokens.size(); ++i) {
        m_backend->ExecuteToken(prompt_tokens[i], static_cast<uint32_t>(i), logits.data());
    }
    
    // Generate new tokens
    uint32_t position = static_cast<uint32_t>(prompt_tokens.size());
    std::vector<uint32_t> generated_tokens;
    
    for (size_t i = 0; i < config.max_new_tokens; ++i) {
        // Sample next token
        uint32_t next_token = SampleToken(logits.data(), config);
        
        // Check for EOS
        if (next_token == m_tokenizer->GetEosTokenId()) {
            break;
        }
        
        generated_tokens.push_back(next_token);
        
        // Decode and stream
        std::string token_text = m_tokenizer->Decode(std::vector<uint32_t>{next_token});
        output_accumulator += token_text;
        
        // Callback
        if (config.on_token) {
            config.on_token(next_token, token_text, config.user_data);
        }
        
        // Check stop strings
        for (const auto& stop_str : config.stop_strings) {
            if (output_accumulator.find(stop_str) != std::string::npos) {
                return;
            }
        }
        
        // Execute next token
        m_backend->ExecuteToken(next_token, position++, logits.data());
    }
}

// ============================================================================
// Token Counting
// ============================================================================
size_t SovereignInferencePipeline::CountTokens(const std::string& text) const {
    if (!m_tokenizer) return 0;
    return m_tokenizer->Encode(text).size();
}

// ============================================================================
// Get Model Info
// ============================================================================
size_t SovereignInferencePipeline::GetVocabSize() const {
    if (!m_tokenizer) return 0;
    return m_tokenizer->GetVocabSize();
}

std::string SovereignInferencePipeline::GetModelInfo() const {
    if (!m_backend || !m_initialized) {
        return "Not initialized";
    }
    
    return "Layers: " + std::to_string(m_backend->GetNumLayers()) +
           ", Hidden: " + std::to_string(m_backend->GetHiddenSize()) +
           ", Vocab: " + std::to_string(m_backend->GetVocabSize());
}

// ============================================================================
// Reset State
// ============================================================================
void SovereignInferencePipeline::Reset() {
    if (m_backend) {
        m_backend->Reset();
    }
    m_conversation_history.clear();
}

// ============================================================================
// Token Sampling
// ============================================================================
uint32_t SovereignInferencePipeline::SampleToken(const float* logits, 
                                                  const GenerationConfig& config) {
    if (config.temperature <= 0.0f) {
        return GreedySample(logits);
    }
    
    if (config.top_p < 1.0f && config.top_p > 0.0f) {
        return TopPSample(logits, config.top_p, config.temperature);
    }
    
    if (config.top_k > 0) {
        return TopKSample(logits, config.top_k, config.temperature);
    }
    
    return TopKSample(logits, static_cast<int>(GetVocabSize()), config.temperature);
}

uint32_t SovereignInferencePipeline::GreedySample(const float* logits) {
    uint32_t best_id = 0;
    float best_logit = logits[0];
    
    for (size_t i = 1; i < GetVocabSize(); ++i) {
        if (logits[i] > best_logit) {
            best_logit = logits[i];
            best_id = static_cast<uint32_t>(i);
        }
    }
    
    return best_id;
}

uint32_t SovereignInferencePipeline::TopKSample(const float* logits, int k, float temperature) {
    size_t vocab_size = GetVocabSize();
    
    // Create (id, logit) pairs
    std::vector<std::pair<uint32_t, float>> candidates;
    candidates.reserve(vocab_size);
    
    for (size_t i = 0; i < vocab_size; ++i) {
        candidates.push_back({static_cast<uint32_t>(i), logits[i]});
    }
    
    // Sort by logit descending
    std::partial_sort(candidates.begin(), 
                      candidates.begin() + std::min(static_cast<size_t>(k), candidates.size()),
                      candidates.end(),
                      [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Apply temperature and compute softmax
    float max_logit = candidates[0].second;
    float sum = 0.0f;
    
    for (int i = 0; i < k && i < static_cast<int>(candidates.size()); ++i) {
        candidates[i].second = std::exp((candidates[i].second - max_logit) / temperature);
        sum += candidates[i].second;
    }
    
    // Sample
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(gen) * sum;
    
    float cumsum = 0.0f;
    for (int i = 0; i < k && i < static_cast<int>(candidates.size()); ++i) {
        cumsum += candidates[i].second;
        if (r <= cumsum) {
            return candidates[i].first;
        }
    }
    
    return candidates[0].first;
}

uint32_t SovereignInferencePipeline::TopPSample(const float* logits, float p, float temperature) {
    size_t vocab_size = GetVocabSize();
    
    // Create (id, logit) pairs and sort
    std::vector<std::pair<uint32_t, float>> candidates;
    candidates.reserve(vocab_size);
    
    for (size_t i = 0; i < vocab_size; ++i) {
        candidates.push_back({static_cast<uint32_t>(i), logits[i]});
    }
    
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Apply temperature
    float max_logit = candidates[0].second;
    for (auto& c : candidates) {
        c.second = std::exp((c.second - max_logit) / temperature);
    }
    
    // Compute cumulative probabilities and find cutoff
    float cumsum = 0.0f;
    size_t cutoff = candidates.size();
    for (size_t i = 0; i < candidates.size(); ++i) {
        cumsum += candidates[i].second;
        if (cumsum >= p) {
            cutoff = i + 1;
            break;
        }
    }
    
    // Renormalize and sample
    float sum = cumsum;
    static thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(gen) * sum;
    
    cumsum = 0.0f;
    for (size_t i = 0; i < cutoff; ++i) {
        cumsum += candidates[i].second;
        if (r <= cumsum) {
            return candidates[i].first;
        }
    }
    
    return candidates[0].first;
}

// ============================================================================
// Convenience Functions
// ============================================================================
std::string SovereignGenerate(
    const std::string& tokenizer_path,
    const std::string& model_path,
    const std::string& prompt,
    const GenerationConfig& config
) {
    SovereignInferencePipeline pipeline;
    if (!pipeline.Initialize(tokenizer_path, model_path)) {
        return "";
    }
    return pipeline.Generate(prompt, config);
}

} // namespace Runtime
} // namespace RawrXD
