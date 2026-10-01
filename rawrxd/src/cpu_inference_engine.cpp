#include "cpu_inference_engine.h"
#include "rawrxd_transformer.hpp"
#include "rawrxd_tokenizer.hpp"
#include "rawrxd_sampler.hpp"
#include "gguf_loader.hpp"

#include <mutex>
#include <sstream>
#include <chrono>
#include <iomanip>

namespace RawrXD {

class CPUInferenceEngine::Impl {
public:
    rawrxd::TransformerRuntime transformer_;
    rawrxd::Tokenizer tokenizer_;
    rawrxd::Sampler sampler_;
    mutable std::mutex mutex_;
    bool model_loaded_ = false;
    std::string last_error_;
    int total_tokens_generated_ = 0;

    Impl() {
        rawrxd::SamplerConfig sampler_config;
        sampler_config.strategy = rawrxd::SamplerStrategy::Combined;
        sampler_config.temperature = 0.7f;
        sampler_config.top_k = 40;
        sampler_config.top_p = 0.9f;
        sampler_.SetConfig(sampler_config);
    }
};

CPUInferenceEngine::CPUInferenceEngine()
    : m_impl(std::make_unique<Impl>()) {}
CPUInferenceEngine::~CPUInferenceEngine() = default;

RawrXD::Expected<void, InferenceError> CPUInferenceEngine::loadModel(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);

    // Load transformer config (and attempt weight loading)
    if (!m_impl->transformer_.LoadWeights(path)) {
        m_impl->last_error_ = "TransformerRuntime::LoadWeights failed";
        return RawrXD::unexpected(InferenceError::ModelNotFound);
    }

    // Load tokenizer vocab from GGUF metadata.
    // RAWRXD_P0_FAIL_CLOSED_001: this was non-fatal, so loadModel() returned
    // success and set model_loaded_ = true with an empty vocabulary. Callers
    // then encoded against nothing and reported a loaded model. A model whose
    // tokenizer did not load cannot generate text, so this must fail.
    if (!m_impl->tokenizer_.LoadFromGGUF(path)) {
        m_impl->model_loaded_ = false;
        m_impl->last_error_ =
            "Tokenizer::LoadFromGGUF failed; refusing to report a loaded model "
            "with no vocabulary";
        return RawrXD::unexpected(InferenceError::TokenizationFailed);
    }

    m_impl->model_loaded_ = true;
    return RawrXD::Expected<void, InferenceError>();
}

bool CPUInferenceEngine::isModelLoaded() const {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    return m_impl->model_loaded_;
}

RawrXD::Expected<CPUInferenceEngine::GenerationResult, InferenceError>
CPUInferenceEngine::generate(const std::string& prompt, float temp, float top_p_val, int max_tokens) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);

    if (!m_impl->model_loaded_) {
        return RawrXD::unexpected(InferenceError::ModelNotFound);
    }

    // Tokenize prompt
    auto input_tokens_u32 = m_impl->tokenizer_.Encode(prompt);
    if (input_tokens_u32.empty()) {
        return RawrXD::unexpected(InferenceError::TokenizationFailed);
    }

    // Configure sampler
    rawrxd::SamplerConfig cfg = m_impl->sampler_.GetConfig();
    cfg.temperature = temp;
    cfg.top_p = top_p_val;
    cfg.strategy = rawrxd::SamplerStrategy::Combined;
    m_impl->sampler_.SetConfig(cfg);
    m_impl->sampler_.ResetState();

    // Prefill: run forward on the input tokens
    rawrxd::ForwardResult result = m_impl->transformer_.Forward(input_tokens_u32, 0);
    if (!result.success) {
        return RawrXD::unexpected(InferenceError::InternalError);
    }

    std::vector<uint32_t> generated_tokens;
    int tokens_generated = 0;
    int pos = static_cast<int>(input_tokens_u32.size());

    // Autoregressive generation
    for (int i = 0; i < max_tokens; ++i) {
        if (result.logits.empty()) {
            break;
        }

        rawrxd::SamplerResult sample_result = m_impl->sampler_.Sample(result.logits);
        uint32_t next_token = sample_result.selected_token;

        // Accept token into sampler state for repetition penalty
        m_impl->sampler_.AcceptToken(next_token);

        generated_tokens.push_back(next_token);
        tokens_generated++;

        if (sample_result.is_end_of_text) {
            break;
        }

        // Single-token forward for next step
        std::vector<uint32_t> single_token = {next_token};
        result = m_impl->transformer_.Forward(single_token, pos);
        if (!result.success) {
            break;
        }
        pos++;
    }

    // Detokenize generated tokens
    std::string output_text = m_impl->tokenizer_.Decode(generated_tokens);

    GenerationResult gen_result;
    gen_result.text = output_text;
    gen_result.tokens_generated = tokens_generated;
    gen_result.confidence = 0.0f;
    if (!generated_tokens.empty()) {
        // Simple confidence proxy based on token count
        gen_result.confidence = std::min(1.0f, static_cast<float>(tokens_generated) / static_cast<float>(max_tokens));
    }

    m_impl->total_tokens_generated_ += tokens_generated;
    return gen_result;
}

void CPUInferenceEngine::GenerateStreaming(
    const std::vector<int>& tokens,
    int max_tokens,
    StreamCallback on_token,
    DoneCallback on_done) {

    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    if (!m_impl->model_loaded_ || tokens.empty()) {
        if (on_done) on_done();
        return;
    }

    // Convert int to uint32_t
    std::vector<uint32_t> input_tokens_u32(tokens.begin(), tokens.end());

    rawrxd::ForwardResult result = m_impl->transformer_.Forward(input_tokens_u32, 0);
    if (!result.success) {
        if (on_done) on_done();
        return;
    }

    int pos = static_cast<int>(input_tokens_u32.size());
    rawrxd::SamplerConfig cfg = m_impl->sampler_.GetConfig();
    cfg.strategy = rawrxd::SamplerStrategy::Combined;
    m_impl->sampler_.SetConfig(cfg);
    m_impl->sampler_.ResetState();

    for (int i = 0; i < max_tokens; ++i) {
        if (result.logits.empty()) break;

        rawrxd::SamplerResult sample_result = m_impl->sampler_.Sample(result.logits);
        uint32_t next_token = sample_result.selected_token;
        m_impl->sampler_.AcceptToken(next_token);

        std::string piece = m_impl->tokenizer_.DecodePiece(next_token);
        if (on_token) on_token(piece);

        if (sample_result.is_end_of_text) break;

        std::vector<uint32_t> single = {next_token};
        result = m_impl->transformer_.Forward(single, pos);
        if (!result.success) break;
        pos++;
    }

    if (on_done) on_done();
}

std::vector<int> CPUInferenceEngine::Tokenize(const std::string& text) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    auto u32 = m_impl->tokenizer_.Encode(text);
    return std::vector<int>(u32.begin(), u32.end());
}

std::string CPUInferenceEngine::Detokenize(const std::vector<int>& tokens) {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    std::vector<uint32_t> u32(tokens.begin(), tokens.end());
    return m_impl->tokenizer_.Decode(u32);
}

nlohmann::json CPUInferenceEngine::getStatus() const {
    std::lock_guard<std::mutex> lock(m_impl->mutex_);
    nlohmann::json j;
    j["model_loaded"] = m_impl->model_loaded_;
    j["total_tokens_generated"] = m_impl->total_tokens_generated_;
    j["last_error"] = m_impl->last_error_;
    if (m_impl->model_loaded_) {
        const auto& cfg = m_impl->transformer_.GetConfig();
        j["vocab_size"] = cfg.vocab_size;
        j["hidden_size"] = cfg.hidden_size;
        j["num_layers"] = cfg.num_hidden_layers;
        j["num_heads"] = cfg.num_attention_heads;
        j["max_position_embeddings"] = cfg.max_position_embeddings;
    }
    return j;
}

} // namespace RawrXD
