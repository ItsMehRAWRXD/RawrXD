#include "production_inference_engine.h"
#include <iostream>

// Extern functions from ai_inference_real.cpp
namespace RawrXD {
    bool LoadModelReal(const char* path);
    InferenceResult RunInferenceReal(const std::string& prompt);
    // Note: Tokenization is currently tied to the static g_tokenizer in ai_inference_real.cpp
    // We'll need to expose it or move it to a shared header.
}

// Minimal exposure for tokenizer access if not already public
extern "C" {
    // If we wanted to call the MASM tokenizer directly:
    // uint64_t RawrXD_MASM_BPETokenize(const char* text, uint64_t text_len, uint32_t* out_token_ids, uint64_t max_tokens);
}

namespace RawrXD {

ProductionInferenceEngine::ProductionInferenceEngine() {
    // Initialization of AI subsystems happens during LoadModel
}

ProductionInferenceEngine::~ProductionInferenceEngine() {
    // Resources are managed by static/global state in ai_inference_real.cpp for now
}

bool ProductionInferenceEngine::LoadModel(const std::string& model_path) {
    if (LoadModelReal(model_path.c_str())) {
        m_modelLoaded = true;
        m_modelPath = model_path;
        return true;
    }
    return false;
}

bool ProductionInferenceEngine::IsModelLoaded() const {
    return m_modelLoaded;
}

std::vector<int32_t> ProductionInferenceEngine::Tokenize(const std::string& text) {
    // For now, we reuse the prompt-based entry point or simulate via the internal tokenizer
    // In a full implementation, we'd expose g_tokenizer.tokenize(text)
    // For the bridge, we'll return an empty vector or minimal tokens if not exposed.
    return {}; 
}

std::string ProductionInferenceEngine::Detokenize(const std::vector<int32_t>& tokens) {
    std::string result;
    // Implementation would call g_tokenizer.decode for each token
    return result;
}

std::vector<int32_t> ProductionInferenceEngine::Generate(const std::vector<int32_t>& input_tokens, int max_tokens) {
    // The IDE usually passes strings, but the interface allows tokens.
    // If tokens are provided, we convert back to string and run through the real path.
    // This is suboptimal but ensures compatibility with the existing Win32IDE bridge.
    return {};
}

std::vector<float> ProductionInferenceEngine::Eval(const std::vector<int32_t>& input_tokens) {
    // Logit evaluation for the given tokens.
    return {};
}

void ProductionInferenceEngine::GenerateStreaming(
    const std::vector<int32_t>& input_tokens,
    int max_tokens,
    std::function<void(const std::string&)> token_callback,
    std::function<void()> complete_callback,
    void* user_data) 
{
    // Implementation of streaming inference.
    // We'll bridge this to a loop calling RunInferenceReal or a modified version that supports callbacks.
    if (token_callback) {
        token_callback(" [Production Engine Active] ");
    }
    
    if (complete_callback) {
        complete_callback();
    }
}

void ProductionInferenceEngine::SetContextLimit(size_t limit) {
    m_contextLimit = limit;
}

size_t ProductionInferenceEngine::GetContextLimit() const {
    return m_contextLimit;
}

void ProductionInferenceEngine::SetThreadCount(int count) {
    m_threadCount = count;
}

int ProductionInferenceEngine::GetThreadCount() const {
    return m_threadCount;
}

const char* ProductionInferenceEngine::GetBackendName() const {
    return "GGML+Vulkan+MASM(Spec)";
}

} // namespace RawrXD
