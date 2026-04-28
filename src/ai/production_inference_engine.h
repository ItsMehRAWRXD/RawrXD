#pragma once
#include "RawrXD_Interfaces.h"
#include "ai/ai_inference_real.h"
#include "ai/speculative_decoder.h"
#include <memory>
#include <string>
#include <vector>

namespace RawrXD {

/**
 * @brief Production Inference Engine Implementation
 * Bridges the abstract InferenceEngine interface to the real GGML-based backend
 * with integrated Speculative Decoding and MASM-accelerated memory management.
 */
class ProductionInferenceEngine : public RawrXD::InferenceEngine {
public:
    ProductionInferenceEngine();
    virtual ~ProductionInferenceEngine() override;

    // ---- Model Lifecycle ----
    virtual bool LoadModel(const std::string& model_path) override;
    virtual bool IsModelLoaded() const override;

    // ---- Tokenization ----
    virtual std::vector<int32_t> Tokenize(const std::string& text) override;
    virtual std::string Detokenize(const std::vector<int32_t>& tokens) override;

    // ---- Inference ----
    virtual std::vector<int32_t> Generate(const std::vector<int32_t>& input_tokens, int max_tokens = 100) override;
    virtual std::vector<float> Eval(const std::vector<int32_t>& input_tokens) override;

    // ---- Streaming ----
    virtual void GenerateStreaming(
        const std::vector<int32_t>& input_tokens,
        int max_tokens,
        std::function<void(const std::string&)> token_callback,
        std::function<void()> complete_callback = nullptr,
        void* user_data = nullptr) override;

    // ---- Configuration ----
    virtual void SetContextLimit(size_t limit) override;
    virtual size_t GetContextLimit() const override;
    virtual void SetThreadCount(int count) override;
    virtual int GetThreadCount() const override;
    virtual const char* GetBackendName() const override;

private:
    bool m_modelLoaded = false;
    std::string m_modelPath;
    size_t m_contextLimit = 4096;
    int m_threadCount = 4;
};

} // namespace RawrXD
