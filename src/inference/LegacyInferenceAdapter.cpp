/**
 * @file LegacyInferenceAdapter.cpp
 * @brief Implementation of LegacyInferenceAdapter with GGMLBackend integration
 * 
 * Wraps existing inference code behind the new unified InferenceEngine interface.
 * Now uses GGMLBackend for real model loading and inference.
 * 
 * @copyright RawrXD 2026
 */

#include "LegacyInferenceAdapter.h"
#include "GGMLBackend.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <thread>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Private Implementation
// ============================================================================

class LegacyInferenceAdapter::Impl {
public:
    Impl(LegacyInferenceEngine* legacyEngine, const EngineConfig& config)
        : m_legacyEngine(legacyEngine)
        , m_config(config)
        , m_modelLoaded(false)
        , m_isGenerating(false)
        , m_cancelled(false) {
    }

    // Configuration
    EngineConfig m_config;
    
    // Legacy engine reference (may be null)
    LegacyInferenceEngine* m_legacyEngine;
    
    // GGML Backend for real inference
    std::unique_ptr<GGMLBackend> m_ggmlBackend;
    
    // State
    mutable std::mutex m_mutex;
    bool m_modelLoaded;
    std::atomic<bool> m_isGenerating{false};
    std::atomic<bool> m_cancelled{false};
    std::string m_lastError;
    std::string m_systemPrompt;
    
    // Model info
    ModelInfo m_modelInfo{};
    
    // Context
    std::vector<int> m_contextTokens;
    size_t m_maxContextLength = 4096;
    
    // Metrics
    mutable PerformanceMetrics m_lastMetrics{};
    
    // Callbacks
    std::function<void(float)> m_progressCallback;
    
    // Helper methods
    void UpdateMetrics(const std::chrono::steady_clock::time_point& start,
                       int tokensGenerated, int promptTokens);
};

void LegacyInferenceAdapter::Impl::UpdateMetrics(const std::chrono::steady_clock::time_point& start,
                                                   int tokensGenerated, 
                                                   int promptTokens) {
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - start).count();
    
    m_lastMetrics.totalTimeMs = duration;
    m_lastMetrics.tokensGenerated = tokensGenerated;
    m_lastMetrics.promptTokens = promptTokens;
    m_lastMetrics.tokensPerSecond = duration > 0 ? 
        (tokensGenerated * 1000.0f / duration) : 0.0f;
}

// ============================================================================
// Factory Methods
// ============================================================================

std::unique_ptr<InferenceEngine> LegacyInferenceAdapter::Create(
    LegacyInferenceEngine* legacyEngine) {
    return Create(legacyEngine, EngineConfig{});
}

std::unique_ptr<InferenceEngine> LegacyInferenceAdapter::Create(
    LegacyInferenceEngine* legacyEngine,
    const EngineConfig& config) {
    return std::unique_ptr<InferenceEngine>(new LegacyInferenceAdapter(legacyEngine, config));
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

LegacyInferenceAdapter::LegacyInferenceAdapter(LegacyInferenceEngine* legacyEngine,
                                                const EngineConfig& config)
    : m_impl(std::make_unique<Impl>(legacyEngine, config)) {
    
    // Initialize GGML backend
    GGMLBackendConfig ggmlConfig;
    ggmlConfig.backendType = GGMLBackendConfig::BackendType::CPU;
    ggmlConfig.maxContextSize = config.maxContextLength;
    ggmlConfig.tensorBufferSize = config.tensorBufferSize;
    
    m_impl->m_ggmlBackend = GGMLBackend::Create(ggmlConfig);
}

LegacyInferenceAdapter::~LegacyInferenceAdapter() = default;

// ============================================================================
// Model Lifecycle
// ============================================================================

bool LegacyInferenceAdapter::LoadModel(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    // Unload existing model
    if (m_impl->m_modelLoaded) {
        UnloadModel();
    }
    
    // Initialize GGML backend if not already done
    if (!m_impl->m_ggmlBackend->IsInitialized()) {
        if (!m_impl->m_ggmlBackend->Initialize()) {
            m_impl->m_lastError = "Failed to initialize GGML backend: " + 
                m_impl->m_ggmlBackend->GetLastError();
            return false;
        }
    }
    
    // Load model using GGML backend
    if (!m_impl->m_ggmlBackend->LoadModel(path)) {
        m_impl->m_lastError = "Failed to load model: " + path + 
            " - " + m_impl->m_ggmlBackend->GetLastError();
        return false;
    }
    
    // Get model architecture info
    auto arch = m_impl->m_ggmlBackend->GetModelArchitecture();
    m_impl->m_modelInfo.path = path;
    m_impl->m_modelInfo.architecture = arch.name;
    m_impl->m_modelInfo.vocabSize = arch.vocabSize;
    m_impl->m_modelInfo.numLayers = arch.numLayers;
    m_impl->m_modelInfo.embeddingDim = arch.embeddingDim;
    m_impl->m_modelInfo.numHeads = arch.numHeads;
    m_impl->m_modelInfo.contextLength = arch.contextLength;
    m_impl->m_modelInfo.quantization = "Q4_K_M";  // TODO: Detect from GGUF
    
    m_impl->m_maxContextLength = arch.contextLength;
    m_impl->m_modelLoaded = true;
    m_impl->m_contextTokens.clear();
    
    return true;
}

void LegacyInferenceAdapter::UnloadModel() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_ggmlBackend) {
        m_impl->m_ggmlBackend->UnloadModel();
    }
    
    m_impl->m_modelLoaded = false;
    m_impl->m_contextTokens.clear();
}

bool LegacyInferenceAdapter::IsModelLoaded() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->IsModelLoaded();
    }
    return false;
}

ModelInfo LegacyInferenceAdapter::GetModelInfo() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_modelInfo;
}

// ============================================================================
// Generation
// ============================================================================

GenerationResult LegacyInferenceAdapter::Generate(const std::string& prompt, 
                                                   const GenerationParams& params) {
    return GenerateStreaming(prompt, params, std::function<bool(const TokenInfo&)>{});
}

GenerationResult LegacyInferenceAdapter::GenerateStreaming(
    const std::string& prompt,
    const GenerationParams& params,
    std::function<bool(const TokenInfo&)> callback) {
    
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    GenerationResult result;
    result.success = false;
    
    if (!m_impl->m_modelLoaded || !m_impl->m_ggmlBackend) {
        result.errorMessage = "No model loaded";
        return result;
    }
    
    // Tokenize prompt using GGML backend
    std::vector<int> promptTokens = m_impl->m_ggmlBackend->Tokenize(prompt, true, false);
    int promptTokenCount = static_cast<int>(promptTokens.size());
    
    // Check context limit
    if (promptTokens.size() > m_impl->m_maxContextLength) {
        result.errorMessage = "Prompt exceeds context length";
        return result;
    }
    
    // Start generation
    m_impl->m_isGenerating = true;
    m_impl->m_cancelled = false;
    auto startTime = std::chrono::steady_clock::now();
    
    std::vector<int> generatedTokens;
    std::string generatedText;
    
    // Generate tokens
    for (int i = 0; i < params.maxTokens && !m_impl->m_cancelled; ++i) {
        // Build context (prompt + generated so far)
        std::vector<int> context = promptTokens;
        context.insert(context.end(), generatedTokens.begin(), generatedTokens.end());
        
        // Forward pass using GGML backend
        std::vector<float> logits = m_impl->m_ggmlBackend->Forward(context);
        
        // Sample next token using GGML backend
        int nextToken = m_impl->m_ggmlBackend->SampleToken(
            logits, params.temperature, params.topK, params.topP, params.repeatPenalty);
        
        // Check for EOS
        if (nextToken == m_impl->m_ggmlBackend->GetEOSToken()) {
            break;
        }
        
        // Add to generated tokens
        generatedTokens.push_back(nextToken);
        
        // Get token info
        TokenInfo tokenInfo;
        tokenInfo.id = nextToken;
        tokenInfo.text = m_impl->m_ggmlBackend->GetTokenText(nextToken);
        tokenInfo.logprob = 0.0f;  // TODO: Get actual logprob
        tokenInfo.isSpecial = (nextToken == m_impl->m_ggmlBackend->GetBOSToken() || 
                               nextToken == m_impl->m_ggmlBackend->GetEOSToken() || 
                               nextToken == m_impl->m_ggmlBackend->GetPadToken());
        
        generatedText += tokenInfo.text;
        result.tokens.push_back(tokenInfo);
        
        // Call callback if provided
        if (callback && !callback(tokenInfo)) {
            break; // Callback returned false, stop generation
        }
        
        // Progress callback
        if (m_impl->m_progressCallback) {
            m_impl->m_progressCallback(static_cast<float>(i) / params.maxTokens);
        }
    }
    
    m_impl->m_isGenerating = false;
    
    // Build result
    result.success = true;
    result.text = generatedText;
    result.tokensGenerated = static_cast<int>(generatedTokens.size());
    result.promptTokens = promptTokenCount;
    result.stoppedEOS = !m_impl->m_cancelled && generatedTokens.size() < params.maxTokens;
    result.stoppedLimit = generatedTokens.size() >= params.maxTokens;
    result.isComplete = true;
    
    m_impl->UpdateMetrics(startTime, result.tokensGenerated, promptTokenCount);
    
    return result;
}

GenerationResult LegacyInferenceAdapter::GenerateStreaming(
    const std::string& prompt,
    const GenerationParams& params,
    std::function<void(const std::string&)> callback) {
    
    return GenerateStreaming(prompt, params,
        [&callback](const TokenInfo& token) {
            if (callback) {
                callback(token.text);
            }
            return true;
        });
}

// ============================================================================
// Token Operations
// ============================================================================

std::vector<int> LegacyInferenceAdapter::Tokenize(const std::string& text) {
    return Tokenize(text, false, false);
}

std::vector<int> LegacyInferenceAdapter::Tokenize(const std::string& text, 
                                                 bool addBOS, 
                                                 bool addEOS) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->Tokenize(text, addBOS, addEOS);
    }
    
    return {};
}

std::string LegacyInferenceAdapter::Detokenize(const std::vector<int>& tokens) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->Detokenize(tokens);
    }
    
    return "";
}

std::string LegacyInferenceAdapter::Detokenize(int token) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->GetTokenText(token);
    }
    
    return "<unk>";
}

TokenInfo LegacyInferenceAdapter::GetTokenInfo(int tokenId) {
    TokenInfo info;
    info.id = tokenId;
    info.text = Detokenize(tokenId);
    info.logprob = 0.0f;
    info.isSpecial = false;
    
    if (m_impl->m_ggmlBackend) {
        info.isSpecial = (tokenId == m_impl->m_ggmlBackend->GetBOSToken() || 
                          tokenId == m_impl->m_ggmlBackend->GetEOSToken() || 
                          tokenId == m_impl->m_ggmlBackend->GetPadToken());
    }
    
    return info;
}

// ============================================================================
// Context Management
// ============================================================================

void LegacyInferenceAdapter::ClearContext() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_contextTokens.clear();
    
    if (m_impl->m_ggmlBackend) {
        m_impl->m_ggmlBackend->ClearKVCache();
    }
}

size_t LegacyInferenceAdapter::GetContextLength() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->GetContextLength();
    }
    
    return m_impl->m_contextTokens.size();
}

size_t LegacyInferenceAdapter::GetContextRemaining() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    size_t maxLen = m_impl->m_maxContextLength;
    if (m_impl->m_ggmlBackend) {
        maxLen = m_impl->m_ggmlBackend->GetMaxContextLength();
    }
    
    return maxLen - GetContextLength();
}

bool LegacyInferenceAdapter::IsContextFull() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return GetContextLength() >= m_impl->m_maxContextLength;
}

void LegacyInferenceAdapter::SetSystemPrompt(const std::string& systemPrompt) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_systemPrompt = systemPrompt;
}

// ============================================================================
// Metrics & Diagnostics
// ============================================================================

PerformanceMetrics LegacyInferenceAdapter::GetLastMetrics() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_lastMetrics;
}

void LegacyInferenceAdapter::ResetMetrics() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_lastMetrics = PerformanceMetrics{};
}

bool LegacyInferenceAdapter::ValidateModel() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_modelLoaded) {
        return false;
    }
    
    // Check that GGML backend has model loaded
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->IsModelLoaded();
    }
    
    return false;
}

std::string LegacyInferenceAdapter::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_lastError.empty()) {
        return m_impl->m_lastError;
    }
    
    if (m_impl->m_ggmlBackend) {
        return m_impl->m_ggmlBackend->GetLastError();
    }
    
    return "";
}

// ============================================================================
// Advanced Features
// ============================================================================

void LegacyInferenceAdapter::SetProgressCallback(std::function<void(float)> callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_progressCallback = callback;
}

void LegacyInferenceAdapter::CancelGeneration() {
    m_impl->m_cancelled = true;
}

bool LegacyInferenceAdapter::IsGenerating() const {
    return m_impl->m_isGenerating;
}

bool LegacyInferenceAdapter::Warmup() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_modelLoaded) {
        return false;
    }
    
    // TODO: Run warmup inference
    // For now, just return success
    return true;
}

ggml_context* LegacyInferenceAdapter::GetGGMLContext() {
    // TODO: Return actual GGML context from legacy engine
    return nullptr;
}

// ============================================================================
// Legacy Access
// ============================================================================

LegacyInferenceEngine* LegacyInferenceAdapter::GetLegacyEngine() const {
    return m_impl->m_legacyEngine;
}

} // namespace Inference
} // namespace RawrXD
