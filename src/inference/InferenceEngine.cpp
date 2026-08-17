/**
 * @file InferenceEngine.cpp
 * @brief Unified Inference Engine Implementation
 * 
 * Consolidates all CPUInferenceEngine implementations into a single,
 * coherent implementation following the 5-layer architecture.
 * 
 * @copyright RawrXD 2026
 */

#include "InferenceEngine.h"

// Real inference implementation
#include "../ai/ai_inference_real.h"

// GGML headers - using RawrXD's modified GGML
extern "C" {
#include "../../3rdparty/ggml/include/ggml.h"
}

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <thread>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace RawrXD {
namespace Inference {

// ============================================================================
// Internal Implementation
// ============================================================================

class InferenceEngineImpl : public InferenceEngine {
public:
    explicit InferenceEngineImpl(const EngineConfig& config);
    ~InferenceEngineImpl() override;

    // Model Lifecycle
    bool LoadModel(const std::string& path) override;
    void UnloadModel() override;
    bool IsModelLoaded() const override;
    ModelInfo GetModelInfo() const override;

    // Generation
    GenerationResult Generate(const std::string& prompt, 
                               const GenerationParams& params) override;
    GenerationResult GenerateStreaming(const std::string& prompt,
                                        const GenerationParams& params,
                                        std::function<bool(const TokenInfo&)> callback) override;
    GenerationResult GenerateStreaming(const std::string& prompt,
                                        const GenerationParams& params,
                                        std::function<void(const std::string&)> callback) override;

    // Token Operations
    std::vector<int> Tokenize(const std::string& text) override;
    std::vector<int> Tokenize(const std::string& text, bool addBOS, bool addEOS) override;
    std::string Detokenize(const std::vector<int>& tokens) override;
    std::string Detokenize(int token) override;
    TokenInfo GetTokenInfo(int tokenId) override;

    // Context Management
    void ClearContext() override;
    size_t GetContextLength() const override;
    size_t GetContextRemaining() const override;
    bool IsContextFull() const override;
    void SetSystemPrompt(const std::string& systemPrompt) override;

    // Metrics & Diagnostics
    PerformanceMetrics GetLastMetrics() const override;
    void ResetMetrics() override;
    bool ValidateModel() override;
    std::string GetLastError() const override;

    // Advanced Features
    void SetProgressCallback(std::function<void(float)> callback) override;
    void CancelGeneration() override;
    bool IsGenerating() const override;
    bool Warmup() override;
    ggml_context* GetGGMLContext() override;

private:
    // Configuration
    EngineConfig m_config;
    
    // GGML State
    struct ggml_context* m_ctx = nullptr;
    struct ggml_model* m_model = nullptr;
    struct ggml_backend* m_backend = nullptr;
    
    // Tokenizer State
    std::vector<std::string> m_vocab;
    std::unordered_map<std::string, int> m_tokenToId;
    std::unordered_map<int, std::string> m_idToToken;
    int m_bosToken = 1;
    int m_eosToken = 2;
    int m_padToken = 0;
    
    // Context State
    std::vector<int> m_contextTokens;
    std::string m_systemPrompt;
    size_t m_maxContextLength = 4096;
    
    // Generation State
    mutable std::mutex m_mutex;
    std::atomic<bool> m_isGenerating{false};
    std::atomic<bool> m_cancelled{false};
    std::function<void(float)> m_progressCallback;
    
    // Metrics
    mutable PerformanceMetrics m_lastMetrics{};
    std::string m_lastError;
    
    // Internal Methods
    void UpdateMetrics(const std::chrono::steady_clock::time_point& start,
                       int tokensGenerated, int promptTokens);
};

// ============================================================================
// Factory Implementation
// ============================================================================

std::unique_ptr<InferenceEngine> InferenceEngine::Create(const EngineConfig& config) {
    return std::make_unique<InferenceEngineImpl>(config);
}

std::unique_ptr<InferenceEngine> InferenceEngine::Create() {
    return Create(EngineConfig{});
}

std::unique_ptr<InferenceEngine> InferenceEngine::CreateLegacyAdapter(
    void* legacyEngine,
    const EngineConfig& config) {
    // Forward declaration - implementation is in LegacyInferenceAdapter.cpp
    // This avoids circular dependency
    extern std::unique_ptr<InferenceEngine> CreateLegacyInferenceAdapter(void* engine, const EngineConfig& cfg);
    return CreateLegacyInferenceAdapter(legacyEngine, config);
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

InferenceEngineImpl::InferenceEngineImpl(const EngineConfig& config)
    : m_config(config) {
    m_maxContextLength = config.maxContextLength;
}

InferenceEngineImpl::~InferenceEngineImpl() {
    UnloadModel();
}

// ============================================================================
// Model Lifecycle
// ============================================================================

bool InferenceEngineImpl::LoadModel(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_model) {
        UnloadModel();
    }

    // Delegate to real GGML-based inference implementation
    if (!RawrXD::LoadModelReal(path.c_str())) {
        m_lastError = "Failed to load GGUF model: " + path;
        return false;
    }

    // Mark as loaded
    m_model = reinterpret_cast<ggml_model*>(1);  // Non-null sentinel
    m_config.modelPath = path;

    // Sync vocab from real tokenizer
    auto info = RawrXD::GetModelInfoReal();
    m_vocab.clear();
    m_tokenToId.clear();
    m_idToToken.clear();
    for (int i = 0; i < info.vocabSize; ++i) {
        std::string token_text = RawrXD::DetokenizeSingleReal(i);
        m_vocab.push_back(token_text);
        m_tokenToId[token_text] = i;
        m_idToToken[i] = token_text;
    }
    if (m_vocab.empty()) {
        // Fallback: create minimal vocab
        for (int i = 0; i < 32000; ++i) {
            m_idToToken[i] = "token_" + std::to_string(i);
            m_tokenToId[m_idToToken[i]] = i;
        }
    }

    return true;
}

void InferenceEngineImpl::UnloadModel() {
    std::lock_guard<std::mutex> lock(m_mutex);

    RawrXD::UnloadModelReal();
    m_backend = nullptr;
    m_ctx = nullptr;
    m_model = nullptr;
    m_contextTokens.clear();
    m_vocab.clear();
    m_tokenToId.clear();
    m_idToToken.clear();
}

bool InferenceEngineImpl::IsModelLoaded() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_model != nullptr && RawrXD::IsModelLoadedReal();
}

ModelInfo InferenceEngineImpl::GetModelInfo() const {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto realInfo = RawrXD::GetModelInfoReal();
    ModelInfo info;
    info.path = m_config.modelPath.empty() ? realInfo.path : m_config.modelPath;
    info.architecture = realInfo.architecture.empty() ? "llama" : realInfo.architecture;
    info.quantization = "unknown";
    info.vocabSize = realInfo.vocabSize > 0 ? realInfo.vocabSize : static_cast<int>(m_vocab.size());
    info.numLayers = realInfo.numLayers;
    info.embeddingDim = realInfo.embeddingDim;
    info.numHeads = realInfo.numHeads;
    info.contextLength = realInfo.contextLength > 0 ? realInfo.contextLength : static_cast<int>(m_maxContextLength);
    info.modelSize = realInfo.modelSizeBytes;
    info.hasTokenizer = !m_vocab.empty();
    info.hasGGMLFormat = m_model != nullptr;

    return info;
}

// ============================================================================
// Generation
// ============================================================================

GenerationResult InferenceEngineImpl::Generate(const std::string& prompt,
                                                const GenerationParams& params) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_model || !RawrXD::IsModelLoadedReal()) {
        return GenerationResult{.success = false, .errorMessage = "No model loaded"};
    }

    auto startTime = std::chrono::steady_clock::now();

    // Delegate to real multi-token inference
    auto result = RawrXD::RunInferenceMultiToken(prompt, params.maxTokens,
                                                   params.temperature, params.topP, params.topK);

    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

    GenerationResult genResult;
    if (result.error.empty()) {
        genResult.success = true;
        genResult.text = result.text;
        genResult.tokensGenerated = static_cast<int>(result.tokens.size());
        genResult.promptTokens = static_cast<int>(RawrXD::TokenizeReal(prompt).size());
        genResult.stoppedEOS = true;
        genResult.isComplete = true;

        for (int tokenId : result.tokens) {
            TokenInfo ti;
            ti.id = tokenId;
            ti.text = RawrXD::DetokenizeSingleReal(tokenId);
            ti.logprob = 0.0f;
            ti.isSpecial = (tokenId == m_bosToken || tokenId == m_eosToken);
            genResult.tokens.push_back(ti);
        }
    } else {
        genResult.success = false;
        genResult.errorMessage = result.error;
    }

    UpdateMetrics(startTime, genResult.tokensGenerated, genResult.promptTokens);
    return genResult;
}

GenerationResult InferenceEngineImpl::GenerateStreaming(
    const std::string& prompt,
    const GenerationParams& params,
    std::function<bool(const TokenInfo&)> callback) {

    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_model || !RawrXD::IsModelLoadedReal()) {
        return GenerationResult{.success = false, .errorMessage = "No model loaded"};
    }

    m_isGenerating = true;
    m_cancelled = false;

    auto startTime = std::chrono::steady_clock::now();

    int promptTokenCount = static_cast<int>(RawrXD::TokenizeReal(prompt).size());
    std::vector<int> generatedTokens;
    std::string generatedText;

    // Use real streaming generation
    RawrXD::GenerateStreamReal(prompt, params.maxTokens,
                               params.temperature, params.topP, params.topK,
        [&callback, &generatedTokens, &generatedText, &m_cancelled = m_cancelled,
         &m_bosToken = m_bosToken, &m_eosToken = m_eosToken, this]
        (const std::string& token_text, bool finished) -> bool {
            if (finished) return true;
            if (m_cancelled) return false;

            // We don't have token IDs in the stream callback, so we use a placeholder
            int tokenId = static_cast<int>(generatedTokens.size()) + 100000;  // Placeholder ID
            generatedTokens.push_back(tokenId);
            generatedText += token_text;

            TokenInfo tokenInfo;
            tokenInfo.id = tokenId;
            tokenInfo.text = token_text;
            tokenInfo.logprob = 0.0f;
            tokenInfo.isSpecial = false;

            if (callback) {
                return callback(tokenInfo);
            }
            return true;
        });

    m_isGenerating = false;

    GenerationResult result;
    result.success = true;
    result.text = generatedText;
    result.tokensGenerated = static_cast<int>(generatedTokens.size());
    result.promptTokens = promptTokenCount;
    result.stoppedEOS = !m_cancelled && generatedTokens.size() < params.maxTokens;
    result.stoppedLimit = generatedTokens.size() >= params.maxTokens;
    result.isComplete = true;

    UpdateMetrics(startTime, result.tokensGenerated, promptTokenCount);
    return result;
}

GenerationResult InferenceEngineImpl::GenerateStreaming(
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

std::vector<int> InferenceEngineImpl::Tokenize(const std::string& text) {
    return Tokenize(text, false, false);
}

std::vector<int> InferenceEngineImpl::Tokenize(const std::string& text,
                                                bool addBOS,
                                                bool addEOS) {
    std::vector<int> tokens;

    if (addBOS) {
        tokens.push_back(m_bosToken);
    }

    // Delegate to real tokenizer
    auto realTokens = RawrXD::TokenizeReal(text);
    tokens.insert(tokens.end(), realTokens.begin(), realTokens.end());

    if (addEOS) {
        tokens.push_back(m_eosToken);
    }

    return tokens;
}

std::string InferenceEngineImpl::Detokenize(const std::vector<int>& tokens) {
    return RawrXD::DetokenizeReal(tokens);
}

std::string InferenceEngineImpl::Detokenize(int token) {
    return RawrXD::DetokenizeSingleReal(token);
}

TokenInfo InferenceEngineImpl::GetTokenInfo(int tokenId) {
    TokenInfo info;
    info.id = tokenId;
    info.text = RawrXD::DetokenizeSingleReal(tokenId);
    info.logprob = 0.0f;
    info.isSpecial = (tokenId == m_bosToken || tokenId == m_eosToken || tokenId == m_padToken);
    return info;
}

// ============================================================================
// Context Management
// ============================================================================

void InferenceEngineImpl::ClearContext() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_contextTokens.clear();
    if (!m_systemPrompt.empty()) {
        m_contextTokens = Tokenize(m_systemPrompt, true, false);
    }
}

size_t InferenceEngineImpl::GetContextLength() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_contextTokens.size();
}

size_t InferenceEngineImpl::GetContextRemaining() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_contextTokens.size() >= m_maxContextLength) {
        return 0;
    }
    return m_maxContextLength - m_contextTokens.size();
}

bool InferenceEngineImpl::IsContextFull() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_contextTokens.size() >= m_maxContextLength;
}

void InferenceEngineImpl::SetSystemPrompt(const std::string& systemPrompt) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_systemPrompt = systemPrompt;
    ClearContext();
}

// ============================================================================
// Metrics & Diagnostics
// ============================================================================

PerformanceMetrics InferenceEngineImpl::GetLastMetrics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastMetrics;
}

void InferenceEngineImpl::ResetMetrics() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_lastMetrics = PerformanceMetrics{};
}

bool InferenceEngineImpl::ValidateModel() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_model != nullptr && m_backend != nullptr;
}

std::string InferenceEngineImpl::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}

// ============================================================================
// Advanced Features
// ============================================================================

void InferenceEngineImpl::SetProgressCallback(std::function<void(float)> callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_progressCallback = callback;
}

void InferenceEngineImpl::CancelGeneration() {
    m_cancelled = true;
}

bool InferenceEngineImpl::IsGenerating() const {
    return m_isGenerating;
}

bool InferenceEngineImpl::Warmup() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_model || !RawrXD::IsModelLoadedReal()) {
        return false;
    }

    // Warm up by running a single-token inference
    auto result = RawrXD::RunInferenceReal("hello");
    return result.error.empty();
}

ggml_context* InferenceEngineImpl::GetGGMLContext() {
    return m_ctx;
}

// ============================================================================
// Internal Methods
// ============================================================================

void InferenceEngineImpl::UpdateMetrics(const std::chrono::steady_clock::time_point& start,
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
// Utility Functions
// ============================================================================

const char* GetInferenceVersion() {
    return "RawrXD Inference Engine v15.0.0";
}

HardwareInfo GetHardwareInfo() {
    HardwareInfo info{};
    
    // CPU detection
    info.numLogicalCores = std::thread::hardware_concurrency();
    info.numPhysicalCores = info.numLogicalCores; // Approximation
    
    // Feature detection
#ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    info.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    info.hasAVX2 = (cpuInfo[2] & (1 << 28)) != 0; // Simplified
    info.hasAVX512 = false; // Would need more complex detection
#else
    // Linux detection would go here
    info.hasAVX = false;
    info.hasAVX2 = false;
    info.hasAVX512 = false;
#endif
    
    // Memory
    info.systemMemory = 0; // Would query system
    info.gpuMemory = 0;
    info.hasGPU = false;
    
    return info;
}

bool IsValidGGUF(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Check GGUF magic number
    uint32_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    return magic == 0x46554747; // "GGUF" in little-endian
}

ModelInfo PeekModelInfo(const std::string& path) {
    ModelInfo info;
    info.path = path;
    
    if (!IsValidGGUF(path)) {
        return info;
    }
    
    // TODO: Read actual metadata from GGUF
    info.hasGGMLFormat = true;
    
    return info;
}

} // namespace Inference
} // namespace RawrXD
