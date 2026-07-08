/**
 * @file GGMLBackend.cpp
 * @brief Implementation of GGMLBackend wrapper
 * 
 * Provides clean C++ interface to GGML functionality.
 * 
 * @copyright RawrXD 2026
 */

#include "GGMLBackend.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <mutex>
#include <random>
#include <sstream>
#include <unordered_map>

// GGML includes
extern "C" {
#include "../../3rdparty/ggml/include/ggml.h"
#include "../../3rdparty/ggml/include/ggml-backend.h"
#include "../../3rdparty/ggml/include/ggml-cpu.h"
#include "../../3rdparty/ggml/include/gguf.h"
}

namespace RawrXD {
namespace Inference {

// ============================================================================
// Private Implementation
// ============================================================================

class GGMLBackend::Impl {
public:
    Impl(const GGMLBackendConfig& config)
        : m_config(config)
        , m_initialized(false)
        , m_modelLoaded(false)
        , m_backend(nullptr)
        , m_context(nullptr)
        , m_ggufContext(nullptr) {
    }

    ~Impl() {
        // Cleanup is handled by GGMLBackend destructor
    }

    // Configuration
    GGMLBackendConfig m_config;
    
    // State
    bool m_initialized;
    bool m_modelLoaded;
    mutable std::mutex m_mutex;
    std::string m_lastError;
    
    // GGML objects (using proper C types)
    void* m_backend;  // ggml_rxd_backend_t
    void* m_context;  // ggml_rxd_context*
    void* m_ggufContext; // gguf_context*
    
    // Model info
    ModelArchitecture m_architecture{};
    size_t m_modelSize = 0;
    
    // Vocabulary
    std::vector<std::string> m_vocab;
    std::unordered_map<std::string, int> m_tokenToId;
    std::unordered_map<int, std::string> m_idToToken;
    int m_bosToken = 1;
    int m_eosToken = 2;
    int m_padToken = 0;
    int m_nlToken = 13;  // '\n'
    
    // Context
    std::vector<int> m_contextTokens;
    
    // Helper methods
    bool InitializeBackend();
    bool LoadGGUF(const std::string& path);
    bool InitializeTokenizer();
    std::vector<float> Softmax(const std::vector<float>& logits);
};

bool GGMLBackend::Impl::InitializeBackend() {
    // Initialize GGML backend based on config
    ggml_rxd_backend_t backend = nullptr;
    
    switch (m_config.backendType) {
        case GGMLBackendConfig::BackendType::CPU:
            backend = ggml_rxd_backend_cpu_init();
            break;
            
        case GGMLBackendConfig::BackendType::CUDA:
            // TODO: Add CUDA support
            backend = ggml_rxd_backend_cpu_init();  // Fallback to CPU
            break;
            
        case GGMLBackendConfig::BackendType::Vulkan:
            // TODO: Add Vulkan support
            backend = ggml_rxd_backend_cpu_init();  // Fallback to CPU
            break;
            
        case GGMLBackendConfig::BackendType::Auto:
        default:
            // Try GPU backends first, fall back to CPU
            backend = ggml_rxd_backend_cpu_init();
            break;
    }
    
    if (!backend) {
        m_lastError = "Failed to initialize GGML backend";
        return false;
    }
    
    m_backend = backend;  // void* stores the opaque pointer
    
    // Create context
    struct ggml_rxd_init_params params = {
        .mem_size = m_config.tensorBufferSize,
        .mem_buffer = nullptr,
        .no_alloc = false,
    };
    
    m_context = ggml_rxd_init(params);
    if (!m_context) {
        ggml_rxd_backend_free(static_cast<ggml_rxd_backend_t>(m_backend));
        m_backend = nullptr;
        m_lastError = "Failed to create GGML context";
        return false;
    }
    
    return true;
}

bool GGMLBackend::Impl::LoadGGUF(const std::string& path) {
    // Load GGUF file
    struct gguf_init_params gguf_params = {
        .no_alloc = false,
        .ctx = reinterpret_cast<struct ggml_rxd_context**>(&m_context),
    };
    
    m_ggufContext = gguf_init_from_file(path.c_str(), gguf_params);
    if (!m_ggufContext) {
        m_lastError = "Failed to load GGUF file: " + path;
        return false;
    }
    
    // Extract architecture info
    // TODO: Parse actual GGUF metadata
    m_architecture.name = "llama";
    m_architecture.vocabSize = 32000;  // Default vocab size
    m_architecture.numLayers = 32;
    m_architecture.numHeads = 32;
    m_architecture.numKVHeads = 32;
    m_architecture.embeddingDim = 4096;
    m_architecture.hiddenDim = 11008;
    m_architecture.contextLength = 4096;
    
    // Calculate model size
    m_modelSize = 0;
    int numTensors = gguf_get_n_tensors(static_cast<struct gguf_context*>(m_ggufContext));
    for (int i = 0; i < numTensors; i++) {
        const char* name = gguf_get_tensor_name(static_cast<struct gguf_context*>(m_ggufContext), i);
        struct ggml_rxd_tensor* tensor = ggml_rxd_get_tensor(static_cast<struct ggml_rxd_context*>(m_context), name);
        if (tensor) {
            m_modelSize += ggml_rxd_nbytes(tensor);
        }
    }
    
    return true;
}

bool GGMLBackend::Impl::InitializeTokenizer() {
    // TODO: Load actual tokenizer from GGUF
    // For now, create a simple stub vocabulary
    int vocabSize = m_architecture.vocabSize > 0 ? m_architecture.vocabSize : 32000;
    
    m_vocab.reserve(vocabSize);
    m_tokenToId.reserve(vocabSize);
    m_idToToken.reserve(vocabSize);
    
    for (int i = 0; i < vocabSize; i++) {
        std::string token = "token_" + std::to_string(i);
        if (i == m_bosToken) token = "<s>";
        if (i == m_eosToken) token = "</s>";
        if (i == m_padToken) token = "<pad>";
        
        m_vocab.push_back(token);
        m_tokenToId[token] = i;
        m_idToToken[i] = token;
    }
    
    return true;
}

std::vector<float> GGMLBackend::Impl::Softmax(const std::vector<float>& logits) {
    std::vector<float> probs = logits;
    
    // Find max for numerical stability
    float maxLogit = *std::max_element(probs.begin(), probs.end());
    
    // Compute exp(x - max)
    float sum = 0.0f;
    for (auto& p : probs) {
        p = std::exp(p - maxLogit);
        sum += p;
    }
    
    // Normalize
    for (auto& p : probs) {
        p /= sum;
    }
    
    return probs;
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<GGMLBackend> GGMLBackend::Create(const GGMLBackendConfig& config) {
    return std::unique_ptr<GGMLBackend>(new GGMLBackend(config));
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

GGMLBackend::GGMLBackend(const GGMLBackendConfig& config)
    : m_impl(std::make_unique<Impl>(config)) {
}

GGMLBackend::~GGMLBackend() = default;

// ============================================================================
// Backend Lifecycle
// ============================================================================

bool GGMLBackend::Initialize() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_initialized) {
        return true;
    }
    
    if (!m_impl->InitializeBackend()) {
        return false;
    }
    
    m_impl->m_initialized = true;
    return true;
}

void GGMLBackend::Shutdown() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_initialized) {
        return;
    }
    
    // Free GGUF context
    if (m_impl->m_ggufContext) {
        gguf_free(static_cast<struct gguf_context*>(m_impl->m_ggufContext));
        m_impl->m_ggufContext = nullptr;
    }
    
    // Free context
    if (m_impl->m_context) {
        ggml_rxd_free(static_cast<struct ggml_rxd_context*>(m_impl->m_context));
        m_impl->m_context = nullptr;
    }
    
    // Free backend
    if (m_impl->m_backend) {
        ggml_rxd_backend_free(static_cast<ggml_rxd_backend_t>(m_impl->m_backend));
        m_impl->m_backend = nullptr;
    }
    
    m_impl->m_initialized = false;
    m_impl->m_modelLoaded = false;
}

bool GGMLBackend::IsInitialized() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_initialized;
}

std::string GGMLBackend::GetBackendType() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_backend) {
        return "none";
    }
    
    // TODO: Get actual backend type from GGML
    return "cpu";
}

// ============================================================================
// Model Loading
// ============================================================================

bool GGMLBackend::LoadModel(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_initialized) {
        m_impl->m_lastError = "Backend not initialized";
        return false;
    }
    
    // Unload existing model
    if (m_impl->m_modelLoaded) {
        UnloadModel();
    }
    
    // Load GGUF
    if (!m_impl->LoadGGUF(path)) {
        return false;
    }
    
    // Initialize tokenizer
    if (!m_impl->InitializeTokenizer()) {
        m_impl->m_lastError = "Failed to initialize tokenizer";
        return false;
    }
    
    m_impl->m_modelLoaded = true;
    return true;
}

void GGMLBackend::UnloadModel() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_ggufContext) {
        gguf_free(static_cast<struct gguf_context*>(m_impl->m_ggufContext));
        m_impl->m_ggufContext = nullptr;
    }
    
    m_impl->m_modelLoaded = false;
    m_impl->m_modelSize = 0;
    m_impl->m_vocab.clear();
    m_impl->m_tokenToId.clear();
    m_impl->m_idToToken.clear();
}

bool GGMLBackend::IsModelLoaded() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_modelLoaded;
}

ModelArchitecture GGMLBackend::GetModelArchitecture() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_architecture;
}

size_t GGMLBackend::GetModelSize() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_modelSize;
}

// ============================================================================
// Tokenization
// ============================================================================

std::vector<int> GGMLBackend::Tokenize(const std::string& text, bool addBOS, bool addEOS) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    std::vector<int> tokens;
    
    if (addBOS) {
        tokens.push_back(m_impl->m_bosToken);
    }
    
    // Simple word-based tokenization (placeholder)
    // TODO: Implement proper BPE/SentencePiece tokenization
    std::istringstream iss(text);
    std::string word;
    while (iss >> word) {
        auto it = m_impl->m_tokenToId.find(word);
        if (it != m_impl->m_tokenToId.end()) {
            tokens.push_back(it->second);
        } else {
            // Unknown token - use hash
            size_t hash = std::hash<std::string>{}(word) % m_impl->m_vocab.size();
            tokens.push_back(static_cast<int>(hash));
        }
    }
    
    if (addEOS) {
        tokens.push_back(m_impl->m_eosToken);
    }
    
    return tokens;
}

std::string GGMLBackend::Detokenize(const std::vector<int>& tokens) {
    std::string result;
    for (int token : tokens) {
        result += GetTokenText(token);
    }
    return result;
}

std::string GGMLBackend::GetTokenText(int token) const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    auto it = m_impl->m_idToToken.find(token);
    if (it != m_impl->m_idToToken.end()) {
        return it->second;
    }
    return "<unk>";
}

int GGMLBackend::GetVocabSize() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return static_cast<int>(m_impl->m_vocab.size());
}

int GGMLBackend::GetBOSToken() const {
    return m_impl->m_bosToken;
}

int GGMLBackend::GetEOSToken() const {
    return m_impl->m_eosToken;
}

int GGMLBackend::GetPadToken() const {
    return m_impl->m_padToken;
}

int GGMLBackend::GetNLToken() const {
    return m_impl->m_nlToken;
}

// ============================================================================
// Inference
// ============================================================================

// Forward declaration from GGMLCompleteForward.cpp
extern std::vector<float> GGMLForward_SimplePass(
    struct ggml_rxd_context* ctx,
    const ModelArchitecture& arch,
    const std::vector<int>& tokens);

std::vector<float> GGMLBackend::Forward(const std::vector<int>& tokens) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_modelLoaded) {
        m_impl->m_lastError = "No model loaded";
        return {};
    }
    
    if (!m_impl->m_context) {
        m_impl->m_lastError = "No GGML context";
        return {};
    }
    
    // Use real GGML forward pass
    return GGMLForward_SimplePass(
        static_cast<struct ggml_rxd_context*>(m_impl->m_context),
        m_impl->m_architecture,
        tokens);
}

std::vector<std::vector<float>> GGMLBackend::ForwardBatch(
    const std::vector<std::vector<int>>& batchTokens) {
    std::vector<std::vector<float>> results;
    results.reserve(batchTokens.size());
    
    for (const auto& tokens : batchTokens) {
        results.push_back(Forward(tokens));
    }
    
    return results;
}

int GGMLBackend::SampleToken(const std::vector<float>& logits,
                              float temperature,
                              int topK,
                              float topP,
                              float repeatPenalty) {
    if (logits.empty()) {
        return 0;
    }
    
    // Apply temperature
    std::vector<float> scaledLogits = logits;
    if (temperature != 1.0f && temperature > 0.0f) {
        for (auto& logit : scaledLogits) {
            logit /= temperature;
        }
    }
    
    // Convert to probabilities
    std::vector<float> probs = m_impl->Softmax(scaledLogits);
    
    // Top-K sampling
    if (topK > 0 && topK < static_cast<int>(probs.size())) {
        std::vector<std::pair<float, int>> indexedProbs;
        for (int i = 0; i < static_cast<int>(probs.size()); i++) {
            indexedProbs.push_back({probs[i], i});
        }
        
        std::partial_sort(indexedProbs.begin(),
                         indexedProbs.begin() + topK,
                         indexedProbs.end(),
                         std::greater<std::pair<float, int>>());
        
        // Sample from top-K
        std::random_device rd;
        std::mt19937 gen(rd());
        std::vector<double> weights;
        for (int i = 0; i < topK; i++) {
            weights.push_back(indexedProbs[i].first);
        }
        std::discrete_distribution<int> dist(weights.begin(), weights.end());
        return indexedProbs[dist(gen)].second;
    }
    
    // Greedy sampling (argmax)
    return std::max_element(probs.begin(), probs.end()) - probs.begin();
}

std::string GGMLBackend::Generate(const std::string& prompt,
                                   int maxTokens,
                                   float temperature,
                                   std::function<bool(const std::string&)> callback) {
    // Tokenize prompt
    std::vector<int> tokens = Tokenize(prompt, true, false);
    
    // Generate tokens
    std::string result;
    for (int i = 0; i < maxTokens; i++) {
        // Forward pass
        std::vector<float> logits = Forward(tokens);
        
        // Sample next token
        int nextToken = SampleToken(logits, temperature);
        
        // Check for EOS
        if (nextToken == GetEOSToken()) {
            break;
        }
        
        // Add to tokens
        tokens.push_back(nextToken);
        
        // Get token text
        std::string tokenText = GetTokenText(nextToken);
        result += tokenText;
        
        // Call callback
        if (callback && !callback(tokenText)) {
            break;
        }
    }
    
    return result;
}

// ============================================================================
// Context Management
// ============================================================================

void GGMLBackend::ClearKVCache() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_contextTokens.clear();
}

size_t GGMLBackend::GetContextLength() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_contextTokens.size();
}

size_t GGMLBackend::GetMaxContextLength() const {
    return m_impl->m_config.maxContextSize;
}

// ============================================================================
// Memory Management
// ============================================================================

size_t GGMLBackend::GetMemoryUsage() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    // TODO: Get actual memory usage from GGML
    return m_impl->m_modelSize;
}

size_t GGMLBackend::GetTotalAllocated() const {
    // TODO: Get total allocated from GGML
    return GetMemoryUsage();
}

// ============================================================================
// Error Handling
// ============================================================================

std::string GGMLBackend::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_lastError;
}

void GGMLBackend::ClearError() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_lastError.clear();
}

} // namespace Inference
} // namespace RawrXD
