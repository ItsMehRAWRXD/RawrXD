// ============================================================================
// inference_engine.cpp — Main Inference Engine Implementation
// ============================================================================
// Bridges RawrInference (Engine interface) to CPUInferenceEngine for real
// transformer-based inference through the RawrXD pipeline.
//
// Key routing: RawrInference::infer() → CPUInferenceEngine::Generate()
// ============================================================================

#include "engine_iface.h"
#include "inference_engine.h"
#include "cpu_inference_engine.h"
#include "RawrXD_Interfaces.h"

#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <random>

// ============================================================================
// RAWRL INFERENCE ENGINE - Production Implementation
// ============================================================================
class RawrInference : public Engine {
private:
    std::string m_modelPath;
    bool m_loaded = false;
    std::shared_ptr<RawrXD::CPUInferenceEngine> m_cpuEngine;

    // Performance tracking
    mutable std::chrono::high_resolution_clock::time_point m_lastInferenceStart;
    mutable double m_lastTokensPerSec = 0.0;
    mutable uint64_t m_totalTokensGenerated = 0;

public:
    RawrInference() {
        printf("[RawrInference] Initializing inference engine...\n");
        // Get the shared CPU inference engine instance
        m_cpuEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
    }

    ~RawrInference() override {
        printf("[RawrInference] Shutting down inference engine...\n");
    }

    // ========================================================================
    // MODEL LOADING
    // ========================================================================
    bool load_model(const std::string& path) override {
        printf("[RawrInference] Loading model from: %s\n", path.c_str());
        m_modelPath = path;

        if (!m_cpuEngine) {
            printf("[RawrInference] ERROR: CPU engine not available\n");
            return false;
        }

        bool success = m_cpuEngine->LoadModel(path);
        if (success) {
            m_loaded = true;
            printf("[RawrInference] Model loaded successfully:\n");
            printf("  - Vocab size: %d\n", m_cpuEngine->GetVocabSize());
            printf("  - Embedding dim: %d\n", m_cpuEngine->GetEmbeddingDim());
            printf("  - Layers: %d\n", m_cpuEngine->GetNumLayers());
            printf("  - Heads: %d\n", m_cpuEngine->GetNumHeads());
        } else {
            printf("[RawrInference] Failed to load model: %s\n", 
                   m_cpuEngine->GetLastLoadErrorMessage().c_str());
        }

        return success;
    }

    // ========================================================================
    // MAIN INFERENCE ENTRY POINT
    // Routes to CPUInferenceEngine::Generate() for real transformer inference
    // ========================================================================
    std::string infer(const AgentRequest& req) override {
        if (!m_loaded || !m_cpuEngine) {
            return "Error: No model loaded. Please load a GGUF model first.";
        }

        auto startTime = std::chrono::high_resolution_clock::now();

        // Configure engine based on request flags
        m_cpuEngine->SetDeepThinking(req.deep_thinking);
        m_cpuEngine->SetDeepResearch(req.deep_research);

        // Set context limit if specified
        if (req.context_limit > 0) {
            m_cpuEngine->SetContextLimit(req.context_limit);
        }

        // Tokenize the prompt
        std::vector<int32_t> inputTokens = m_cpuEngine->Tokenize(req.prompt);
        if (inputTokens.empty()) {
            return "Error: Failed to tokenize input prompt.";
        }

        // Determine max tokens based on mode
        int maxTokens = 100;
        switch (req.mode) {
            case 0: // CHAT
                maxTokens = 512;
                break;
            case 1: // PLAN
                maxTokens = 1024;
                break;
            case 2: // EDIT
            case 3: // CODESUGGEST
                maxTokens = 512;
                break;
            case 4: // BUGREPORT
                maxTokens = 768;
                break;
            case 5: // ASK
                maxTokens = 256;
                break;
            default:
                maxTokens = 100;
        }

        // Deep thinking doubles the token budget
        if (req.deep_thinking) {
            maxTokens *= 2;
        }

        printf("[RawrInference] Starting inference:\n");
        printf("  - Input tokens: %zu\n", inputTokens.size());
        printf("  - Max output tokens: %d\n", maxTokens);
        printf("  - Deep thinking: %s\n", req.deep_thinking ? "yes" : "no");
        printf("  - Deep research: %s\n", req.deep_research ? "yes" : "no");

        // =====================================================================
        // CRITICAL: Route to CPUInferenceEngine::Generate() for real inference
        // This executes the full transformer forward pass:
        //   embedding → [layer_norm → attention → FFN] × N → output projection
        // =====================================================================
        std::vector<int32_t> generatedTokens;
        std::string outputText;

        // Use streaming generation for real-time output
        m_cpuEngine->GenerateStreaming(
            inputTokens,
            maxTokens,
            [&](const std::string& token) {
                // Token callback - accumulate output
                outputText += token;
            },
            [&]() {
                // Completion callback
                printf("[RawrInference] Generation complete\n");
            },
            [&](int32_t tokenId) {
                // Token ID callback - track generated tokens
                generatedTokens.push_back(tokenId);
                m_totalTokensGenerated++;
            }
        );

        // Calculate performance metrics
        auto endTime = std::chrono::high_resolution_clock::now();
        double elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        if (elapsedMs > 0 && !generatedTokens.empty()) {
            m_lastTokensPerSec = (generatedTokens.size() * 1000.0) / elapsedMs;
        }

        // Build response with metadata
        char perfBuffer[256];
        snprintf(perfBuffer, sizeof(perfBuffer),
            "\n\n---\n[RawrXD Inference] %.1fms | %.2f tok/s | %zu tokens generated",
            elapsedMs, m_lastTokensPerSec, generatedTokens.size());

        return outputText + perfBuffer;
    }

    const char* name() override {
        return "RawrXD-Inference-Engine";
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    bool isLoaded() const { return m_loaded; }
    
    double getLastTokensPerSec() const { return m_lastTokensPerSec; }
    
    uint64_t getTotalTokensGenerated() const { return m_totalTokensGenerated; }
    
    std::shared_ptr<RawrXD::CPUInferenceEngine> getCPUEngine() const { 
        return m_cpuEngine; 
    }
};

// ============================================================================
// GLOBAL INSTANCE REGISTRATION
// ============================================================================
static RawrInference g_rawrInferenceInstance;

// Register with the engine registry
struct RawrInferenceRegistrar {
    RawrInferenceRegistrar() {
        EngineRegistry::register_engine(&g_rawrInferenceInstance);
        printf("[RawrInference] Registered with EngineRegistry\n");
    }
};

static RawrInferenceRegistrar g_registrar;

// ============================================================================
// C API EXPORTS (for external integration)
// ============================================================================
extern "C" {

// Check if inference engine is ready
__declspec(dllexport) bool RawrInference_IsReady() {
    return g_rawrInferenceInstance.isLoaded();
}

// Load a model via C API
__declspec(dllexport) bool RawrInference_LoadModel(const char* path) {
    if (!path) return false;
    return g_rawrInferenceInstance.load_model(path);
}

// Run inference via C API
__declspec(dllexport) const char* RawrInference_Run(
    const char* prompt,
    int mode,
    bool deepThinking,
    bool deepResearch,
    size_t contextLimit)
{
    static thread_local std::string resultBuffer;
    
    AgentRequest req;
    req.prompt = prompt ? prompt : "";
    req.mode = mode;
    req.deep_thinking = deepThinking;
    req.deep_research = deepResearch;
    req.context_limit = contextLimit;
    req.no_refusal = false;
    
    resultBuffer = g_rawrInferenceInstance.infer(req);
    return resultBuffer.c_str();
}

// Get engine performance stats
__declspec(dllexport) void RawrInference_GetStats(
    double* tokensPerSec,
    uint64_t* totalTokens)
{
    if (tokensPerSec) *tokensPerSec = g_rawrInferenceInstance.getLastTokensPerSec();
    if (totalTokens) *totalTokens = g_rawrInferenceInstance.getTotalTokensGenerated();
}

} // extern "C"

// ============================================================================
// FALLBACK IMPLEMENTATION (when CPU engine unavailable)
// Provides basic response generation without model weights
// ============================================================================
namespace {

// Simple tokenization fallback
std::vector<int32_t> simpleTokenize(const std::string& text) {
    std::vector<int32_t> tokens;
    // Simple whitespace tokenization as fallback
    size_t start = 0;
    size_t end = text.find(' ');
    int tokenId = 1;
    
    while (end != std::string::npos) {
        tokens.push_back(tokenId++);
        start = end + 1;
        end = text.find(' ', start);
    }
    
    if (start < text.length()) {
        tokens.push_back(tokenId);
    }
    
    return tokens;
}

// Simple detokenization fallback
std::string simpleDetokenize(const std::vector<int32_t>& tokens) {
    std::string result;
    for (size_t i = 0; i < tokens.size(); i++) {
        if (i > 0) result += " ";
        result += "tok" + std::to_string(tokens[i]);
    }
    return result;
}

} // anonymous namespace
