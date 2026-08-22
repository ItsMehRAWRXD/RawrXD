// ============================================================================
// IModelRuntime.hpp — Authoritative Model Runtime Contract
// ----------------------------------------------------------------------------
// Abstract interface that decouples the agent/IDE layer from any specific
// inference backend (Deep2, Ollama, future GPU runtime, etc.).
//
// Design constraints:
//   - No backend-specific types leak through (no GGML types, no OllamaConfig)
//   - Streaming-first: blocking Generate is implemented atop GenerateStream
//   - Thread-safe: implementations must serialize concurrent calls internally
//   - Cancellation: cooperative, signaled via CancelGeneration()
//
// Migration path:
//   1. Implement Deep2ModelRuntime : IModelRuntime (wraps Deep2Engine)
//   2. Implement OllamaModelRuntime : IModelRuntime (wraps AgentOllamaClient)
//   3. Replace OrchestratorBridge::m_ollamaClient with std::unique_ptr<IModelRuntime>
//   4. Delete rawrxd_link_stubs.cpp OrchestratorBridge/AgentOllamaClient stubs
// ============================================================================

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Model metadata (backend-agnostic)
// ============================================================================
struct ModelInfo {
    std::string name;                 // e.g. "kimi-k2-instruct-0905"
    std::string architecture;         // e.g. "deepseek_moe", "llama"
    std::string quantization;         // e.g. "Q4_K_M", "Q8_0", "FP16"
    uint64_t parameterCount = 0;
    uint32_t numLayers = 0;
    uint32_t numExperts = 0;
    uint32_t hiddenSize = 0;
    uint32_t vocabSize = 0;
    uint32_t contextLength = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;
    bool isLoaded = false;
    bool isMoE = false;
    uint64_t memoryBytes = 0;         // Approximate RAM/VRAM footprint
};

// ============================================================================
// Generation request
// ============================================================================
struct GenerationRequest {
    std::string prompt;
    std::string systemPrompt;         // Optional system instructions
    uint32_t maxTokens = 4096;
    float temperature = 0.7f;
    float topP = 0.9f;
    uint32_t topK = 40;
    float repeatPenalty = 1.0f;
    std::vector<std::string> stopSequences;
    // Tool-calling schema (JSON schema strings)
    std::vector<std::string> toolSchemas;
};

// ============================================================================
// Generation result (blocking API)
// ============================================================================
struct GenerationResult {
    std::string text;
    uint32_t tokensGenerated = 0;
    uint32_t promptTokens = 0;
    double tokensPerSecond = 0.0;
    double latencyMs = 0.0;
    std::string finishReason;         // "stop", "length", "cancelled", "error"
    bool success = false;
    std::string errorMessage;
    // Tool calls emitted by the model (if any)
    std::vector<std::pair<std::string, std::string>> toolCalls; // [(name, args_json)]
};

// ============================================================================
// Streaming token callback
//   token: the decoded text fragment (may be partial UTF-8)
//   done:  true when the stream is complete
// Return false from callback to request cancellation (cooperative)
// ============================================================================
using TokenCallback = std::function<bool(const std::string& token, bool done)>;

// ============================================================================
// FIM (Fill-in-Middle) request for ghost text
// ============================================================================
struct FIMRequest {
    std::string prefix;
    std::string suffix;
    std::string filePath;             // For language-aware completion
    std::string language;             // e.g. "cpp", "python"
    uint32_t maxTokens = 256;
    float temperature = 0.2f;
};

// ============================================================================
// IModelRuntime — the one authoritative interface
// ============================================================================
class IModelRuntime {
public:
    virtual ~IModelRuntime() = default;

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------

    /// Load a model from a local path (GGUF directory, single file, or registry name).
    /// Returns false with errorMessage on failure.
    virtual bool LoadModel(const std::string& path, std::string& errorMessage) = 0;

    /// Unload the current model and free resources.
    virtual void UnloadModel() = 0;

    /// Query whether a model is currently loaded and ready for inference.
    virtual bool IsLoaded() const = 0;

    /// Get metadata for the currently loaded model.
    virtual ModelInfo GetModelInfo() const = 0;

    // ------------------------------------------------------------------------
    // Tokenization
    // ------------------------------------------------------------------------

    /// Convert text to token IDs (useful for prompt counting, caching).
    virtual std::vector<int32_t> Tokenize(const std::string& text) = 0;

    /// Convert token IDs back to text.
    virtual std::string Detokenize(const std::vector<int32_t>& tokens) = 0;

    // ------------------------------------------------------------------------
    // Generation
    // ------------------------------------------------------------------------

    /// Blocking generation. Internally delegates to GenerateStream and collects output.
    virtual GenerationResult Generate(const GenerationRequest& request) = 0;

    /// Streaming generation. Calls back with tokens as they are produced.
    /// Returns true if generation started successfully.
    virtual bool GenerateStream(const GenerationRequest& request, TokenCallback callback) = 0;

    /// Cancel an in-progress generation (cooperative — signals cancellation flag).
    virtual void CancelGeneration() = 0;

    /// Check if generation is currently running.
    virtual bool IsGenerating() const = 0;

    // ------------------------------------------------------------------------
    // FIM / Ghost Text
    // ------------------------------------------------------------------------

    /// Blocking FIM completion (for ghost text).
    virtual GenerationResult GenerateFIM(const FIMRequest& request) = 0;

    /// Streaming FIM completion.
    virtual bool GenerateFIMStream(const FIMRequest& request, TokenCallback callback) = 0;

    // ------------------------------------------------------------------------
    // Tool Support
    // ------------------------------------------------------------------------

    /// Return true if this runtime supports structured tool calling.
    virtual bool SupportsToolCalling() const = 0;

    /// Return true if this runtime supports FIM/ghost text.
    virtual bool SupportsFIM() const = 0;

    // ------------------------------------------------------------------------
    // Health / Diagnostics
    // ------------------------------------------------------------------------

    /// Backend health check (connection, VRAM, etc.).
    virtual bool HealthCheck(std::string& statusMessage) = 0;

    /// Human-readable backend name (for UI display).
    virtual std::string GetBackendName() const = 0;
};

// ============================================================================
// Factory — create runtime by backend name
// ============================================================================
enum class BackendType {
    Deep2,      // Local Deep2 engine (GGUF, K2, etc.)
    Ollama,     // Remote/local Ollama server
    Mock        // Test stub
};

/// Create a runtime instance. Returns nullptr on unsupported backend.
std::unique_ptr<IModelRuntime> CreateModelRuntime(BackendType type);

/// Create from string ("deep2", "ollama", "mock").
std::unique_ptr<IModelRuntime> CreateModelRuntime(const std::string& name);

} // namespace Runtime
} // namespace RawrXD
