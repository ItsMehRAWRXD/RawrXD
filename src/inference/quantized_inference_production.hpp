// ============================================================================
// Quantized Inference Production Integration
// RawrXD Sovereign Inference Pipeline - C1-C7 Complete
// ============================================================================
// Purpose: Production-ready wrapper for QuantizedInferenceRouter
//          Auto-detects Q4_0 models and routes to 131 tok/s backend
//          Falls back to standard backend (31 tok/s) for other formats
//
// Usage:
//   auto engine = QuantizedInferenceEngine::Create();
//   engine->LoadModel("ministral3_q4_0.gguf");
//   auto result = engine->Generate("Hello, how are you?", 50);
//
// Performance Tiers:
//   - Q4_0: 131 tok/s (4:1 compression, validated)
//   - Standard: 31 tok/s (FP32 fallback)
//   - Speculative: 372 tok/s projected (C5d, draft+verify)
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

namespace RawrXD {
namespace Inference {

// Forward declarations
class QuantizedInferenceRouter;

// ============================================================================
// Generation Result
// ============================================================================
struct GenerationResult {
    std::string text;                    // Generated text
    std::vector<uint32_t> tokens;        // Token IDs
    float tokensPerSecond;               // Actual throughput achieved
    float targetTokensPerSecond;         // Expected throughput
    bool isQuantized;                    // Used Q4_0 backend
    uint32_t promptTokens;               // Input token count
    uint32_t generatedTokens;            // Output token count
    float durationMs;                    // Total generation time
    
    GenerationResult() 
        : tokensPerSecond(0.0f)
        , targetTokensPerSecond(31.0f)
        , isQuantized(false)
        , promptTokens(0)
        , generatedTokens(0)
        , durationMs(0.0f) {}
};

// ============================================================================
// Configuration
// ============================================================================
struct InferenceConfig {
    float temperature;                   // Sampling temperature (0.0-2.0)
    int topK;                           // Top-K sampling (0=disabled)
    float topP;                         // Top-P sampling (0.0-1.0)
    int maxTokens;                      // Maximum tokens to generate
    uint32_t seed;                      // Random seed
    bool autoDetectQuantization;        // Auto-detect Q4_0 from filename
    bool forceQuantized;                // Force Q4_0 path (fail if not Q4_0)
    bool enableSpeculative;             // Enable speculative decoding (C5d)
    int speculativeDraftTokens;         // K draft tokens (default: 4)
    
    InferenceConfig()
        : temperature(0.8f)
        , topK(40)
        , topP(0.95f)
        , maxTokens(256)
        , seed(42)
        , autoDetectQuantization(true)
        , forceQuantized(false)
        , enableSpeculative(false)
        , speculativeDraftTokens(4) {}
};

// ============================================================================
// Progress Callback
// ============================================================================
using GenerationCallback = std::function<void(
    const std::string& token,           // Current token text
    uint32_t tokenId,                   // Token ID
    int progress,                       // Progress (0-100)
    float tokensPerSecond               // Current throughput
)>;

// ============================================================================
// Quantized Inference Engine
// Production-ready interface for RawrXD inference
// ============================================================================
class QuantizedInferenceEngine {
public:
    // Factory
    static std::unique_ptr<QuantizedInferenceEngine> Create();
    
    // Construction
    QuantizedInferenceEngine();
    ~QuantizedInferenceEngine();
    
    // Disable copy/move
    QuantizedInferenceEngine(const QuantizedInferenceEngine&) = delete;
    QuantizedInferenceEngine& operator=(const QuantizedInferenceEngine&) = delete;
    
    // Model Management
    bool LoadModel(const std::string& modelPath);
    bool LoadModel(const std::string& modelPath, const InferenceConfig& config);
    void UnloadModel();
    bool IsModelLoaded() const;
    
    // Model Information
    std::string GetModelPath() const;
    bool IsQuantizedModel() const;
    float GetModelSizeGB() const;
    std::string GetBackendName() const;
    
    // Configuration
    void SetConfig(const InferenceConfig& config);
    const InferenceConfig& GetConfig() const;
    
    // Generation
    GenerationResult Generate(const std::string& prompt);
    GenerationResult Generate(const std::string& prompt, int maxTokens);
    GenerationResult Generate(const std::string& prompt, 
                              const InferenceConfig& config);
    
    // Streaming Generation
    void GenerateStreaming(const std::string& prompt,
                          const GenerationCallback& callback);
    void GenerateStreaming(const std::string& prompt,
                          const InferenceConfig& config,
                          const GenerationCallback& callback);
    
    // Performance Metrics
    float GetLastTokensPerSecond() const;
    float GetAverageTokensPerSecond() const;
    int GetTotalTokensGenerated() const;
    void ResetMetrics();
    
    // Validation
    bool ValidatePerformance(float minTokensPerSecond = 120.0f);
    bool RunSelfTest();
    
    // Status
    std::string GetStatusString() const;
    void PrintStatus() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Check if model path indicates Q4_0 quantization
bool IsQ4_0Model(const std::string& modelPath);

// Get expected throughput for model type
float GetExpectedThroughput(const std::string& modelPath);

// Format throughput for display
std::string FormatThroughput(float tokensPerSecond);

// Validate model file exists and is readable
bool ValidateModelFile(const std::string& modelPath);

// ============================================================================
// Version Information
// ============================================================================
constexpr uint32_t QUANTIZED_INFERENCE_VERSION_MAJOR = 1;
constexpr uint32_t QUANTIZED_INFERENCE_VERSION_MINOR = 0;
constexpr uint32_t QUANTIZED_INFERENCE_VERSION_PATCH = 0;

inline std::string GetQuantizedInferenceVersion() {
    return std::to_string(QUANTIZED_INFERENCE_VERSION_MAJOR) + "." +
           std::to_string(QUANTIZED_INFERENCE_VERSION_MINOR) + "." +
           std::to_string(QUANTIZED_INFERENCE_VERSION_PATCH);
}

// ============================================================================
// Performance Constants
// ============================================================================
constexpr float Q4_0_TARGET_THROUGHPUT = 131.0f;      // tok/s
constexpr float STANDARD_TARGET_THROUGHPUT = 31.5f;    // tok/s
constexpr float SPECULATIVE_TARGET_THROUGHPUT = 372.0f; // tok/s projected
constexpr float Q4_0_MIN_ACCEPTABLE = 120.0f;        // tok/s
constexpr float STANDARD_MIN_ACCEPTABLE = 25.0f;     // tok/s

} // namespace Inference
} // namespace RawrXD
