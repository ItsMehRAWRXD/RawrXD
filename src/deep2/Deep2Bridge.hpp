// ============================================================================
// Deep2Bridge.hpp — Native Deep2 Engine Bridge
// Connects RawrXD Runtime to Deep2 Inference Engine
// ============================================================================

#ifndef DEEP2_BRIDGE_HPP
#define DEEP2_BRIDGE_HPP

#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

// Forward declaration for the real engine
namespace Deep2 { class Deep2Engine; }
class LlamaNativeBridge;

namespace rawr {

// ============================================================================
// Inference Backend Selection
// ============================================================================
enum class InferenceBackend {
    Deep2Engine,
    LlamaNative
};

// ============================================================================
// Engine Configuration
// ============================================================================
struct EngineConfig {
    std::string modelPath;
    std::string modelType = "GGUF";
    uint32_t gpuDevice = 0;
    uint32_t numThreads = 0;  // 0 = auto
    uint64_t contextSize = 2048;
    float temperature = 0.7f;
    uint32_t topK = 40;
    float topP = 0.95f;
    bool useKVCache = true;
    bool useGPU = true;

    // Model architecture (must be populated for K2 and non-default models)
    size_t hiddenDim = 4096;
    size_t numLayers = 32;
    size_t numHeads = 32;
    size_t numKVHeads = 32;
    size_t headDim = 128;
    size_t vocabSize = 32000;
    size_t intermediateDim = 11008;
    bool   useMLA = false;      // true = use MLA factorized attention (K2)
    float  normEps = 1e-6f;
    float  ropeTheta = 10000.0f;
    float  ropeScaling = 1.0f;
};

// ============================================================================
// Engine Status
// ============================================================================
enum class EngineStatus : uint8_t {
    Uninitialized = 0,
    Initializing,
    Ready,
    Generating,
    Error
};

// ============================================================================
// Generation Callback
// ============================================================================
using TokenCallback = std::function<void(const char* token, uint32_t index)>;
using ErrorCallback = std::function<void(const char* message)>;

// ============================================================================
// Deep2Bridge — Native binding to Deep2Engine
// ============================================================================
class Deep2Bridge {
public:
    static Deep2Bridge& Get();

    bool Initialize(const EngineConfig& config);
    void Shutdown();

    EngineStatus GetStatus() const { return m_status; }
    const EngineConfig& GetConfig() const { return m_config; }

    // Model lifecycle
    bool LoadModel(const char* path);
    void UnloadModel();
    bool IsModelLoaded() const { return m_modelLoaded; }

    // Generation
    bool Generate(const char* prompt, TokenCallback onToken, ErrorCallback onError);
    bool GenerateStream(const char* prompt, TokenCallback onToken, ErrorCallback onError);
    void CancelGeneration();
    bool IsGenerating() const { return m_generating; }

    // Metrics
    struct Metrics {
        double tokensPerSecond = 0.0;
        uint64_t totalTokens = 0;
        uint64_t totalTimeUs = 0;
        double avgLatencyMs = 0.0;
    };
    Metrics GetMetrics() const;

    // Session management
    void ResetSession();
    uint32_t GetSessionId() const { return m_sessionId; }

    // Backend selection
    void SetBackend(InferenceBackend backend);
    InferenceBackend GetBackend() const { return m_backend; }

private:
    Deep2Bridge() = default;
    ~Deep2Bridge();
    Deep2Bridge(const Deep2Bridge&) = delete;
    Deep2Bridge& operator=(const Deep2Bridge&) = delete;

    EngineConfig m_config;
    EngineStatus m_status = EngineStatus::Uninitialized;
    bool m_modelLoaded = false;
    bool m_generating = false;
    uint32_t m_sessionId = 0;
    Metrics m_metrics = {};

    // Backend selection
    InferenceBackend m_backend = InferenceBackend::Deep2Engine;

    // Real Deep2 inference engine instance
    std::unique_ptr<Deep2::Deep2Engine> m_engine;

    // LlamaNative bridge instance (alternative backend)
    std::unique_ptr<LlamaNativeBridge> m_llamaBridge;
};

} // namespace rawr

#endif // DEEP2_BRIDGE_HPP
