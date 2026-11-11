// ============================================================================
// Deep2IDEIntegration.hpp
// ----------------------------------------------------------------------------
// Bridges RawrXD IDE (HeadlessIDE / AgenticBridge) to Deep2 Sovereign Engine
// with GGUFShardRouter multi-shard support for Kimi K2 / Moonshot models.
//
// Integration points:
//   - HeadlessIDE::loadModel()  -> Deep2ModelLoader::Load()
//   - AgenticBridge::LoadModel() -> Deep2ModelLoader::Load()
//   - Deep2Engine::loadModel()   -> ShardRouter + ResidencyFabric
//
// Memory posture: router metadata only (~100KB), no eager tensor loading.
// ============================================================================
#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <optional>
#include <vector>
#include <cstdint>

#include "GGUFShardRouter.hpp"
#include "GGUFShardRouter_lanes.hpp"
#include "FabricTensorTable.hpp"

namespace Deep2 { class Deep2Engine; }

namespace RawrXD {

// ============================================================================
// Deep2ModelLoader — unified entry point for IDE + Deep2 engine
// ============================================================================
class Deep2ModelLoader {
public:
    struct LoadResult {
        bool success = false;
        std::string error;
        std::string modelName;
        std::string modelFamily;
        uint64_t parameterCount = 0;
        uint32_t numLayers = 0;
        uint32_t numExperts = 0;
        uint64_t totalFileBytes = 0;
        uint32_t shardCount = 0;
        uint32_t tensorCount = 0;
        bool isMoE = false;
        bool streamingEnabled = false;
    };

    // Load a model path. Supports:
    //   - Single .gguf file
    //   - Directory containing sharded .gguf files (Kimi K2 style)
    //   - Ollama model reference (resolved to local path)
    static LoadResult Load(const std::string& path);

    // Check if path is a multi-shard model directory
    static bool IsShardedModel(const std::string& path);

    // Get the singleton shard router for the currently loaded model
    static GGUFShardRouter* GetRouter();

    // Get the fabric tensor table for residency management
    static FabricTensorTable* GetFabric();

    // Unload current model, free router + fabric state
    static void Unload();

    // Query if a specific tensor is available (fast, no IO)
    static bool HasTensor(std::string_view tensorName);

    // Get tensor info without loading data
    static std::optional<GGUFShardRouter::TensorLocation> GetTensorInfo(std::string_view tensorName);

private:
    static std::unique_ptr<GGUFShardRouter> s_router;
    static std::unique_ptr<FabricTensorTable> s_fabric;
    static LoadResult s_lastResult;
    static std::mutex s_mutex;

    static LoadResult LoadSingleFile(const std::string& path);
    static LoadResult LoadShardedDirectory(const std::string& path);
    static bool DetectKimiK2Shards(const std::string& dir, std::vector<std::string>& outShards);
};

// ============================================================================
// Deep2InferenceSession — wraps Deep2Engine with shard-aware tensor streaming
// ============================================================================
class Deep2InferenceSession {
public:
    struct SessionConfig {
        uint32_t maxContextLength = 131072;
        uint32_t gpuDevice = 0;           // 0 = R9700 primary
        uint64_t vramBudgetBytes = 32ULL * 1024 * 1024 * 1024; // 32GB
        bool enableStreaming = true;
        bool enableMoERouting = true;
        uint32_t activeExpertWindow = 8;  // keep 8 experts hot
    };

    struct GenerationResult {
        std::string text;
        uint32_t tokensGenerated = 0;
        double tokensPerSecond = 0.0;
        double latencyMs = 0.0;
        std::string finishReason;
    };

    bool Initialize(const Deep2ModelLoader::LoadResult& model, const SessionConfig& cfg);
    void Shutdown();

    // Generate text from prompt (blocking)
    GenerationResult Generate(const std::string& prompt);

    // Generate with streaming callback
    using TokenCallback = std::function<void(const std::string& token, bool done)>;
    bool GenerateStream(const std::string& prompt, TokenCallback callback);

    // Cancel ongoing generation
    void Cancel();

    bool IsReady() const { return m_ready; }

private:
    bool m_ready = false;
    SessionConfig m_config;
    std::atomic<bool> m_cancelled{false};
    std::unique_ptr<Deep2::Deep2Engine> m_engine;
};

// ============================================================================
// IDE Integration Helpers
// ============================================================================

// Call from HeadlessIDE::loadModel() to route through Deep2
bool Deep2LoadModelForIDE(const std::string& path, std::string& outError);

// Call from AgenticBridge::LoadModel() to route through Deep2
bool Deep2LoadModelForBridge(const std::string& path, std::string& outError);

// Get model info for IDE status display
std::string Deep2GetModelStatusJSON();

// Forward declare Deep2Engine for IDE integration
namespace Deep2 { class Deep2Engine; }

} // namespace RawrXD
