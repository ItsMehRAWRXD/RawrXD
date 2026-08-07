// ============================================================================
// Deep2IDEIntegration.cpp
// ----------------------------------------------------------------------------
// Implementation of Deep2 <-> IDE bridge with GGUFShardRouter integration.
// Connects HeadlessIDE + AgenticBridge to Deep2 Sovereign Engine for
// Kimi K2 / Moonshot multi-shard model loading.
// ============================================================================

#include "Deep2IDEIntegration.hpp"
#include "Deep2Engine.h"
#include "Deep2Bridge.hpp"
#include "GGUFShardRouter.hpp"
#include "FabricTensorTable.hpp"

#include <cstdio>
#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace Deep2;

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace RawrXD {

// ============================================================================
// Static state
// ============================================================================
std::unique_ptr<GGUFShardRouter> Deep2ModelLoader::s_router;
std::unique_ptr<FabricTensorTable> Deep2ModelLoader::s_fabric;
Deep2ModelLoader::LoadResult Deep2ModelLoader::s_lastResult;
std::mutex Deep2ModelLoader::s_mutex;

// ============================================================================
// Deep2ModelLoader implementation
// ============================================================================

bool Deep2ModelLoader::IsShardedModel(const std::string& path) {
    if (path.empty()) return false;

    // If it's a directory, check for shard patterns
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::vector<std::string> shards;
        return DetectKimiK2Shards(path, shards);
    }

    // If it's a single file, check if filename contains shard pattern
    std::string filename = fs::path(path).filename().string();
    return filename.find("-of-") != std::string::npos;
}

bool Deep2ModelLoader::DetectKimiK2Shards(const std::string& dir,
                                          std::vector<std::string>& outShards) {
    outShards.clear();

    // Look for Kimi K2 naming: kimi-k2-instruct-0905-q4_k_m-00001-of-00013.gguf
    for (int i = 1; i <= 13; ++i) {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "kimi-k2-instruct-0905-q4_k_m-%05d-of-00013.gguf", i);
        fs::path p = fs::path(dir) / buf;
        if (fs::exists(p)) {
            outShards.push_back(p.string());
        }
    }

    // Also try generic pattern: model-00001-of-00013.gguf
    if (outShards.empty()) {
        for (int i = 1; i <= 13; ++i) {
            char buf[256];
            std::snprintf(buf, sizeof(buf),
                "model-%05d-of-00013.gguf", i);
            fs::path p = fs::path(dir) / buf;
            if (fs::exists(p)) {
                outShards.push_back(p.string());
            }
        }
    }

    return !outShards.empty();
}

Deep2ModelLoader::LoadResult Deep2ModelLoader::Load(const std::string& path) {
    std::lock_guard<std::mutex> lock(s_mutex);

    // Unload previous
    Unload();

    LoadResult result;
    result.success = false;

    if (path.empty()) {
        result.error = "Empty model path";
        s_lastResult = result;
        return result;
    }

    // Determine if sharded
    if (IsShardedModel(path)) {
        result = LoadShardedDirectory(path);
    } else {
        result = LoadSingleFile(path);
    }

    s_lastResult = result;
    return result;
}

Deep2ModelLoader::LoadResult Deep2ModelLoader::LoadSingleFile(const std::string& path) {
    LoadResult result;
    result.success = false;

    // Validate file exists
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        result.error = "File not found: " + path;
        return result;
    }

    // Create router and add single shard
    s_router = std::make_unique<GGUFShardRouter>();
    s_router->add_shard(path);

    // Build fabric
    s_fabric = std::make_unique<FabricTensorTable>();
    s_fabric->ingest_gguf_router(*s_router);

    // Extract metadata from first tensor
    result.success = true;
    result.modelName = fs::path(path).filename().string();
    result.shardCount = 1;
    result.tensorCount = static_cast<uint32_t>(s_router->tensor_count());
    result.totalFileBytes = fs::file_size(path);
    result.streamingEnabled = true;

    // Try to detect MoE from tensor names
    for (const auto& [name, loc] : s_router->tensors()) {
        if (name.find("expert") != std::string::npos ||
            name.find("gate") != std::string::npos) {
            result.isMoE = true;
            break;
        }
    }

    return result;
}

Deep2ModelLoader::LoadResult Deep2ModelLoader::LoadShardedDirectory(const std::string& path) {
    LoadResult result;
    result.success = false;

    std::vector<std::string> shards;
    if (!DetectKimiK2Shards(path, shards)) {
        result.error = "No GGUF shards found in: " + path;
        return result;
    }

    // Create router and add all shards
    s_router = std::make_unique<GGUFShardRouter>();
    for (const auto& shard : shards) {
        s_router->add_shard(shard);
    }

    // Build fabric
    s_fabric = std::make_unique<FabricTensorTable>();
    s_fabric->ingest_gguf_router(*s_router);

    // Compute totals
    result.success = true;
    result.modelName = fs::path(path).filename().string();
    result.shardCount = static_cast<uint32_t>(shards.size());
    result.tensorCount = static_cast<uint32_t>(s_router->tensor_count());
    result.streamingEnabled = true;
    result.isMoE = true;  // Kimi K2 is MoE

    // Sum file sizes
    for (const auto& shard : shards) {
        result.totalFileBytes += fs::file_size(shard);
    }

    // Try to extract layer count from tensor names
    uint32_t maxLayer = 0;
    for (const auto& [name, loc] : s_router->tensors()) {
        if (name.size() > 4 && name.substr(0, 4) == "blk.") {
            int layer = std::atoi(name.c_str() + 4);
            if (layer > (int)maxLayer) maxLayer = layer;
        }
    }
    result.numLayers = maxLayer + 1;

    return result;
}

GGUFShardRouter* Deep2ModelLoader::GetRouter() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_router.get();
}

FabricTensorTable* Deep2ModelLoader::GetFabric() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_fabric.get();
}

void Deep2ModelLoader::Unload() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_router.reset();
    s_fabric.reset();
    s_lastResult = LoadResult{};
}

bool Deep2ModelLoader::HasTensor(std::string_view tensorName) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_router) return false;
    return s_router->find(tensorName) != nullptr;
}

std::optional<GGUFShardRouter::TensorLocation> Deep2ModelLoader::GetTensorInfo(std::string_view tensorName) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_router) return std::nullopt;
    auto* loc = s_router->find(tensorName);
    if (!loc) return std::nullopt;
    return *loc;
}

// ============================================================================
// Deep2InferenceSession implementation
// ============================================================================

bool Deep2InferenceSession::Initialize(const Deep2ModelLoader::LoadResult& model,
                                       const SessionConfig& cfg) {
    if (!model.success) {
        return false;
    }

    m_config = cfg;
    m_ready = true;
    return true;
}

void Deep2InferenceSession::Shutdown() {
    m_ready = false;
}

Deep2InferenceSession::GenerationResult Deep2InferenceSession::Generate(
    const std::string& prompt) {
    GenerationResult result;
    if (!m_ready) {
        result.finishReason = "not_ready";
        return result;
    }

    m_cancelled.store(false);
    auto t0 = std::chrono::high_resolution_clock::now();

    // Placeholder generation - returns prompt echoed back
    std::string accumulated = "[Deep2InferenceSession: Generation not yet wired to Deep2Engine] Prompt: " + prompt;
    uint32_t tokenCount = static_cast<uint32_t>(accumulated.length());

    auto t1 = std::chrono::high_resolution_clock::now();
    auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    result.text = accumulated;
    result.tokensGenerated = tokenCount;
    result.latencyMs = elapsedUs / 1000.0;
    result.tokensPerSecond = tokenCount > 0
        ? (tokenCount * 1000000.0 / elapsedUs)
        : 0.0;
    result.finishReason = "stop";

    return result;
}

bool Deep2InferenceSession::GenerateStream(const std::string& prompt,
                                           TokenCallback callback) {
    if (!m_ready) return false;

    m_cancelled.store(false);
    
    // Placeholder: invoke callback with prompt tokens
    if (callback) {
        callback(prompt.c_str(), false);
    }
    
    return true;
}

void Deep2InferenceSession::Cancel() {
    m_cancelled.store(true);
}

// ============================================================================
// IDE Integration Helpers
// ============================================================================

bool Deep2LoadModelForIDE(const std::string& path, std::string& outError) {
    auto result = Deep2ModelLoader::Load(path);
    if (!result.success) {
        outError = result.error;
        return false;
    }
    return true;
}

bool Deep2LoadModelForBridge(const std::string& path, std::string& outError) {
    // Same as IDE path — unified loader
    return Deep2LoadModelForIDE(path, outError);
}

std::string Deep2GetModelStatusJSON() {
    auto* router = Deep2ModelLoader::GetRouter();
    if (!router) {
        return "{\"loaded\":false}";
    }

    json j;
    j["loaded"] = true;
    j["shards"] = router->shard_count();
    j["tensors"] = router->tensor_count();

    auto* fabric = Deep2ModelLoader::GetFabric();
    if (fabric) {
        j["fabric_entries"] = fabric->size();
    }

    return j.dump();
}

} // namespace RawrXD
