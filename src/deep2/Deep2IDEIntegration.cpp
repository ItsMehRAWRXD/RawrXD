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
#include "IOCPGGUFLoader.hpp"
#include "ElasticResidencyManager.hpp"

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
std::unique_ptr<IOCPGGUFLoader> Deep2ModelLoader::s_iocpLoader;
std::unique_ptr<ElasticResidencyManager> Deep2ModelLoader::s_elastic;
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

    // Create router, add shard, and scan (metadata only)
    s_router = std::make_unique<GGUFShardRouter>();
    s_router->add_shard(path);
    s_router->scan();

    // Build fabric
    s_fabric = std::make_unique<FabricTensorTable>();
    s_fabric->ingest_gguf_router(*s_router);

    // Initialize Elastic Residency Manager for out-of-core operation
    s_elastic = std::make_unique<ElasticResidencyManager>();
    s_elastic->Initialize({
        .maxWarmCompressedBytes = 48ULL * 1024 * 1024 * 1024, // 48 GB RAM
        .maxWarmStagedBytes = 2ULL * 1024 * 1024 * 1024,     // 2 GB staging
        .maxHotBytes = 28ULL * 1024 * 1024 * 1024,           // 28 GB VRAM (leave headroom)
        .prefetchLookahead = 2,
        .useQuantizedGpuPath = true
    });

    // Open GGUF with IOCP for explicit async reads (no memory mapping)
    s_iocpLoader = std::make_unique<IOCPGGUFLoader>();
    IOCPGGUFLoader::Config iocpCfg;
    iocpCfg.useIOCP = true;
    iocpCfg.noBuffering = true;
    iocpCfg.extentSize = 64 * 1024 * 1024;  // 64 MB read extents
    iocpCfg.maxConcurrentReads = 8;
    iocpCfg.registerWithElastic = true;
    iocpCfg.verbose = false;

    if (!s_iocpLoader->Open(path, iocpCfg)) {
        result.error = "Failed to open GGUF with IOCP: " + path;
        Unload();
        return result;
    }

    // Parse header and register tensors with Elastic (metadata only, no data loaded yet)
    ModelMetadata meta;
    std::vector<TensorInfo> tensors;
    uint64_t dataOffset = 0;
    if (!s_iocpLoader->ParseHeader(meta, tensors, dataOffset)) {
        result.error = "Failed to parse GGUF header: " + path;
        Unload();
        return result;
    }

    s_iocpLoader->SetElasticManager(s_elastic.get());
    if (!s_iocpLoader->LoadTensorDataAsync(tensors, dataOffset)) {
        result.error = "Failed to register tensors with Elastic Residency";
        Unload();
        return result;
    }

    // Extract metadata
    result.success = true;
    result.modelName = fs::path(path).filename().string();
    result.shardCount = 1;
    result.tensorCount = static_cast<uint32_t>(tensors.size());
    result.totalFileBytes = fs::file_size(path);
    result.streamingEnabled = true;
    result.numLayers = meta.numLayers;
    result.numExperts = meta.numExperts;
    result.context_length = meta.maxPositionEmbeddings;

    // Detect MoE from tensor names
    for (const auto& t : tensors) {
        if (t.name.find("expert") != std::string::npos ||
            t.name.find("gate") != std::string::npos) {
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

    // Create router, add all shards, and scan
    s_router = std::make_unique<GGUFShardRouter>();
    for (const auto& shard : shards) {
        s_router->add_shard(shard);
    }
    s_router->scan();

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

    // Extract metadata from GGUF header (first shard)
    const auto& meta = s_router->metadata();
    if (meta.has_metadata) {
        result.numLayers = meta.layer_count;
        result.numExperts = meta.expert_count;
        result.context_length = meta.context_length;
        // Store additional metadata for downstream consumers
        s_lastResult = result;  // Will be overwritten below, but keeps metadata accessible
    } else {
        // Fallback: extract layer count from tensor names
        uint32_t maxLayer = 0;
        for (const auto& [name, loc] : s_router->tensors()) {
            if (name.size() > 4 && name.substr(0, 4) == "blk.") {
                int layer = std::atoi(name.c_str() + 4);
                if (layer > (int)maxLayer) maxLayer = layer;
            }
        }
        result.numLayers = maxLayer + 1;
    }

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
    
    m_engine = std::make_unique<Deep2Engine>();
    EngineConfig engineCfg;
    
    // Propagate actual K2 metadata from loader result (Gate 7 fix)
    // If metadata was extracted from GGUF header, use it; otherwise keep defaults
    if (model.numLayers > 0) {
        engineCfg.numLayers = model.numLayers;
    }
    if (model.numExperts > 0) {
        // K2 uses MoE; experts are handled by the MoE router, not EngineConfig directly
        // but we can store this for validation
    }
    
    // Try to get richer metadata from the router if available
    auto* router = Deep2ModelLoader::GetRouter();
    if (router && router->metadata().has_metadata) {
        const auto& meta = router->metadata();
        if (meta.hidden_size > 0)   engineCfg.hiddenDim = meta.hidden_size;
        if (meta.head_count > 0)   engineCfg.numHeads = meta.head_count;
        if (meta.head_count_kv > 0) engineCfg.numKVHeads = meta.head_count_kv;
        if (meta.ffn_dim > 0)      engineCfg.intermediateDim = meta.ffn_dim;
        if (meta.vocab_size > 0)   engineCfg.vocabSize = meta.vocab_size;
        if (meta.context_length > 0) engineCfg.maxSeqLen = meta.context_length;
    }
    
    engineCfg.useKVCache = true;
    engineCfg.useRoPE = true;
    engineCfg.useThreadPool = true;
    
    if (!m_engine->initialize(engineCfg)) {
        return false;
    }

    m_ready = true;
    return true;
}

void Deep2InferenceSession::Shutdown() {
    m_ready = false;
}

Deep2InferenceSession::GenerationResult Deep2InferenceSession::Generate(
    const std::string& prompt) {
    GenerationResult result;
    if (!m_ready || !m_engine) {
        result.finishReason = "not_ready";
        return result;
    }

    m_cancelled.store(false);
    auto t0 = std::chrono::high_resolution_clock::now();

    ::Deep2::InferenceStats stats;
    std::string accumulated;
    
    std::vector<int> promptTokens = m_engine->tokenize(prompt);
    std::vector<int> outputTokens(m_config.maxContextLength);
    
    size_t generated = m_engine->generate(promptTokens.data(), promptTokens.size(),
                                          outputTokens.data(), m_config.maxContextLength,
                                          &stats,
                                          [&](int token) {
                                              return !m_cancelled.load();
                                          });

    outputTokens.resize(generated);
    accumulated = m_engine->detokenize(outputTokens);

    auto t1 = std::chrono::high_resolution_clock::now();
    auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

    result.text = accumulated;
    result.tokensGenerated = static_cast<uint32_t>(stats.tokensGenerated);
    result.latencyMs = stats.latencyMs * stats.tokensGenerated;
    result.tokensPerSecond = stats.tokensPerSecond;
    result.finishReason = m_cancelled.load() ? "cancelled" : "stop";

    return result;
}

bool Deep2InferenceSession::GenerateStream(const std::string& prompt,
                                           TokenCallback callback) {
    if (!m_ready || !m_engine) return false;

    m_cancelled.store(false);
    
    std::vector<int> promptTokens = m_engine->tokenize(prompt);
    std::vector<int> outputTokens(m_config.maxContextLength);
    
    m_engine->generate(promptTokens.data(), promptTokens.size(),
                       outputTokens.data(), m_config.maxContextLength,
                       nullptr,
                       [&](int token) {
                           if (m_cancelled.load()) return false;
                           
                           std::vector<int> t = {token};
                           std::string text = m_engine->detokenize(t);
                           
                           if (callback) {
                               callback(text, false);
                           }
                           
                           return true;
                       });
                       
    if (callback) {
        callback("", true);
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

    // Add GGUF metadata if available (Gate 7 certification)
    const auto& meta = router->metadata();
    if (meta.has_metadata) {
        json metaJson;
        metaJson["layer_count"] = meta.layer_count;
        metaJson["hidden_size"] = meta.hidden_size;
        metaJson["head_count"] = meta.head_count;
        metaJson["head_count_kv"] = meta.head_count_kv;
        metaJson["context_length"] = meta.context_length;
        metaJson["ffn_dim"] = meta.ffn_dim;
        metaJson["expert_count"] = meta.expert_count;
        metaJson["expert_used_count"] = meta.expert_used_count;
        metaJson["vocab_size"] = meta.vocab_size;
        metaJson["rope_theta"] = meta.rope_theta;
        metaJson["norm_eps"] = meta.norm_eps;
        metaJson["architecture"] = meta.architecture;
        metaJson["model_name"] = meta.model_name;
        j["metadata"] = metaJson;
    }

    return j.dump();
}

} // namespace RawrXD
