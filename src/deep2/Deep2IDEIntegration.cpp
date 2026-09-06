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
#include "execution_policy/PolicyApply.hpp"
#include "execution_policy/LearnedProfileStore.hpp"
#include "execution_policy/ExecutionPolicyBridge.hpp"
#include "execution_policy/ExecutionPolicyApply.hpp"
#include "execution_policy/ObservationBuilder.hpp"
#include "execution_policy/HostRamTelemetry.hpp"

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

using namespace ::Deep2;

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

std::string ToLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool HasGGUFExtension(const fs::path& p) {
    return ToLowerCopy(p.extension().string()) == ".gguf";
}

bool LooksLikeShardedGGUF(const fs::path& p) {
    const std::string lowerName = ToLowerCopy(p.filename().string());
    return lowerName.find("-of-") != std::string::npos && HasGGUFExtension(p);
}

std::vector<std::string> CollectGGUFFiles(const std::string& dir, bool preferSharded) {
    std::vector<fs::path> all;
    std::vector<fs::path> sharded;

    try {
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (!entry.is_regular_file()) continue;
            const fs::path p = entry.path();
            if (!HasGGUFExtension(p)) continue;
            all.push_back(p);
            if (LooksLikeShardedGGUF(p)) {
                sharded.push_back(p);
            }
        }
    } catch (...) {
        return {};
    }

    auto byFilename = [](const fs::path& a, const fs::path& b) {
        return ToLowerCopy(a.filename().string()) < ToLowerCopy(b.filename().string());
    };
    std::sort(all.begin(), all.end(), byFilename);
    std::sort(sharded.begin(), sharded.end(), byFilename);

    const auto& selected = (preferSharded && !sharded.empty()) ? sharded : all;
    std::vector<std::string> out;
    out.reserve(selected.size());
    for (const auto& p : selected) {
        out.push_back(p.string());
    }
    return out;
}

} // namespace

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
    std::string filename = ToLowerCopy(fs::path(path).filename().string());
    return filename.find("-of-") != std::string::npos;
}

bool Deep2ModelLoader::DetectKimiK2Shards(const std::string& dir,
                                          std::vector<std::string>& outShards) {
    outShards = CollectGGUFFiles(dir, true);
    return !outShards.empty();
}

Deep2ModelLoader::LoadResult Deep2ModelLoader::Load(const std::string& path) {
    std::lock_guard<std::mutex> lock(s_mutex);

    // Unload previous (already hold s_mutex ? do not call Unload())
    ResetLocked();

    LoadResult result;
    result.success = false;

    if (path.empty()) {
        result.error = "Empty model path";
        s_lastResult = result;
        return result;
    }

    // Determine if sharded
    if (IsShardedModel(path)) {
        const DWORD attr = GetFileAttributesA(path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            result = LoadShardedDirectory(path);
        } else {
            result = LoadShardedDirectory(fs::path(path).parent_path().string());
        }
    } else {
        result = LoadSingleFile(path);
    }

    s_lastResult = result;
    return result;
}

Deep2ModelLoader::LoadResult Deep2ModelLoader::LoadSingleFile(const std::string& path) {
    LoadResult result;
    result.success = false;

    try {
        // Validate file exists
        DWORD attr = GetFileAttributesA(path.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            result.error = "File not found: " + path;
            return result;
        }

        // Fail-closed on ExecutionPolicy before any residency allocation.
        {
            using namespace ::Deep2::Exec;
            EnsurePolicyLoaded();
            const auto v = Validate(ActivePolicy());
            if (!v.ok) {
                result.error = std::string("POLICY_CHANGE_REJECTED: ") + v.detail;
                return result;
            }
        }

        const ElasticResidencyConfig elasticCfg =
            ::Deep2::Exec::ElasticFromPolicy(::Deep2::Exec::ActivePolicy());
        s_elastic = std::make_unique<ElasticResidencyManager>();
        s_elastic->Initialize(elasticCfg);

        // IOCP streamer first ? metadata via sync fopen; weights stay on NVMe
        // until Elastic.Acquire (no full-model materialize).
        s_iocpLoader = std::make_unique<IOCPGGUFLoader>();
        IOCPGGUFLoader::Config iocpCfg;
        iocpCfg.useIOCP = true;
        {
            const auto& pol = ::Deep2::Exec::ActivePolicy();
            iocpCfg.noBuffering = pol.streaming.directIo.present
                                      ? pol.streaming.directIo.value
                                      : false;
            iocpCfg.extentSize = pol.streaming.chunkSize.present
                                     ? static_cast<size_t>((std::min)(
                                           pol.streaming.chunkSize.value.n,
                                           256ULL << 20))
                                     : (64ull * 1024ull * 1024ull);
            iocpCfg.maxConcurrentReads = pol.streaming.queueDepth.present
                                             ? static_cast<size_t>((std::max)(
                                                   1, pol.streaming.queueDepth.value))
                                             : 8u;
        }
        iocpCfg.registerWithElastic = true;
        iocpCfg.verbose = false;

        if (!s_iocpLoader->Open(path, iocpCfg)) {
            result.error = "Failed to open GGUF with IOCP: " + path;
            ResetLocked();
            return result;
        }

        ModelMetadata meta;
        std::vector<TensorInfo> tensors;
        uint64_t dataOffset = 0;
        if (!s_iocpLoader->ParseHeader(meta, tensors, dataOffset)) {
            result.error = "Failed to parse GGUF header: " + path;
            ResetLocked();
            return result;
        }

        s_iocpLoader->SetElasticManager(s_elastic.get());
        if (!s_iocpLoader->LoadTensorDataAsync(tensors, dataOffset)) {
            result.error = "Failed to register tensors with Elastic Residency";
            ResetLocked();
            return result;
        }

        // Optional router/fabric ? must not abort streaming open on throw.
        try {
            s_router = std::make_unique<GGUFShardRouter>();
            s_router->add_shard(path);
            s_router->scan();
            s_fabric = std::make_unique<FabricTensorTable>();
            s_fabric->ingest_gguf_router(*s_router);
        } catch (const std::exception& e) {
            s_router.reset();
            s_fabric.reset();
            // Streamer path already registered tensors; continue.
            (void)e;
        }

        result.success = true;
        result.modelPath = path;
        result.modelName = fs::path(path).filename().string();
        result.shardCount = 1;
        result.tensorCount = static_cast<uint32_t>(tensors.size());
        result.totalFileBytes = fs::file_size(path);
        result.streamingEnabled = true; // single-file path is always stream-capable
        result.numLayers = meta.numLayers;
        result.numExperts = meta.numExperts;
        result.context_length = meta.maxPositionEmbeddings;

        for (const auto& t : tensors) {
            if (t.name.find("expert") != std::string::npos ||
                t.name.find("gate") != std::string::npos) {
                result.isMoE = true;
                break;
            }
        }

        {
            using namespace ::Deep2::Exec;
            auto apply = EnforcePolicyOnIdeLoad(
                s_elastic.get(), path,
                static_cast<int>(result.numLayers),
                result.tensorCount);
            if (apply.overBudgetFailClosed) {
                result.success = false;
                result.error = apply.detail;
                ResetLocked();
                return result;
            }
        }

        return result;
    } catch (const std::exception& e) {
        result.success = false;
        result.error = std::string("LoadSingleFile exception: ") + e.what();
        ResetLocked();
        return result;
    } catch (...) {
        result.success = false;
        result.error = "LoadSingleFile unknown exception";
        ResetLocked();
        return result;
    }
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
    result.modelPath = path;
    result.modelName = fs::path(path).filename().string();
    result.shardCount = static_cast<uint32_t>(shards.size());
    result.tensorCount = static_cast<uint32_t>(s_router->tensor_count());
    result.streamingEnabled = true;
    result.isMoE = false;

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
        result.isMoE = (meta.expert_count > 0 && meta.expert_used_count > 0);
        result.modelFamily = meta.architecture;
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

    if (!result.isMoE) {
        for (const auto& [name, loc] : s_router->tensors()) {
            (void)loc;
            if (name.find("expert") != std::string::npos ||
                name.find("ffn_gate_exps") != std::string::npos) {
                result.isMoE = true;
                break;
            }
        }
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

::Deep2::ElasticResidencyManager* Deep2ModelLoader::GetElastic() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_elastic.get();
}

const ::Deep2::Exec::PlacementApplyReport*
Deep2ModelLoader::GetLastPolicyApplyReport() {
    return &::Deep2::Exec::LastApplyReport();
}

void Deep2ModelLoader::ResetLocked() {
    s_router.reset();
    s_fabric.reset();
    s_iocpLoader.reset();
    s_elastic.reset();
    s_lastResult = LoadResult{};
}

void Deep2ModelLoader::Unload() {
    std::lock_guard<std::mutex> lock(s_mutex);
    ResetLocked();
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

Deep2InferenceSession::SessionConfig
Deep2InferenceSession::SessionConfig::FromActivePolicy() {
    using namespace ::Deep2::Exec;
    EnsurePolicyLoaded();
    SessionConfig c{};
    const auto& p = ActivePolicy();
    if (const int ctx = PolicyContextTokens(); ctx > 0)
        c.maxContextLength = static_cast<uint32_t>(ctx);
    if (p.memory.vramBudget.present)
        c.vramBudgetBytes = p.memory.vramBudget.value.n;
    c.enableStreaming = PolicyStreamingEnabled();
    return c;
}

bool Deep2InferenceSession::Initialize(const Deep2ModelLoader::LoadResult& model,
                                       const SessionConfig& cfg) {
    if (!model.success) {
        return false;
    }

    m_modelName = model.modelName;
    // Full path required for loadModel (tokenizer + weights). Filename alone fails.
    m_modelPath = !model.modelPath.empty() ? model.modelPath : model.modelName;

    // Merge caller cfg with ActivePolicy hard caps (policy wins on budgets).
    using namespace ::Deep2::Exec;
    EnsurePolicyLoaded(model.modelName.empty() ? std::string{}
                                               : (std::string("name:") + model.modelName));
    m_config = cfg;
    const auto& pol = ActivePolicy();
    if (const uint64_t hard = PolicyVramHardCapBytes(); hard > 0)
        m_config.vramBudgetBytes = (std::min)(m_config.vramBudgetBytes, hard);
    else if (pol.memory.vramBudget.present)
        m_config.vramBudgetBytes = pol.memory.vramBudget.value.n;
    if (const int ctx = PolicyContextTokens(); ctx > 0)
        m_config.maxContextLength =
            (std::min)(m_config.maxContextLength, static_cast<uint32_t>(ctx));
    if (pol.streaming.enabled.present)
        m_config.enableStreaming = pol.streaming.enabled.value;
    
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

    // E2E: bind tokenizer + weights. Streaming open registered residency; generate
    // still requires Deep2Engine::loadModel on the same GGUF path.
    if (m_modelPath.empty() || !m_engine->loadModel(m_modelPath)) {
        m_ready = false;
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

    if (m_engine) {
        if (auto* mars = m_engine->getMARSController()) {
            if (auto* vm = mars->GetVRAMManager())
                vm->ResetRunPeaks();
        }
    }
    ::Deep2::GlobalTelemetry().resetRun();
    ::Deep2::Exec::ResetRunRamPeaks();

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
    ::Deep2::Exec::SampleRunRamPeaks();

    result.text = accumulated;
    result.tokensGenerated = static_cast<uint32_t>(stats.tokensGenerated);
    result.latencyMs = stats.latencyMs * stats.tokensGenerated;
    result.tokensPerSecond = stats.tokensPerSecond;
    result.finishReason = m_cancelled.load() ? "cancelled" : "stop";

    // INV-3/4: observation from live telemetry ? recordSuccess (profiles only).
    // Must NOT call EnsurePolicyLoaded() here: store.load() clears session_
    // overlays and mutates ActivePolicy() after the certified load seam.
    if (result.finishReason == "stop" && result.tokensPerSecond > 0.0) {
        using namespace ::Deep2::Exec;
        auto& hw = ActiveHardwareSnapshot();
        if (hw.fingerprint.empty() && hw.gpus.empty()) {
            const auto& pol = ActivePolicy();
            if (pol.memory.vramBudget.present) {
                GpuTopo g0;
                g0.index = 0;
                g0.name = "gpu0";
                g0.vramBytes = pol.memory.vramBudget.value.n;
                hw.gpus.push_back(g0);
            }
            if (pol.memory.ramBudget.present)
                hw.ramBytes = pol.memory.ramBudget.value.n;
            hw.fingerprint = MakeHardwareFingerprint(hw);
        }
        std::string mfp = ExecutionPolicyStore::Instance().modelFingerprint();
        if (mfp.empty() && !m_modelPath.empty())
            mfp = std::string("path:") + m_modelPath;

        auto* mars = m_engine ? m_engine->getMARSController() : nullptr;
        if (mars) {
            PlacementApplyReport obsReport;
            ObserveMatchesPlan(*mars, LastPlacementPlan(), obsReport);
            LastApplyReport() = obsReport;
        }

        ExecutionObservation obs = BuildObservation(
            hw, mfp, m_modelName, /*quant*/ "", result.tokensPerSecond,
            stats.latencyMs, /*completed*/ true, /*outputValid*/ true,
            ActivePolicy(), mars);
        LearnedProfileStore::Instance().recordSuccess(obs);
    }

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
    // Same as IDE path ? unified loader
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
