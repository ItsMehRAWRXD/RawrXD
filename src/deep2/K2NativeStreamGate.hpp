// k2_native_stream_gate.hpp — K2NativeStream gate for k2_runtime_validation Gate 10
// Bounded partial-forward: real Q4_K embed, streamed MLA layers, Q6_K logits.
// Does NOT modify or replace the certified K2-008 harness baseline.

#pragma once

#include "KimiK2Config.hpp"
#include "K2GlobalTensorIndex.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace K2NativeStreamGate {

struct Config {
    std::string prompt = "hello";
    uint32_t streamTokens = 1;
    uint32_t layerDepth = 4;
    uint64_t budgetBytes = 256ull * 1024 * 1024;
    bool enableMlaComplete = false; // Gate 12: RoPE/softmax/KV (additive)
};

struct Result {
    bool ok = false;
    std::string error;
    uint32_t shardsDiscovered = 0;
    uint32_t layerDepth = 0;
    uint64_t peakResidencyBytes = 0;
    uint64_t finalResidencyBytes = 0;
    bool streamingCallbackFired = false;
    bool outputNonempty = false;
    int32_t promptTokenId = -1;
    int32_t generatedTokenId = -1;
    std::string generatedText;
    // Gate 12 telemetry (meaningful only when enableMlaComplete)
    bool ropeApplied = false;
    bool softmaxFinite = false;
    bool kvCacheWrite = false;
    bool kvCacheRead = false;
    uint32_t kvLength = 0;
};

Result Run(const std::filesystem::path& shardDir,
           const Deep2::GlobalTensorIndex& index,
           const Deep2::KimiK2Config& k2cfg,
           const std::vector<std::filesystem::path>& shards,
           const Config& cfg);

void PrintCertificationContract(const Result& result, bool generationRequested);

struct Gate11Telemetry {
    bool deep2BridgeEntered = false;
    bool deep2EngineEntered = false;
    bool k2NativeStreamSelected = false;
    bool noTestHarnessDirectCall = false;
};

void PrintGate11Contract(const Result& result, const Gate11Telemetry& tel);
void PrintGate12Contract(const Result& result);

} // namespace K2NativeStreamGate
