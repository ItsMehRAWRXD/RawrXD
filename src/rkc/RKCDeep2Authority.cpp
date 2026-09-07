// RKCDeep2Authority.cpp — RAW_GGUF selection + Deep2 open/generate
#include "RKCDeep2Authority.hpp"
#include "Deep2Engine.h"
#include "Deep2LivePath.hpp"
#include "K2LivePolicy.hpp"
#include <chrono>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <stdlib.h>
#endif

namespace RawrXD {
namespace RKC {
namespace {

const KnowledgeAtom* Need(const World& w, const std::string& k) { return w.get(k); }

Deep2AuthoritySelection FromRawId(const World& world, const std::string& id) {
    Deep2AuthoritySelection s;
    s.id = id;
    const std::string pref = "inventory.raw_gguf." + id;
    const auto* src = Need(world, pref + ".source");
    const auto* path = Need(world, pref + ".path");
    const auto* compat = Need(world, pref + ".runtime_compat");
    const auto* shards = Need(world, pref + ".shard_count");
    const auto* bytes = Need(world, pref + ".corpus_bytes");
    if (!src || src->value != "RAW_GGUF") {
        s.reason = "not_raw_gguf";
        return s;
    }
    if (!compat || compat->value != "1") {
        s.reason = "not_runtime_compat";
        return s;
    }
    if (!path || path->value.empty()) {
        s.reason = "missing_path";
        return s;
    }
    s.ok = true;
    s.path = path->value;
    s.source = "RAW_GGUF";
    s.shardCount =
        shards ? (uint32_t)std::strtoul(shards->value.c_str(), nullptr, 10) : 0;
    s.corpusBytes =
        bytes ? std::strtoull(bytes->value.c_str(), nullptr, 10) : 0;
    s.reason = "raw_gguf_selected";
    return s;
}

} // namespace

Deep2AuthoritySelection SelectDeep2Authority(const World& world,
                                             const std::string& inventoryId) {
    Deep2AuthoritySelection s;
    if (inventoryId.empty()) {
        s.reason = "empty_id";
        return s;
    }
    s.id = inventoryId;
    if (world.get("inventory.ollama_manifest." + inventoryId + ".source") ||
        world.get("inventory.ollama_manifest." + inventoryId + ".path")) {
        s.reason = "ollama_manifest_not_authority";
        return s;
    }
    if (!world.get("inventory.raw_gguf." + inventoryId + ".source")) {
        s.reason = "unknown_inventory_id";
        return s;
    }
    return FromRawId(world, inventoryId);
}

Deep2AuthoritySelection SelectDeep2AuthorityPreferred(
    const World& world, const std::string& preferredId,
    const std::string& needleFallback) {
    if (!preferredId.empty()) {
        auto s = SelectDeep2Authority(world, preferredId);
        if (s.ok) return s;
    }
    // Scan RAW entries for needle in id or path.
    for (const auto& kv : world.atoms()) {
        const std::string& k = kv.first;
        const char* pfx = "inventory.raw_gguf.";
        const size_t n = std::strlen(pfx);
        if (k.rfind(pfx, 0) != 0) continue;
        if (k.size() < n + 7 || k.compare(k.size() - 7, 7, ".source") != 0)
            continue;
        if (kv.second.value != "RAW_GGUF") continue;
        const std::string id = k.substr(n, k.size() - n - 7);
        if (!needleFallback.empty() &&
            id.find(needleFallback) == std::string::npos)
            continue;
        auto s = FromRawId(world, id);
        if (s.ok) return s;
    }
    Deep2AuthoritySelection fail;
    fail.reason = "no_raw_compat_match";
    return fail;
}

Deep2AuthorityRun AuthorizeDeep2Generate(const Deep2AuthoritySelection& sel,
                                         uint32_t depth, uint32_t tokens,
                                         const char* prompt) {
    Deep2AuthorityRun r;
    r.path = sel.path;
    r.id = sel.id;
    if (!sel.ok || sel.source != "RAW_GGUF") {
        r.reason = sel.reason ? sel.reason : "selection_failed";
        return r;
    }
    r.selected = true;
    r.ollamaRequired = false;

#ifdef _WIN32
    _putenv_s("DEEP2_LIVE_POLICY", "");
    _putenv_s("DEEP2_LIVE_ALLOW_LAYER_CACHE", "0");
    _putenv_s("DEEP2_LIVE_FUSED", "0");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
#endif

    auto* eng = new Deep2::Deep2Engine();
    Deep2::EngineConfig cfg{};
    cfg.hiddenDim = 7168; cfg.numLayers = 61; cfg.numHeads = 64;
    cfg.numKVHeads = 1; cfg.vocabSize = 163840; cfg.useMLA = true;
    cfg.maxSeqLen = 128; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 8;
    if (!eng->initialize(cfg) || !eng->openK2ShardDirectory(sel.path)) {
        r.reason = "deep2_open_failed";
        delete eng;
        return r;
    }
    r.opened = true;

    K2NativeStreamGate::Config kc;
    kc.prompt = prompt && prompt[0] ? prompt
                                    : "Write one short paragraph on local decode.";
    kc.streamTokens = tokens ? tokens : 2;
    kc.layerDepth = depth ? depth : 4;
    kc.enableMlaComplete = true;
    kc.budgetBytes = 512ull << 20;
    auto t0 = std::chrono::steady_clock::now();
    auto out = eng->runK2NativeStreamPartial(kc);
    const double ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();
    r.generated = out.ok;
    r.genTokenId = out.generatedTokenId;
    r.text = out.generatedText;
    r.tps = (out.ok && tokens && ms > 0) ? (1000.0 * tokens / ms) : 0.0;
    r.localProven = r.opened && r.generated && !r.ollamaRequired;
    r.reason = r.localProven ? "local_generation_proven" : "generate_failed";
    // Engine workers: hard-exit from cert; here just leak-avoid via _exit in cert.
    delete eng;
    return r;
}

} // namespace RKC
} // namespace RawrXD
