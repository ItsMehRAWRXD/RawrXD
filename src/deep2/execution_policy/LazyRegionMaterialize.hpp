// ============================================================================
// LazyRegionMaterialize.hpp — reverse materialization: on-demand region hotpatch
//
// FULL_MODEL_MATERIALIZATION_BEFORE_FIRST_TOKEN = NOT_REQUIRED
// REGION_MATERIALIZATION                         = ON_DEMAND
// MATERIALIZED_REGION_INSTALL                    = GENERATION_HOTPATCH
// IN_FLIGHT_GENERATION_MUTATION                  = FORBIDDEN
// EXISTING_REGIONS_COPY                          = FORBIDDEN (shared handles)
// REQUEST_PATH_BLOCKS_ONLY_ON_NEXT_REQUIRED_DATA = REQUIRED
// ============================================================================
#pragma once

#include "NuColdHotpatch.hpp"
#include "ReverseLoadLifecycle.hpp"
#include "RealtimeKernel.hpp"
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

enum class RegionKind : uint8_t {
    Metadata = 0,
    Tokenizer,
    Embedding,
    Layer,
    FinalNorm,
    LMHead
};

enum class RegionState : uint8_t {
    Missing = 0,
    Loading,
    Ready,
    Failed
};

struct LazyRegionPayload {
    RegionKind kind = RegionKind::Layer;
    uint32_t index = 0;
    uint64_t bytes = 0;
    Hash256 contentSha = 0;
    // Opaque handle — no tensor byte copy on image clone.
    uint64_t handleId = 0;
};

// Immutable shared region — generation N and N+1 share ready regions.
using RegionHandle = std::shared_ptr<const LazyRegionPayload>;

struct LazyModelShell {
    ModelFingerprint fingerprint;
    uint32_t layerCount = 0;
    RegionHandle tokenizer;
    RegionHandle embedding;
    std::vector<RegionHandle> layers; // nullptr = Missing
    RegionHandle finalNorm;
    RegionHandle lmHead;
    uint32_t readyCount = 0;
    std::unique_ptr<std::mutex> regionMu;

    LazyModelShell() : regionMu(std::make_unique<std::mutex>()) {}
    LazyModelShell(const LazyModelShell&) = delete;
    LazyModelShell& operator=(const LazyModelShell&) = delete;
    LazyModelShell(LazyModelShell&&) noexcept = default;
    LazyModelShell& operator=(LazyModelShell&&) noexcept = default;

    bool layerReady(uint32_t i) const {
        return i < layers.size() && layers[i] && layers[i]->handleId != 0;
    }
    bool fullyMaterialized() const {
        if (!tokenizer || !embedding || !finalNorm || !lmHead) return false;
        for (uint32_t i = 0; i < layerCount; ++i)
            if (!layerReady(i)) return false;
        return true;
    }
};

inline void InitUntouchedShell(LazyModelShell& s, const ModelFingerprint& fp,
                               uint32_t nLayers) {
    s.fingerprint = fp;
    s.layerCount = nLayers;
    s.layers.assign(nLayers, nullptr);
    s.readyCount = 0;
    s.tokenizer.reset();
    s.embedding.reset();
    s.finalNorm.reset();
    s.lmHead.reset();
    if (!s.regionMu)
        s.regionMu = std::make_unique<std::mutex>();
}

inline Hash256 HashRegion(const LazyRegionPayload& p) {
    Hash256 h = 14695981039346656037ULL;
    h = MixHash(h, (uint64_t)p.kind);
    h = MixHash(h, p.index);
    h = MixHash(h, p.bytes);
    h = MixHash(h, p.handleId);
    return h;
}

// Simulate GGUF region materialize (no full-model load).
inline RegionHandle MaterializeLayerFromGGUF(uint32_t layer, uint64_t bytesHint) {
    auto p = std::make_shared<LazyRegionPayload>();
    p->kind = RegionKind::Layer;
    p->index = layer;
    p->bytes = bytesHint ? bytesHint : (64ULL << 20);
    p->handleId = 0x4C000000ULL | layer; // 'L' prefix
    p->contentSha = HashRegion(*p);
    return p;
}

inline RegionHandle MaterializeShellRegion(RegionKind kind, uint32_t index = 0) {
    auto p = std::make_shared<LazyRegionPayload>();
    p->kind = kind;
    p->index = index;
    p->bytes = (kind == RegionKind::Tokenizer) ? (4ULL << 20) : (16ULL << 20);
    p->handleId = (uint64_t)kind << 32 | index;
    p->contentSha = HashRegion(*p);
    return p;
}

// Lightweight shell — IDE / request can start before any weight bytes exist.
inline LazyModelShell MakeUntouchedShell(const ModelFingerprint& fp,
                                         uint32_t nLayers) {
    LazyModelShell s;
    InitUntouchedShell(s, fp, nLayers);
    return s;
}

struct RegionHotpatchResult {
    bool ok = false;
    uint64_t generation = 0;
    Hash256 imageSha = 0;
    uint32_t regionIndex = 0;
    bool blockedOnRegionOnly = true;
    std::string detail;
};

// Install one newly materialized region via NUCOLD generation hotpatch.
// CloneImageMetadata: copy table of shared_ptrs only — NEVER copy tensor bytes.
inline RegionHotpatchResult EnsureRegionReady(LazyModelShell& shell,
                                              RealtimeEngine& engine,
                                              uint32_t layer,
                                              uint64_t bytesHint = 0) {
    RegionHotpatchResult out;
    out.regionIndex = layer;

    if (shell.layerReady(layer)) {
        out.ok = true;
        out.generation = engine.AcquireState().generation();
        out.detail = "ALREADY_READY";
        return out;
    }

    std::unique_lock lock(*shell.regionMu);
    if (shell.layerReady(layer)) {
        out.ok = true;
        out.generation = engine.AcquireState().generation();
        out.detail = "ALREADY_READY_AFTER_WAIT";
        return out;
    }

    RealtimeReadView base = engine.AcquireState();
    if (!base.valid()) {
        out.detail = "NO_ACTIVE_IMAGE";
        return out;
    }

    // Materialize ONLY this layer (blocks request path only on next required data).
    RegionHandle region = MaterializeLayerFromGGUF(layer, bytesHint);
    shell.layers[layer] = region;
    ++shell.readyCount;

    // Private N+1: policy/state overlay + region proof — no full reload.
    HotPatchRequest req;
    req.flags = {}; // residency/table update is hot-safe
    req.candidate.expectedSchemaHash = engine.kernel().schemaHash;
    req.candidate.expectedAuthorityHash = engine.kernel().authorityHash;
    req.candidate.source = "lazy_region_hotpatch";
    req.candidate.state = base.state();
    req.candidate.state.patches.active.push_back(CompileReuseRule(
        /*id=*/0x52000000ULL | layer, /*region=*/layer,
        /*pred=*/region->contentSha, /*proof=*/region->handleId,
        /*us=*/0.0));
    req.candidate.state.telemetry.tokenIndex = layer;
    req.note = "layer_" + std::to_string(layer);

    HotPatchResult hp = ControllerHotPatch(engine, req);
    if (hp.status != HotPatchStatus::Applied) {
        shell.layers[layer].reset();
        if (shell.readyCount > 0)
            --shell.readyCount;
        out.detail = hp.detail;
        return out;
    }

    out.ok = true;
    out.generation = hp.generation;
    out.imageSha = hp.imageSha;
    out.blockedOnRegionOnly = true;
    out.detail = "REGION_HOTPATCHED gen=" + std::to_string(hp.generation);
    return out;
}

// Prefetch lookahead: materialize [start, start+depth) ahead of compute.
inline uint32_t PrefetchLayers(LazyModelShell& shell, RealtimeEngine& engine,
                               uint32_t start, uint32_t depth) {
    uint32_t n = 0;
    for (uint32_t i = start; i < shell.layerCount && i < start + depth; ++i) {
        if (!shell.layerReady(i)) {
            if (EnsureRegionReady(shell, engine, i).ok)
                ++n;
        }
    }
    return n;
}

// ExecuteLayer: acquire → ensure → reacquire patched gen → run (stub).
inline bool ExecuteLayer(LazyModelShell& shell, RealtimeEngine& engine,
                         uint32_t layer, uint64_t& outGen) {
    RealtimeReadView view = engine.AcquireState();
    if (!shell.layerReady(layer)) {
        RegionHotpatchResult r = EnsureRegionReady(shell, engine, layer);
        if (!r.ok) return false;
        view = engine.AcquireState(); // acquire patched generation
    }
    outGen = view.generation();
    return shell.layerReady(layer) && view.valid();
}

} // namespace Exec
} // namespace Deep2
