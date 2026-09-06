// ============================================================================
// RealtimeKernel.hpp — STRUCTURE sealed; DATA replaceable via atomic image
//
// INV: REALTIME_STRUCTURE_MUTATION = FORBIDDEN
//      REALTIME_STATE_REPLACEMENT  = ALLOWED (validated + atomic)
//      STATE_REPLACEMENT_ATOMIC    = REQUIRED
//      EXTERNAL_DATA_VALIDATED     = REQUIRED
//      OLD_IMAGE_RETIRED_ON_LAST_RELEASE = REQUIRED (RCU read handles)
//
// Model is unstatic in state, static in execution law.
// ============================================================================
#pragma once

#include "Tunable.hpp"
#include "ExecutionPolicy.hpp"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

namespace Deep2 {
namespace Exec {

using Hash256 = uint64_t; // FNV-1a fold; enough for generation audit

enum class RuleAction : uint8_t {
    Reuse = 0,
    Skip,
    Residency,
    Stream,
    Prefetch,
    Fuse,
    Route,
    Cache,
    QuantSpecialize,
    KernelSpecialize
};

struct ExecutionRule {
    uint64_t id = 0;
    RuleAction action = RuleAction::Reuse;
    uint32_t regionId = 0;
    uint64_t predicateBits = 0;
    uint64_t proofId = 0;
    double predictedSavedUs = 0.0;
    bool persistent = false;
    bool touchesWeights = false;
};

struct PlacementState {
    std::vector<std::pair<LayerRange, DeviceKind>> layerRanges;
    std::vector<PlacementRule> tensorRules;
    std::vector<std::string> pinned;
    DeviceKind embeddings = DeviceKind::Host;
    DeviceKind lmHead = DeviceKind::Gpu0;
};

struct TimingState {
    double baselineDecodeMs = 0.0;
    double targetDecodeMs = 0.0;
    double baselineTtftMs = 0.0;
    double targetTtftMs = 0.0;
    double mustDisappearMs = 0.0;
    double targetRealSpeedup = 1.0;
};

struct LearnedRules {
    std::vector<ExecutionRule> rules;
    uint64_t rulesSha = 0;
};

struct HotpatchData {
    std::vector<ExecutionRule> active;
    std::vector<uint64_t> blacklist;
    uint64_t patchSetSha = 0;
};

struct TelemetryState {
    double currentDecodeMs = 0.0;
    double currentTtftMs = 0.0;
    double currentTps = 0.0;
    double currentSpeedup = 1.0;
    double disappearedMs = 0.0;
    double remainingMs = 0.0;
    double progress = 0.0;
    uint64_t tokenIndex = 0;
};

struct RealtimeState {
    PlacementState placement;
    TimingState timing;
    LearnedRules learned;
    HotpatchData patches;
    TelemetryState telemetry;
    std::string policySha;
};

struct VerificationRules {
    bool requireOutputEquivalent = true;
    bool requireAuthorityPreserved = true;
    bool requireNetTimeSaved = true;
    double minAcceptedGain = 1.01;
    double maxRegression = 0.0;
};

struct AuthorityRules {
    bool honorUserLocked = true;
    bool forbidStructureMutation = true;
    bool forbidAuthorityRewrite = true;
    bool forbidGraphRewrite = true;
};

struct ExecutionGraph {
    uint32_t nodeCount = 0;
    uint32_t edgeCount = 0;
    Hash256 topologyHash = 0;
    uint32_t opcodeTableId = 1;
};

struct RealtimeImage {
    uint64_t generation = 0;
    Hash256 schemaHash = 0;
    Hash256 authorityHash = 0;
    Hash256 stateHash = 0;
    RealtimeState state;
    bool frozen = false;
};

struct RealtimeStateSnapshot {
    RealtimeState state;
    Hash256 expectedSchemaHash = 0;
    Hash256 expectedAuthorityHash = 0;
    std::string source;
};

struct CommitResult {
    bool ok = false;
    uint64_t newGeneration = 0;
    std::string detail;
};

struct TokenProvenance {
    uint64_t stateGeneration = 0;
    Hash256 stateImageSha = 0;
    Hash256 policySha = 0;
    Hash256 authoritySha = 0;
    Hash256 rulesetSha = 0;
    Hash256 proofSetSha = 0;
};

inline Hash256 MixHash(Hash256 h, uint64_t x) {
    h ^= x + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h;
}

inline Hash256 HashRules(const std::vector<ExecutionRule>& rules) {
    Hash256 h = 14695981039346656037ULL;
    for (const auto& r : rules) {
        h = MixHash(h, r.id);
        h = MixHash(h, (uint64_t)r.action);
        h = MixHash(h, r.regionId);
        h = MixHash(h, r.predicateBits);
        h = MixHash(h, r.proofId);
    }
    return h;
}

inline Hash256 HashProofSet(const std::vector<ExecutionRule>& rules) {
    Hash256 h = 14695981039346656037ULL;
    for (const auto& r : rules)
        h = MixHash(h, r.proofId);
    return h;
}

inline Hash256 HashPolicyShaString(const std::string& policySha) {
    Hash256 h = 14695981039346656037ULL;
    for (unsigned char c : policySha) {
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

inline Hash256 HashRealtimeState(const RealtimeState& s) {
    Hash256 h = 14695981039346656037ULL;
    h = MixHash(h, (uint64_t)(s.timing.baselineDecodeMs * 1000.0));
    h = MixHash(h, (uint64_t)(s.timing.targetDecodeMs * 1000.0));
    h = MixHash(h, (uint64_t)(s.timing.mustDisappearMs * 1000.0));
    h = MixHash(h, HashRules(s.learned.rules));
    h = MixHash(h, HashRules(s.patches.active));
    h = MixHash(h, HashPolicyShaString(s.policySha));
    return h;
}

inline Hash256 HashKernelSchema(const ExecutionGraph& g,
                                const VerificationRules& v) {
    Hash256 h = 14695981039346656037ULL;
    h = MixHash(h, g.topologyHash);
    h = MixHash(h, g.nodeCount);
    h = MixHash(h, g.edgeCount);
    h = MixHash(h, g.opcodeTableId);
    h = MixHash(h, v.requireOutputEquivalent ? 1ULL : 0ULL);
    h = MixHash(h, v.requireAuthorityPreserved ? 1ULL : 0ULL);
    h = MixHash(h, v.requireNetTimeSaved ? 1ULL : 0ULL);
    h = MixHash(h, (uint64_t)(v.minAcceptedGain * 1000.0));
    return h;
}

inline Hash256 HashAuthority(const AuthorityRules& a) {
    Hash256 h = 14695981039346656037ULL;
    h = MixHash(h, a.honorUserLocked ? 1ULL : 0ULL);
    h = MixHash(h, a.forbidStructureMutation ? 1ULL : 0ULL);
    h = MixHash(h, a.forbidAuthorityRewrite ? 1ULL : 0ULL);
    h = MixHash(h, a.forbidGraphRewrite ? 1ULL : 0ULL);
    return h;
}

inline ExecutionGraph MakeDefaultGraph() {
    ExecutionGraph g;
    g.nodeCount = 8;
    g.edgeCount = 12;
    g.opcodeTableId = 1;
    g.topologyHash = MixHash(0xA5000001ULL, g.nodeCount ^ g.edgeCount);
    return g;
}

inline bool ImageIntegrityOk(const RealtimeImage& img) {
    if (!img.frozen) return false;
    if (img.stateHash != HashRealtimeState(img.state)) return false;
    if (img.state.learned.rulesSha != HashRules(img.state.learned.rules))
        return false;
    if (img.state.patches.patchSetSha != HashRules(img.state.patches.active))
        return false;
    return true;
}

struct RealtimeKernel final {
    const ExecutionGraph graph;
    const VerificationRules rules;
    const AuthorityRules authority;
    const Hash256 schemaHash;
    const Hash256 authorityHash;

    RealtimeKernel(ExecutionGraph g, VerificationRules v, AuthorityRules a,
                   Hash256 schema, Hash256 authHash)
        : graph(std::move(g)), rules(v), authority(a), schemaHash(schema),
          authorityHash(authHash) {}

    RealtimeKernel(const RealtimeKernel&) = delete;
    RealtimeKernel& operator=(const RealtimeKernel&) = delete;
};

inline void FinalizeImage(RealtimeImage& img, const RealtimeKernel* kernel) {
    img.state.timing.mustDisappearMs =
        (std::max)(0.0, img.state.timing.baselineDecodeMs -
                            img.state.timing.targetDecodeMs);
    if (img.state.timing.baselineDecodeMs > 0.0 &&
        img.state.timing.targetDecodeMs > 0.0)
        img.state.timing.targetRealSpeedup =
            img.state.timing.baselineDecodeMs /
            img.state.timing.targetDecodeMs;
    img.state.learned.rulesSha = HashRules(img.state.learned.rules);
    img.state.patches.patchSetSha = HashRules(img.state.patches.active);
    img.stateHash = HashRealtimeState(img.state);
    if (kernel) {
        img.schemaHash = kernel->schemaHash;
        img.authorityHash = kernel->authorityHash;
    }
    img.frozen = true;
}

inline bool ValidateSnapshotAgainstKernel(const RealtimeKernel& kernel,
                                          const RealtimeStateSnapshot& snap,
                                          std::string& detail) {
    if (snap.expectedSchemaHash != 0 &&
        snap.expectedSchemaHash != kernel.schemaHash) {
        detail = "SCHEMA_HASH_MISMATCH";
        return false;
    }
    if (snap.expectedAuthorityHash != 0 &&
        snap.expectedAuthorityHash != kernel.authorityHash) {
        detail = "AUTHORITY_HASH_MISMATCH";
        return false;
    }
    if (!kernel.authority.forbidStructureMutation ||
        !kernel.authority.forbidGraphRewrite ||
        !kernel.authority.forbidAuthorityRewrite) {
        detail = "KERNEL_AUTHORITY_TAMPERED";
        return false;
    }
    for (const auto& r : snap.state.patches.active) {
        for (uint64_t bl : snap.state.patches.blacklist) {
            if (r.proofId == bl || r.id == bl) {
                detail = "BLACKLISTED_RULE";
                return false;
            }
        }
        if (r.touchesWeights && kernel.rules.requireAuthorityPreserved &&
            r.proofId == 0) {
            detail = "WEIGHT_RULE_WITHOUT_PROOF";
            return false;
        }
    }
    if (snap.state.timing.targetDecodeMs > 0.0 &&
        snap.state.timing.baselineDecodeMs > 0.0 &&
        snap.state.timing.targetDecodeMs > snap.state.timing.baselineDecodeMs) {
        detail = "TARGET_SLOWER_THAN_BASELINE";
        return false;
    }
    detail = "OK";
    return true;
}

// RCU read handle — token holds one generation for its entire execution.
class RealtimeReadView {
public:
    RealtimeReadView() = default;
    explicit RealtimeReadView(std::shared_ptr<const RealtimeImage> img)
        : image_(std::move(img)) {}

    bool valid() const { return image_ != nullptr; }
    uint64_t generation() const { return image_ ? image_->generation : 0; }
    Hash256 stateImageSha() const { return image_ ? image_->stateHash : 0; }
    Hash256 schemaHash() const { return image_ ? image_->schemaHash : 0; }
    Hash256 authorityHash() const { return image_ ? image_->authorityHash : 0; }
    Hash256 rulesetSha() const {
        return image_ ? image_->state.patches.patchSetSha : 0;
    }
    Hash256 proofSetSha() const {
        return image_ ? HashProofSet(image_->state.patches.active) : 0;
    }
    Hash256 policySha() const {
        return image_ ? HashPolicyShaString(image_->state.policySha) : 0;
    }
    const RealtimeState& state() const { return image_->state; }
    const RealtimeImage* raw() const { return image_.get(); }
    long readerRefCount() const {
        return image_ ? image_.use_count() : 0;
    }

private:
    std::shared_ptr<const RealtimeImage> image_;
};

inline TokenProvenance ProvenanceFromView(const RealtimeReadView& view) {
    TokenProvenance p;
    if (!view.valid()) return p;
    p.stateGeneration = view.generation();
    p.stateImageSha = view.stateImageSha();
    p.policySha = view.policySha();
    p.authoritySha = view.authorityHash();
    p.rulesetSha = view.rulesetSha();
    p.proofSetSha = view.proofSetSha();
    return p;
}

class RealtimeEngine {
public:
    explicit RealtimeEngine(RealtimeKernel* kernel) : kernel_(kernel) {
        auto img = std::make_shared<RealtimeImage>();
        img->generation = 0;
        FinalizeImage(*img, kernel_);
        {
            std::unique_lock lock(imageMu_);
            active_ = img;
            lastIssuedGeneration_ = 0;
        }
    }

    ~RealtimeEngine() {
        std::unique_lock lock(imageMu_);
        active_.reset();
    }

    RealtimeEngine(const RealtimeEngine&) = delete;
    RealtimeEngine& operator=(const RealtimeEngine&) = delete;

    const RealtimeKernel& kernel() const { return *kernel_; }

    // Each token acquires exactly once; entire token uses the same image.
    RealtimeReadView AcquireState() const {
        std::shared_lock lock(imageMu_);
        return RealtimeReadView(active_);
    }

    const RealtimeImage* active() const {
        std::shared_lock lock(imageMu_);
        return active_.get();
    }

    uint64_t generationForToken(uint64_t /*tokenIndex*/) const {
        return AcquireState().generation();
    }

    uint64_t lastIssuedGeneration() const {
        std::shared_lock lock(imageMu_);
        return lastIssuedGeneration_;
    }

    CommitResult CommitRealtimeState(const RealtimeStateSnapshot& candidate) {
        CommitResult r;
        if (!kernel_) {
            r.detail = "NO_KERNEL";
            return r;
        }
        std::string detail;
        if (!ValidateSnapshotAgainstKernel(*kernel_, candidate, detail)) {
            r.detail = detail;
            return r;
        }

        auto next = std::make_shared<RealtimeImage>();
        {
            std::shared_lock readLock(imageMu_);
            const uint64_t prevGen =
                active_ ? active_->generation : lastIssuedGeneration_;
            next->generation = prevGen + 1; // monotonic; never reused (ABA-safe)
        }
        next->state = candidate.state;
        FinalizeImage(*next, kernel_);
        if (!ImageIntegrityOk(*next)) {
            r.detail = "IMAGE_INTEGRITY_FAIL";
            return r;
        }

        std::unique_lock writeLock(imageMu_);
        const uint64_t prevGen =
            active_ ? active_->generation : lastIssuedGeneration_;
        if (next->generation <= prevGen) {
            r.detail = "GENERATION_NOT_MONOTONIC";
            return r;
        }
        const auto prev = active_;
        active_ = next;
        lastIssuedGeneration_ = next->generation;
        writeLock.unlock();

        // prev retained until last RealtimeReadView releases (shared_ptr RCU).
        r.ok = true;
        r.newGeneration = next->generation;
        r.detail = "COMMITTED gen=" + std::to_string(r.newGeneration) +
                   " src=" + candidate.source;
        (void)prev;
        return r;
    }

    bool ModifyRealtimeKernel() {
        lastForbid_ = "REALTIME_STRUCTURE_MUTATION_FORBIDDEN";
        return false;
    }
    bool RewriteExecutionGraph() {
        lastForbid_ = "REALTIME_GRAPH_REWRITE_FORBIDDEN";
        return false;
    }
    bool PatchAuthorityRules() {
        lastForbid_ = "REALTIME_AUTHORITY_REWRITE_FORBIDDEN";
        return false;
    }
    const std::string& lastForbid() const { return lastForbid_; }

private:
    RealtimeKernel* kernel_ = nullptr;
    mutable std::shared_mutex imageMu_;
    std::shared_ptr<const RealtimeImage> active_;
    uint64_t lastIssuedGeneration_ = 0;
    std::string lastForbid_;
};

inline RealtimeKernel* MakeSealedKernel() {
    ExecutionGraph g = MakeDefaultGraph();
    VerificationRules v;
    AuthorityRules a;
    const Hash256 schema = HashKernelSchema(g, v);
    const Hash256 auth = HashAuthority(a);
    return new RealtimeKernel(std::move(g), v, a, schema, auth);
}

inline ExecutionRule CompileReuseRule(uint64_t id, uint32_t regionId,
                                      uint64_t predicateBits, uint64_t proofId,
                                      double predictedSavedUs) {
    ExecutionRule r;
    r.id = id;
    r.action = RuleAction::Reuse;
    r.regionId = regionId;
    r.predicateBits = predicateBits;
    r.proofId = proofId;
    r.predictedSavedUs = predictedSavedUs;
    r.persistent = true;
    r.touchesWeights = false;
    return r;
}

} // namespace Exec
} // namespace Deep2
