// ============================================================================
// ExecutionPolicy.cpp — resolve, validate, defaults, policy SHA
// ============================================================================
#include "ExecutionPolicy.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace Deep2 {
namespace Exec {

namespace {

bool MatchGlob(const std::string& pat, const std::string& name) {
    // Minimal * wildcard matcher (no **).
    size_t pi = 0, ni = 0, star = std::string::npos, match = 0;
    while (ni < name.size()) {
        if (pi < pat.size() && (pat[pi] == name[ni] || pat[pi] == '?')) {
            ++pi; ++ni;
        } else if (pi < pat.size() && pat[pi] == '*') {
            star = pi++; match = ni;
        } else if (star != std::string::npos) {
            pi = star + 1; ni = ++match;
        } else {
            return false;
        }
    }
    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}

bool LayerInRange(int layer, const LayerRange& r) {
    if (layer < r.first) return false;
    if (r.last < 0) return true;
    return layer <= r.last;
}

} // namespace

DeviceKind ExecutionPolicy::resolvePlacement(const std::string& tensorName,
                                             int layer,
                                             TensorClass cls) const {
    // 1) Tensor / pattern overrides (last matching wins among same authority;
    //    scan reverse so later rules win).
    for (auto it = placement.rules.rbegin(); it != placement.rules.rend(); ++it) {
        if (MatchGlob(it->pattern, tensorName))
            return it->device;
    }

    // 2) Layer range map
    for (auto it = placement.layerRanges.rbegin();
         it != placement.layerRanges.rend(); ++it) {
        if (LayerInRange(layer, it->first))
            return it->second;
    }

    // 3) Tensor-class policy
    switch (cls) {
    case TensorClass::Attention:
        if (placement.attentionClass.present) return placement.attentionClass.value;
        break;
    case TensorClass::FFN:
        if (placement.ffnClass.present) return placement.ffnClass.value;
        break;
    case TensorClass::Embeddings:
        if (placement.embeddings.present) return placement.embeddings.value;
        break;
    case TensorClass::LmHead:
        if (placement.lmHead.present) return placement.lmHead.value;
        break;
    case TensorClass::Norms:
        if (placement.norms.present) return placement.norms.value;
        break;
    default:
        break;
    }

    // 4) Global weight policy
    if (placement.weightPolicy.present) {
        switch (placement.weightPolicy.value) {
        case WeightPolicy::Gpu: return DeviceKind::Gpu0;
        case WeightPolicy::Cpu: return DeviceKind::Host;
        case WeightPolicy::Stream: return DeviceKind::Stream;
        case WeightPolicy::Hybrid: return DeviceKind::Hybrid;
        }
    }
    return DeviceKind::Host;
}

PolicyValidation Validate(const ExecutionPolicy& p) {
    PolicyValidation out;
    out.ok = true;

    auto fail = [&](const std::string& msg) {
        out.ok = false;
        if (!out.detail.empty()) out.detail += "; ";
        out.detail += msg;
    };

    const uint64_t vram =
        p.memory.vramBudget.present ? p.memory.vramBudget.value.n : 0;
    const uint64_t parts = p.memory.vramParts.sum();
    if (vram > 0 && parts > vram) {
        fail("VRAM partition sum exceeds vram budget (" +
             std::to_string(parts) + " > " + std::to_string(vram) + ")");
    }

    for (const auto& g : p.memory.gpus) {
        const uint64_t gb = g.budget.present ? g.budget.value.n : 0;
        const uint64_t gs = g.partition.sum();
        if (gb > 0 && gs > gb) {
            fail("GPU" + std::to_string(g.index) +
                 " partition exceeds budget");
        }
    }

    if (p.memory.ram.hardCap.present) {
        auto g = [](const Tunable<Bytes>& t) {
            return t.present ? t.value.n : 0ULL;
        };
        const uint64_t ramSum = g(p.memory.ram.maxMapped) +
                                g(p.memory.ram.weightCache) +
                                g(p.memory.ram.kvSpill) +
                                g(p.memory.ram.staging);
        if (ramSum > p.memory.ram.hardCap.value.n)
            fail("RAM partition sum exceeds hard cap");
    }

    if (p.kv.context.present && p.kv.context.value < 0)
        fail("KV context must be >= 0");

    if (p.streaming.enabled.present && p.streaming.enabled.value) {
        if (p.streaming.chunkSize.present && p.streaming.chunkSize.value.n == 0)
            fail("stream chunk_size must be > 0 when streaming enabled");
        if (p.streaming.buffers.present && p.streaming.buffers.value < 1)
            fail("stream buffers must be >= 1");
    }

    if (p.reuse.enabled.present && p.reuse.enabled.value) {
        if (p.reuse.mode.present &&
            p.reuse.mode.value == ReuseMode::Disabled)
            fail("reuse enabled but mode=Disabled");
        // Only CertifiedReuse / ExactOnly are legal when fail-closed.
        if (p.reuse.failClosed.present && p.reuse.failClosed.value) {
            if (p.reuse.mode.present &&
                p.reuse.mode.value != ReuseMode::CertifiedReuse &&
                p.reuse.mode.value != ReuseMode::ExactOnly)
                fail("fail-closed reuse requires ExactOnly or CertifiedReuse");
        }
    }

    return out;
}

ExecutionPolicy MakeDefaultPolicy() {
    ExecutionPolicy p;
    p.mode = UiMode::Guided;
    p.version = 1;
    p.persistRuntimeChanges.force(true, SettingAuthority::AutoDetect,
                                  SettingMutability::Immediate);

    p.memory.vramBudget.force(Bytes::GiB(12), SettingAuthority::AutoDetect,
                              SettingMutability::TokenBoundary);
    p.memory.vramCapKind.force(CapKind::Hard, SettingAuthority::AutoDetect,
                               SettingMutability::Immediate);
    p.memory.ramBudget.force(Bytes::GiB(40), SettingAuthority::AutoDetect,
                             SettingMutability::TokenBoundary);
    p.memory.ramCapKind.force(CapKind::Soft, SettingAuthority::AutoDetect,
                              SettingMutability::Immediate);
    p.memory.diskCacheBudget.force(Bytes::GiB(100), SettingAuthority::AutoDetect,
                                   SettingMutability::Immediate);

    p.memory.vramParts.weights.force(Bytes::GiB(6), SettingAuthority::AutoDetect,
                                     SettingMutability::TokenBoundary);
    p.memory.vramParts.kv.force(Bytes::GiB(3), SettingAuthority::AutoDetect,
                                SettingMutability::TokenBoundary);
    p.memory.vramParts.activations.force(Bytes::GiB(1), SettingAuthority::AutoDetect,
                                         SettingMutability::TokenBoundary);
    p.memory.vramParts.streaming.force(Bytes::GiB(1), SettingAuthority::AutoDetect,
                                       SettingMutability::TokenBoundary);
    p.memory.vramParts.scratch.force(Bytes::MiB(512), SettingAuthority::AutoDetect,
                                     SettingMutability::TokenBoundary);
    p.memory.vramParts.reserve.force(Bytes::MiB(512), SettingAuthority::AutoDetect,
                                     SettingMutability::TokenBoundary);

    p.memory.ram.hardCap.force(Bytes::GiB(40), SettingAuthority::AutoDetect,
                               SettingMutability::TokenBoundary);
    p.memory.ram.weightCache.force(Bytes::GiB(20), SettingAuthority::AutoDetect,
                                   SettingMutability::TokenBoundary);
    p.memory.ram.kvSpill.force(Bytes::GiB(8), SettingAuthority::AutoDetect,
                               SettingMutability::TokenBoundary);
    p.memory.ram.staging.force(Bytes::GiB(4), SettingAuthority::AutoDetect,
                               SettingMutability::TokenBoundary);

    p.placement.embeddings.force(DeviceKind::Host, SettingAuthority::AutoDetect,
                                 SettingMutability::TokenBoundary);
    p.placement.lmHead.force(DeviceKind::Gpu0, SettingAuthority::AutoDetect,
                             SettingMutability::TokenBoundary);
    p.placement.attentionClass.force(DeviceKind::Gpu0, SettingAuthority::AutoDetect,
                                     SettingMutability::TokenBoundary);
    p.placement.ffnClass.force(DeviceKind::Hybrid, SettingAuthority::AutoDetect,
                               SettingMutability::TokenBoundary);
    p.placement.weightPolicy.force(WeightPolicy::Hybrid, SettingAuthority::AutoDetect,
                                   SettingMutability::TokenBoundary);

    p.streaming.enabled.force(true, SettingAuthority::AutoDetect,
                              SettingMutability::TokenBoundary);
    p.streaming.chunkSize.force(Bytes::MiB(128), SettingAuthority::AutoDetect,
                                SettingMutability::Immediate);
    p.streaming.prefetchDepth.force(3, SettingAuthority::AutoDetect,
                                    SettingMutability::Immediate);
    p.streaming.queueDepth.force(8, SettingAuthority::AutoDetect,
                                 SettingMutability::Immediate);
    p.streaming.buffers.force(3, SettingAuthority::AutoDetect,
                              SettingMutability::Immediate);
    p.streaming.directIo.force(true, SettingAuthority::AutoDetect,
                               SettingMutability::ModelReload);
    p.streaming.prefetch.force(PrefetchPolicy::DependencyAware,
                               SettingAuthority::AutoDetect,
                               SettingMutability::Immediate);
    p.streaming.granularity.force(StreamGranularity::TensorSlice,
                                  SettingAuthority::AutoDetect,
                                  SettingMutability::TokenBoundary);

    p.kv.placement.force(KVPlacement::Hybrid, SettingAuthority::AutoDetect,
                         SettingMutability::SequenceBoundary);
    p.kv.gpuBudget.force(Bytes::GiB(2), SettingAuthority::AutoDetect,
                         SettingMutability::TokenBoundary);
    p.kv.quant.force(std::string("q8"), SettingAuthority::AutoDetect,
                     SettingMutability::SequenceBoundary);
    p.kv.context.force(16384, SettingAuthority::AutoDetect,
                       SettingMutability::ModelReload);

    p.reuse.enabled.force(true, SettingAuthority::AutoDetect,
                          SettingMutability::TokenBoundary);
    p.reuse.mode.force(ReuseMode::CertifiedReuse, SettingAuthority::AutoDetect,
                       SettingMutability::TokenBoundary);
    p.reuse.failClosed.force(true, SettingAuthority::AutoDetect,
                             SettingMutability::Immediate);

    p.scheduler.objective.force(OptimizationTarget::HighestTPS,
                                SettingAuthority::AutoDetect,
                                SettingMutability::Immediate);
    p.scheduler.eviction.force(EvictionPolicyKind::CostAware,
                               SettingAuthority::AutoDetect,
                               SettingMutability::Immediate);
    p.scheduler.autoTune.force(true, SettingAuthority::AutoDetect,
                               SettingMutability::Immediate);
    p.scheduler.respectOverrides.force(true, SettingAuthority::AutoDetect,
                                       SettingMutability::Immediate);

    p.hotpatch.enabled.force(true, SettingAuthority::AutoDetect,
                             SettingMutability::Immediate);
    p.hotpatch.adaptive.force(true, SettingAuthority::AutoDetect,
                              SettingMutability::Immediate);
    p.hotpatch.persistLearnedPlan.force(true, SettingAuthority::AutoDetect,
                                        SettingMutability::Immediate);

    p.latency.autoTarget.force(true, SettingAuthority::AutoDetect,
                               SettingMutability::Immediate);
    p.latency.maxRiskBudget.force(0.25, SettingAuthority::AutoDetect,
                                  SettingMutability::Immediate);
    p.speedup.autoTarget.force(true, SettingAuthority::AutoDetect,
                               SettingMutability::Immediate);
    p.speedup.minimumAcceptedGain.force(1.01, SettingAuthority::AutoDetect,
                                        SettingMutability::Immediate);
    p.speedup.maxRiskBudget.force(0.25, SettingAuthority::AutoDetect,
                                  SettingMutability::Immediate);

    p.context.force(16384, SettingAuthority::AutoDetect,
                    SettingMutability::ModelReload);
    return p;
}

// FNV-1a 64 then hex — lightweight stable digest (not crypto; PolicySha name kept).
std::string PolicySha256(const ExecutionPolicy& p) {
    auto h = 14695981039346656037ULL;
    auto mix = [&](uint64_t x) {
        h ^= x;
        h *= 1099511628211ULL;
    };
    auto mixS = [&](const std::string& s) {
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ULL;
        }
    };

    mix(p.version);
    mix(static_cast<uint64_t>(p.mode));
    if (p.memory.vramBudget.present) mix(p.memory.vramBudget.value.n);
    if (p.memory.ramBudget.present) mix(p.memory.ramBudget.value.n);
    mix(p.memory.vramParts.sum());
    if (p.streaming.enabled.present) mix(p.streaming.enabled.value ? 1ULL : 0ULL);
    if (p.streaming.chunkSize.present) mix(p.streaming.chunkSize.value.n);
    if (p.kv.placement.present) mix(static_cast<uint64_t>(p.kv.placement.value));
    if (p.reuse.mode.present) mix(static_cast<uint64_t>(p.reuse.mode.value));
    if (p.modelFingerprint.present) mixS(p.modelFingerprint.value);
    for (const auto& r : p.placement.layerRanges) {
        mix(static_cast<uint64_t>(r.first.first));
        mix(static_cast<uint64_t>(r.first.last));
        mix(static_cast<uint64_t>(r.second));
    }
    for (const auto& rule : p.placement.rules) {
        mixS(rule.pattern);
        mix(static_cast<uint64_t>(rule.device));
    }

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%016llx",
                  static_cast<unsigned long long>(h));
    return std::string("policy:") + buf;
}

} // namespace Exec
} // namespace Deep2
