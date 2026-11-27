// ReapSelectionIdentity.hpp — RAWRXD C02 (deterministic transformation identity)
// Deterministic, host-pointer-independent fingerprint binding a retained-expert
// selection to checkpoint identity, logical tensor identity, quantization geometry
// and transformation mode. Prevents incorrect cache reuse between different
// selections. Storage-independent; no RNG.
#pragma once
#include "reap/ReapTensorSlice.hpp"
#include <cstdint>
#include <string>

namespace RawrXD::Reap {

// FNV-1a over a byte stream, seeded deterministically.
static inline uint64_t FingerprintBytes(uint64_t seed, const uint8_t* p, size_t n) {
    uint64_t h = seed ^ 0x9E3779B97F4A7C15ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// Deterministic identity for a transformation: selection + checkpoint + geometry + mode.
static inline uint64_t SelectionFingerprint(const ExpertSelection& sel, uint64_t checkpointId,
                                            uint64_t tensorBytes, uint32_t mode) {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    auto mix = [&](uint64_t v) { h ^= v; h *= 1099511628211ULL; h ^= h >> 29; };
    mix(checkpointId); mix(tensorBytes); mix(mode);
    for (const auto& kv : sel) {                 // ordered map => deterministic
        mix(kv.first);
        mix((uint64_t)kv.second.size());
        for (uint32_t e : kv.second) mix(e);
    }
    return h;
}

// PR-06: production cache identity = weight key + selection fingerprint.
// Prevents cross-selection / cross-checkpoint / cross-mode cache reuse. A zero
// fingerprint must NOT collapse to the bare weight key (Virtual/Streaming safety).
static inline uint64_t CacheIdentity(uint64_t weightKey, uint64_t selectionFingerprint,
                                     bool selectionValid) {
    uint64_t h = weightKey;
    if (!selectionValid) {
        // No validated selection: use a distinct sentinel domain (never the bare key).
        h ^= 0xD1B54A32D192ED03ULL;
    } else {
        h ^= selectionFingerprint;
    }
    h *= 1099511628211ULL; h ^= h >> 29; h *= 0x9E3779B97F4A7C15ULL; h ^= h >> 31;
    return h;
}

// S03.5: checkpoint-content identity across all shards (content + geometry).
static inline uint64_t CheckpointContentIdentity(const std::vector<uint64_t>& shardContentHashes,
                                                 uint64_t tensorCount, uint32_t quantBlockBytes) {
    uint64_t h = 0x9E3779B97F4A7C15ULL;
    auto mix = [&](uint64_t v) { h ^= v; h *= 1099511628211ULL; h ^= h >> 29; };
    mix((uint64_t)shardContentHashes.size());
    for (uint64_t s : shardContentHashes) mix(s);
    mix(tensorCount); mix(quantBlockBytes);
    return h;
}

} // namespace RawrXD::Reap