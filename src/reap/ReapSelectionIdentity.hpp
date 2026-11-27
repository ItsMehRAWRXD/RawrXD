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

} // namespace RawrXD::Reap