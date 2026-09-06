// RetainedProofSerialize.hpp — canonical LE encoding + SHA-256
#pragma once
#include "RetainedProofTable.hpp"
#include "Sha256.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace Deep2 {
namespace Regenerative {

constexpr uint32_t kProofMagic = 0x46525052u; // 'RPRF' LE
constexpr uint32_t kProofVersion = 1u;

inline void AppendU32LE(std::vector<uint8_t>& o, uint32_t v) {
    o.push_back(uint8_t(v)); o.push_back(uint8_t(v >> 8));
    o.push_back(uint8_t(v >> 16)); o.push_back(uint8_t(v >> 24));
}
inline void AppendU64LE(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back(uint8_t(v >> (8 * i)));
}
inline void AppendF64LE(std::vector<uint8_t>& o, double d) {
    uint64_t bits = 0;
    std::memcpy(&bits, &d, 8);
    AppendU64LE(o, bits);
}
inline void AppendHash(std::vector<uint8_t>& o, const TimeReversal::Hash256& h) {
    o.insert(o.end(), h.b, h.b + 32);
}
inline void AppendBytes(std::vector<uint8_t>& o, const void* p, size_t n) {
    const auto* b = static_cast<const uint8_t*>(p);
    o.insert(o.end(), b, b + n);
}

inline std::vector<uint8_t> SerializeProofTableCanonical(
    const RetainedProofTable& t, const ProofFactEnvelope& env) {
    int idx[RetainedProofTable::kMax];
    int n = 0;
    for (int i = 0; i < t.count; ++i) {
        if (t.entries[i].active) idx[n++] = i;
    }
    std::sort(idx, idx + n, [&](int a, int b) {
        return std::strncmp(t.entries[a].ruleId, t.entries[b].ruleId, 48) < 0;
    });

    std::vector<uint8_t> out;
    out.reserve(160 + size_t(n) * 120);
    AppendU32LE(out, kProofMagic);
    AppendU32LE(out, kProofVersion);
    AppendHash(out, env.hardwareSha);
    AppendHash(out, env.workloadSha);
    AppendHash(out, env.budgetSha);
    AppendHash(out, env.kernelAbiSha);
    AppendU32LE(out, uint32_t(n));
    for (int k = 0; k < n; ++k) {
        const RetainedProof& p = t.entries[idx[k]];
        out.push_back(uint8_t(p.kind));
        for (int z = 0; z < 7; ++z) out.push_back(0);
        AppendBytes(out, p.ruleId, 48);
        AppendF64LE(out, p.measuredNetRemovalMs);
        AppendF64LE(out, p.confidence);
        AppendU64LE(out, p.sourceGeneration);
        AppendHash(out, p.evidenceSha);
    }
    return out;
}

inline TimeReversal::Hash256 HashProofTableCanonical(
    const RetainedProofTable& t, const ProofFactEnvelope& env) {
    const auto blob = SerializeProofTableCanonical(t, env);
    return Sha256Bytes(blob.data(), blob.size());
}

inline void SealProofTableHash(RetainedProofTable& t, const ProofFactEnvelope& env) {
    t.tableEnvelope = env;
    t.tableSha = HashProofTableCanonical(t, env);
}

inline bool ValidateProofTableHash(const RetainedProofTable& t) {
    return HashEq(t.tableSha, HashProofTableCanonical(t, t.tableEnvelope));
}

inline bool ValidateProofFactEnvelopeMatch(const RetainedProofTable& t,
                                           const ProofFactEnvelope& current) {
    if (!EnvelopeMatch(t.tableEnvelope, current)) return false;
    for (int i = 0; i < t.count; ++i) {
        if (!t.entries[i].active) continue;
        if (!EnvelopeMatch(t.entries[i].envelope, current)) return false;
    }
    return true;
}

inline int InvalidateProofsOutsideEnvelope(RetainedProofTable& t,
                                           const ProofFactEnvelope& current) {
    int dropped = 0;
    for (int i = 0; i < t.count; ++i) {
        if (!t.entries[i].active) continue;
        if (!EnvelopeMatch(t.entries[i].envelope, current)) {
            t.entries[i].active = false;
            ++dropped;
        }
    }
    if (dropped) SealProofTableHash(t, current);
    return dropped;
}

// Parse minimal header to verify canonical magic/version (encoding gate)
inline bool ProofBlobLooksCanonical(const std::vector<uint8_t>& blob) {
    if (blob.size() < 8) return false;
    const uint32_t magic = uint32_t(blob[0]) | (uint32_t(blob[1]) << 8) |
                           (uint32_t(blob[2]) << 16) | (uint32_t(blob[3]) << 24);
    const uint32_t ver = uint32_t(blob[4]) | (uint32_t(blob[5]) << 8) |
                         (uint32_t(blob[6]) << 16) | (uint32_t(blob[7]) << 24);
    return magic == kProofMagic && ver == kProofVersion;
}

} // namespace Regenerative
} // namespace Deep2
