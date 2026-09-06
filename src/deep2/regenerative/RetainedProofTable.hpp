// RetainedProofTable.hpp — surviving physical deductions (not patch history)
#pragma once
#include "ProofFactEnvelope.hpp"
#include "RegenerativeTypes.hpp"
#include <cstdio>
#include <cstring>
#include <string>

namespace Deep2 {
namespace Regenerative {

enum class ProofKind : uint8_t {
    TimeRemoval = 0,
    OutputEquivalent = 1,
    ResourceCap = 2,
    AuthorityUnchanged = 3,
    CriticalPathCut = 4,
    WorkAvoidance = 5
};

struct RetainedProof {
    ProofKind kind = ProofKind::TimeRemoval;
    char ruleId[48]{};
    double measuredNetRemovalMs = 0.0;
    double confidence = 0.0;
    uint64_t sourceGeneration = 0;
    TimeReversal::Hash256 evidenceSha{};
    ProofFactEnvelope envelope{}; // valid only inside this sealed envelope
    bool active = false;
};

struct RetainedProofTable {
    static constexpr int kMax = 64;
    RetainedProof entries[kMax]{};
    int count = 0;
    TimeReversal::Hash256 tableSha{};
    ProofFactEnvelope tableEnvelope{};

    bool Add(const RetainedProof& p) {
        if (count >= kMax || !p.active) return false;
        for (int i = 0; i < count; ++i) {
            if (std::strncmp(entries[i].ruleId, p.ruleId, sizeof(p.ruleId)) == 0) {
                if (p.measuredNetRemovalMs >= entries[i].measuredNetRemovalMs)
                    entries[i] = p;
                return true;
            }
        }
        entries[count++] = p;
        return true;
    }

    int ActiveCount() const {
        int n = 0;
        for (int i = 0; i < count; ++i) if (entries[i].active) ++n;
        return n;
    }

    double TotalMeasuredRemovalMs() const {
        double s = 0.0;
        for (int i = 0; i < count; ++i)
            if (entries[i].active) s += entries[i].measuredNetRemovalMs;
        return s;
    }

    bool EphemeralSlotsAllZero(const uint64_t* slots, int n) const {
        if (!slots || n <= 0) return true;
        for (int i = 0; i < n; ++i) if (slots[i] != 0) return false;
        return true;
    }
};

inline std::string FormatProofTable(const RetainedProofTable& t) {
    char buf[1024];
    int n = std::snprintf(buf, sizeof(buf),
        "RETAINED_PROOFS active=%d total_removal=%.2f ms\n",
        t.ActiveCount(), t.TotalMeasuredRemovalMs());
    for (int i = 0; i < t.count && n < (int)sizeof(buf) - 64; ++i) {
        if (!t.entries[i].active) continue;
        n += std::snprintf(buf + n, sizeof(buf) - n, "  %-20s %.2f ms conf=%.2f G%llu\n",
            t.entries[i].ruleId, t.entries[i].measuredNetRemovalMs,
            t.entries[i].confidence,
            static_cast<unsigned long long>(t.entries[i].sourceGeneration));
    }
    return std::string(buf);
}

} // namespace Regenerative
} // namespace Deep2
