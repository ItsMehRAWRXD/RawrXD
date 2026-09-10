#pragma once
// CandidateBindingPolicy — transient bindings under fixed authority.
// C++17, no third-party deps. Not wired into decode until COMPILE receipt.
#include <cstdint>

namespace rawrxd::runtime {

enum class CandidateClass : uint8_t {
    BraidCandidate = 1,
    SchedulerHint,
    FaultRecovery,
    TransientBinding,
    CoverageRankOnly,
    HistoricalSignal,
    BlockedReadbackDownward,
    HostConsumerReadback,
    RejectedAuthorityPath,
    DeadForStrict
};

enum class CandidateFlags : uint32_t {
    None = 0,
    Keep = 1u << 0,
    MayRun = 1u << 1,
    MayPromote = 1u << 2,
    AuthorityDenied = 1u << 3,
    ReadbackBlocked = 1u << 4
};

inline CandidateFlags operator|(CandidateFlags a, CandidateFlags b) {
    return static_cast<CandidateFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool HasFlag(CandidateFlags f, CandidateFlags bit) {
    return (static_cast<uint32_t>(f) & static_cast<uint32_t>(bit)) != 0;
}

struct CandidateBindingPolicy {
    // Survival invariant bits (must all be true to promote).
    bool fixed_graph = true;
    bool canonical_model_bytes = true;
    bool transient_bindings_only = true;
    bool no_downstream_readback_unless_host = true;
    bool parity = false;
    bool product_path = false;
    bool purity = false;

    static CandidateFlags DefaultFlags(CandidateClass c) {
        using F = CandidateFlags;
        switch (c) {
        case CandidateClass::BraidCandidate:
            return F::Keep | F::MayRun | F::AuthorityDenied;
        case CandidateClass::SchedulerHint:
            return F::Keep | F::MayRun | F::AuthorityDenied;
        case CandidateClass::FaultRecovery:
            return F::Keep | F::MayRun | F::AuthorityDenied;
        case CandidateClass::TransientBinding:
            return F::Keep | F::MayRun | F::MayPromote | F::AuthorityDenied;
        case CandidateClass::CoverageRankOnly:
            return F::Keep | F::AuthorityDenied;
        case CandidateClass::HistoricalSignal:
            return F::Keep | F::AuthorityDenied;
        case CandidateClass::BlockedReadbackDownward:
            return F::Keep | F::ReadbackBlocked | F::AuthorityDenied;
        case CandidateClass::HostConsumerReadback:
            return F::Keep | F::MayRun | F::AuthorityDenied;
        case CandidateClass::RejectedAuthorityPath:
            return F::AuthorityDenied;
        case CandidateClass::DeadForStrict:
            return F::AuthorityDenied;
        default:
            return F::AuthorityDenied;
        }
    }

    bool InvariantHolds() const {
        return fixed_graph && canonical_model_bytes && transient_bindings_only
            && no_downstream_readback_unless_host && parity && product_path
            && purity;
    }

    bool MayPromote(CandidateClass c) const {
        if (!InvariantHolds()) return false;
        return HasFlag(DefaultFlags(c), CandidateFlags::MayPromote);
    }
};

} // namespace rawrxd::runtime
