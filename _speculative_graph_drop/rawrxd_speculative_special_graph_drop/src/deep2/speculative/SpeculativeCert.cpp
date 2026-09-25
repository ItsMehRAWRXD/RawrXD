#include "SpeculativeCert.hpp"

#include <sstream>

namespace rawrxd::deep2::spec {

SpeculativeCert makeSpeculativeCert(const SpeculativeCertInput& input) {
    const bool generatedSomething = input.stats.committedTokens > 0;
    const bool parity = input.parityMismatches == 0;
    const bool noStubs = input.stubFallbacks == 0;
    const bool rollbackOk =
        input.stats.rollbackCalls == 0 || input.kvRollbackVerified;

    const bool pass =
        generatedSomething &&
        parity &&
        noStubs &&
        rollbackOk &&
        input.strictGpuAuthority;

    std::ostringstream os;
    os << "=== RAWRXD_SPECULATIVE_SPECIAL_GRAPH_001 ===\n";
    os << "COMMITTED_TOKENS=" << input.stats.committedTokens << "\n";
    os << "PROPOSED_TOKENS=" << input.stats.proposedTokens << "\n";
    os << "ACCEPTED_DRAFT_TOKENS=" << input.stats.acceptedDraftTokens << "\n";
    os << "REPLACEMENT_TOKENS=" << input.stats.replacementTokens << "\n";
    os << "ROLLBACK_CALLS=" << input.stats.rollbackCalls << "\n";
    os << "TARGET_ONLY_TOKENS=" << input.targetOnlyTokens << "\n";
    os << "PARITY_MISMATCHES=" << input.parityMismatches << "\n";
    os << "KV_ROLLBACK_VERIFIED=" << (input.kvRollbackVerified ? "PASS" : "FAIL") << "\n";
    os << "STRICT_GPU_AUTHORITY=" << (input.strictGpuAuthority ? "PASS" : "FAIL") << "\n";
    os << "STUB_FALLBACKS=" << input.stubFallbacks << "\n";
    os << "VERDICT=" << (pass ? "PASS" : "FAIL") << "\n";

    return SpeculativeCert{pass, os.str()};
}

} // namespace rawrxd::deep2::spec
