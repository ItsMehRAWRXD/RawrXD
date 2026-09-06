// ============================================================================
// W0HexMagBridge.hpp — W0 solver as HexMag CandidateGenerator (CANDIDATE_ONLY)
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_HEXMAG_BRIDGE_HPP
#define RAWRXD_DEEP2W0_W0_HEXMAG_BRIDGE_HPP

#include "core/hexmag_oracle_binder.hpp"
#include "deep2w0/W0Engine.hpp"

#include <string>

namespace RawrXD {
namespace W0 {

struct W0CandidateGenerator final : HexMag::CandidateGenerator {
    std::string workspaceRoot;
    W0Result last;

    bool available() const override { return true; }
    HexMag::CandidateSource source() const override {
        return HexMag::CandidateSource::W0;
    }

    std::string generate(const std::string& prompt,
                         const std::string& /*roleContext*/) override {
        W0Request req;
        req.task = prompt;
        req.workspaceRoot = workspaceRoot;
        last = W0Engine().solve(req);
        if (last.needInput) return {}; // binder treats empty as failure; control plane NEED_INPUT wins first
        if (last.candidateSource.empty()) return {};
        return last.candidateSource;
    }
};

/// Verifier: W0 structural evidence already computed — re-check candidate text.
inline bool w0StructuralVerifier(const HexMag::CandidateArtifact& a) {
    return a.status == HexMag::CandidateStatus::Ok
        && a.text.find("return ") != std::string::npos
        && a.source == HexMag::CandidateSource::W0;
}

} // namespace W0
} // namespace RawrXD

#endif
