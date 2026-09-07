// RKCEmit.cpp — minimal proof-state prompt
#include "RKCEmit.hpp"
#include <sstream>

namespace RawrXD {
namespace RKC {

std::string EmitState(const ProofState& proof) {
    std::ostringstream o;
    o << "[GOAL]\n" << proof.goal << "\n\n";
    o << "[TASK]\n" << proof.task << "\n\n";

    o << "[KNOWN]\n";
    if (proof.known.empty()) {
        o << "(none)\n";
    } else {
        for (const auto& a : proof.known) {
            o << "FACT " << a.key << "  " << EpistemicName(a.state) << "  "
              << a.value << "\n";
        }
    }
    o << "\n[MISSING]\n";
    if (proof.missing.empty()) {
        o << "(none)\n";
    } else {
        for (const auto& a : proof.missing) {
            o << "NEED " << a.key << "  " << EpistemicName(a.state);
            if (!a.value.empty()) o << "  " << a.value;
            o << "\n";
        }
    }
    o << "\n[NEGATIVE]\n";
    if (proof.negative.empty()) {
        o << "(none)\n";
    } else {
        for (const auto& a : proof.negative) {
            o << "NEG " << a.key << "  " << EpistemicName(a.state) << "  "
              << a.value << "\n";
        }
    }
    if (!proof.syntheticCandidates.empty()) {
        o << "\n[SYNTHETIC_CANDIDATES]\n";
        for (const auto& c : proof.syntheticCandidates)
            o << "- " << c << "\n";
        o << "(candidates only; not REAL)\n";
    }
    o << "\n[CONSTRAINT]\n";
    for (const auto& c : proof.constraints) o << "- " << c << "\n";
    o << "\n[INSTRUCTION]\n";
    o << "Answer from KNOWN/NEGATIVE only. Resolve MISSING via observe/derive.\n";
    o << "Do not invent REAL facts. SYNTHETIC cannot become REAL.\n";
    return o.str();
}

} // namespace RKC
} // namespace RawrXD
