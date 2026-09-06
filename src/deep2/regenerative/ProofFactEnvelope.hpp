// ProofFactEnvelope.hpp — sealed hardware/workload/budget/ABI binding
#pragma once
#include "RegenerativeFacts.hpp"
#include "Sha256.hpp"
#include <cstring>

namespace Deep2 {
namespace Regenerative {

struct ProofFactEnvelope {
    TimeReversal::Hash256 hardwareSha{};
    TimeReversal::Hash256 workloadSha{};
    TimeReversal::Hash256 budgetSha{};
    TimeReversal::Hash256 kernelAbiSha{};
};

inline TimeReversal::Hash256 HashHardwareFacts(const HardwareFacts& h) {
    return Sha256Bytes(&h, sizeof(h));
}
inline TimeReversal::Hash256 HashWorkloadFacts(const WorkloadFacts& w) {
    return Sha256Bytes(&w, sizeof(w));
}
inline TimeReversal::Hash256 HashBudgetFacts(const BudgetFacts& b) {
    return Sha256Bytes(&b, sizeof(b));
}
inline TimeReversal::Hash256 HashKernelAbi(const char* abiTag) {
    const char* t = abiTag ? abiTag : "rawrxd.deep2.abi.v1";
    return Sha256Bytes(t, std::strlen(t));
}

inline ProofFactEnvelope MakeEnvelope(const HardwareFacts& h, const WorkloadFacts& w,
                                      const BudgetFacts& b, const char* kernelAbiTag) {
    ProofFactEnvelope e;
    e.hardwareSha = HashHardwareFacts(h);
    e.workloadSha = HashWorkloadFacts(w);
    e.budgetSha = HashBudgetFacts(b);
    e.kernelAbiSha = HashKernelAbi(kernelAbiTag);
    return e;
}

inline bool EnvelopeMatch(const ProofFactEnvelope& a, const ProofFactEnvelope& b) {
    return HashEq(a.hardwareSha, b.hardwareSha) &&
           HashEq(a.workloadSha, b.workloadSha) &&
           HashEq(a.budgetSha, b.budgetSha) &&
           HashEq(a.kernelAbiSha, b.kernelAbiSha);
}

} // namespace Regenerative
} // namespace Deep2
