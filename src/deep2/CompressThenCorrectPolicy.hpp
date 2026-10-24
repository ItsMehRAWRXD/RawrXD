#pragma once
#include <cmath>
#include <cstdint>
namespace rawrxd::deep2 {
enum class CorrectionDecision : std::uint8_t { Invalid, Exact, Approximate };
struct CorrectionPolicy { float minimumMargin = 0.45f; bool enableApproximate = false; };
inline CorrectionDecision decideCorrection(float best, float runnerUp, const CorrectionPolicy& policy) noexcept {
 if (!std::isfinite(best) || !std::isfinite(runnerUp) || !std::isfinite(policy.minimumMargin) || policy.minimumMargin < 0 || runnerUp > best) return CorrectionDecision::Invalid;
 if (!policy.enableApproximate || static_cast<double>(best) - runnerUp <= policy.minimumMargin) return CorrectionDecision::Exact;
 return CorrectionDecision::Approximate;
}
}
