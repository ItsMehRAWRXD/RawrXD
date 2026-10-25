// RawrXD REAP unified policy — no external dependencies.
// This header defines validated runtime and structural controls; it does not
// alter model files or claim an inference speedup.
#pragma once
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace Deep2::Reap {
struct Options {
    std::uint64_t targetSizeBytes = 0; // 0 = no structural size target
    std::uint32_t activeExperts = 0;   // 0 = model default
    std::uint32_t expertBudget = 0;    // 0 = retain all
    double qualityFloor = 0.0;         // 0 = no threshold; otherwise (0,1]
    bool structuralRewrite = false;
};
struct Route {
    std::uint32_t expert = 0;
    float weight = 0.0f;
};
inline bool Validate(const Options& o, std::uint32_t totalExperts,
                     std::uint32_t modelActive, std::string& error) {
    if (totalExperts == 0 || modelActive == 0 || modelActive > totalExperts) {
        error = "Invalid model expert topology"; return false;
    }
    if (o.activeExperts > modelActive) {
        error = "active-experts exceeds model routing top-k"; return false;
    }
    if (o.expertBudget > totalExperts) {
        error = "expert-budget exceeds total experts"; return false;
    }
    const auto active = o.activeExperts ? o.activeExperts : modelActive;
    if (o.expertBudget && active > o.expertBudget) {
        error = "active-experts exceeds expert-budget"; return false;
    }
    if (!std::isfinite(o.qualityFloor) || o.qualityFloor < 0.0 ||
        o.qualityFloor > 1.0) {
        error = "quality-floor must be between 0 and 1"; return false;
    }
    if (o.structuralRewrite && !o.targetSizeBytes && !o.expertBudget) {
        error = "Structural rewrite requires target-size or expert-budget"; return false;
    }
    error.clear(); return true;
}
// Operates on already-ranked router selections. Preserves original weights
// and ordering: no unconditional softmax/renormalization.
inline bool SelectRuntimeRoutes(const std::vector<Route>& ranked,
                                std::uint32_t requested,
                                std::vector<Route>& selected,
                                std::string& error) {
    if (ranked.empty()) { error = "Empty router output"; return false; }
    const auto n = requested ? static_cast<std::size_t>(requested) : ranked.size();
    if (n > ranked.size()) { error = "Requested more routes than available"; return false; }
    for (const auto& r : ranked) {
        if (!std::isfinite(r.weight)) { error = "Nonfinite router weight"; return false; }
    }
    std::vector<Route> next(ranked.begin(), ranked.begin() + n);
    selected.swap(next);
    error.clear(); return true;
}
// Higher score is better. This gate cannot replace full perplexity / logit
// and task-quality validation performed by the calibration harness.
inline bool MeetsQualityFloor(double candidateScore, double referenceScore,
                              double floor, std::string& error) {
    if (!std::isfinite(candidateScore) || !std::isfinite(referenceScore) ||
        referenceScore <= 0.0 || floor <= 0.0 || floor > 1.0) {
        error = "Invalid quality gate inputs"; return false;
    }
    if (candidateScore / referenceScore < floor) {
        error = "REAP_QUALITY_FLOOR_FAILED"; return false;
    }
    error.clear(); return true;
}
} // namespace Deep2::Reap
