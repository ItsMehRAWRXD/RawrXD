#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace Deep2 { namespace ReapQuant {

enum class ExpertPrecision : uint8_t { Q2_K = 0, Q3_K = 1, Q4_K = 2 };

struct ExpertImportance {
    uint32_t layer = 0;
    uint32_t expert = 0;
    double score = 0.0;
    uint64_t q2Bytes = 0;
    uint64_t q3Bytes = 0;
    uint64_t q4Bytes = 0;
};

struct ExpertAllocation {
    uint32_t layer = 0;
    uint32_t expert = 0;
    ExpertPrecision precision = ExpertPrecision::Q2_K;
    uint64_t bytes = 0;
    double qualityScore = 0.0;
};

struct MixedPrecisionPlan {
    bool success = false;
    std::string error;
    uint64_t budgetBytes = 0;
    uint64_t totalBytes = 0;
    double qualityScore = 0.0;
    std::vector<ExpertAllocation> allocations;
};

inline const char* ExpertPrecisionName(ExpertPrecision precision) noexcept {
    switch (precision) {
    case ExpertPrecision::Q2_K: return "Q2_K";
    case ExpertPrecision::Q3_K: return "Q3_K";
    case ExpertPrecision::Q4_K: return "Q4_K";
    }
    return "UNKNOWN";
}

inline bool checkedAdd(uint64_t a, uint64_t b, uint64_t& result) noexcept {
    if (b > std::numeric_limits<uint64_t>::max() - a) return false;
    result = a + b;
    return true;
}

inline bool buildMixedPrecisionPlan(const std::vector<ExpertImportance>& experts,
                                    uint64_t budgetBytes,
                                    MixedPrecisionPlan& plan) {
    plan = MixedPrecisionPlan{};
    plan.budgetBytes = budgetBytes;
    if (experts.empty()) {
        plan.error = "no expert importance records";
        return false;
    }

    struct Candidate {
        size_t index = 0;
        ExpertPrecision from = ExpertPrecision::Q2_K;
        ExpertPrecision to = ExpertPrecision::Q3_K;
        uint64_t deltaBytes = 0;
        double gain = 0.0;
        double ratio = 0.0;
    };

    uint64_t total = 0;
    plan.allocations.reserve(experts.size());
    for (size_t i = 0; i < experts.size(); ++i) {
        const auto& input = experts[i];
        if (!std::isfinite(input.score) || input.score < 0.0 ||
            input.q2Bytes == 0 || input.q2Bytes > input.q3Bytes ||
            input.q3Bytes > input.q4Bytes) {
            plan.error = "invalid expert importance or byte ladder";
            return false;
        }
        if (!checkedAdd(total, input.q2Bytes, total)) {
            plan.error = "minimum mixed-precision allocation overflows";
            return false;
        }
        plan.allocations.push_back({input.layer, input.expert,
                                    ExpertPrecision::Q2_K, input.q2Bytes,
                                    input.score * 2.6});
        plan.qualityScore += input.score * 2.6;
    }
    if (total > budgetBytes) {
        plan.error = "budget cannot retain every expert at Q2_K";
        return false;
    }

    auto makeCandidate = [&](size_t index, ExpertPrecision from,
                             ExpertPrecision to) {
        const auto& input = experts[index];
        const uint64_t fromBytes = from == ExpertPrecision::Q2_K ? input.q2Bytes : input.q3Bytes;
        const uint64_t toBytes = to == ExpertPrecision::Q3_K ? input.q3Bytes : input.q4Bytes;
        const double fromBits = from == ExpertPrecision::Q2_K ? 2.6 : 3.5;
        const double toBits = to == ExpertPrecision::Q3_K ? 3.5 : 4.5;
        Candidate candidate;
        candidate.index = index;
        candidate.from = from;
        candidate.to = to;
        candidate.deltaBytes = toBytes - fromBytes;
        candidate.gain = input.score * (toBits - fromBits);
        candidate.ratio = candidate.deltaBytes ? candidate.gain / double(candidate.deltaBytes) : 0.0;
        return candidate;
    };

    while (true) {
        std::vector<Candidate> candidates;
        for (size_t i = 0; i < experts.size(); ++i) {
            const auto current = plan.allocations[i].precision;
            if (current == ExpertPrecision::Q2_K)
                candidates.push_back(makeCandidate(i, current, ExpertPrecision::Q3_K));
            else if (current == ExpertPrecision::Q3_K)
                candidates.push_back(makeCandidate(i, current, ExpertPrecision::Q4_K));
        }
        std::sort(candidates.begin(), candidates.end(), [&](const Candidate& a, const Candidate& b) {
            if (a.ratio != b.ratio) return a.ratio > b.ratio;
            if (a.gain != b.gain) return a.gain > b.gain;
            if (experts[a.index].layer != experts[b.index].layer)
                return experts[a.index].layer < experts[b.index].layer;
            return experts[a.index].expert < experts[b.index].expert;
        });

        const Candidate* selected = nullptr;
        for (const auto& candidate : candidates) {
            if (candidate.deltaBytes <= budgetBytes - total) {
                selected = &candidate;
                break;
            }
        }
        if (!selected) break;
        auto& allocation = plan.allocations[selected->index];
        allocation.precision = selected->to;
        allocation.bytes += selected->deltaBytes;
        allocation.qualityScore = experts[selected->index].score *
            (selected->to == ExpertPrecision::Q3_K ? 3.5 : 4.5);
        total += selected->deltaBytes;
        plan.qualityScore += selected->gain;
    }

    plan.totalBytes = total;
    plan.success = true;
    return true;
}

} } // namespace Deep2::ReapQuant
