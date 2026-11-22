#pragma once

#include "ReapMixedPrecisionPlanner.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace Deep2 { namespace ReapQuant {

struct ActivationQualityProfile {
    uint32_t layer = 0;
    uint32_t expert = 0;
    double activationEnergy = 0.0;
    double q2Error = 0.0;
    double q3Error = 0.0;
    double q4Error = 0.0;
    uint64_t q2Bytes = 0;
    uint64_t q3Bytes = 0;
    uint64_t q4Bytes = 0;
};

struct ActivationPlan {
    bool success = false;
    std::string error;
    uint64_t budgetBytes = 0;
    uint64_t totalBytes = 0;
    double baselineWeightedError = 0.0;
    double weightedError = 0.0;
    std::vector<ExpertAllocation> allocations;
};

inline bool buildActivationWeightedPlan(
    const std::vector<ActivationQualityProfile>& profiles,
    uint64_t budgetBytes, ActivationPlan& plan) {
    plan = ActivationPlan{};
    plan.budgetBytes = budgetBytes;
    if (profiles.empty()) {
        plan.error = "no activation quality profiles";
        return false;
    }
    uint64_t total = 0;
    for (const auto& profile : profiles) {
        if (!std::isfinite(profile.activationEnergy) || profile.activationEnergy < 0.0 ||
            !std::isfinite(profile.q2Error) || !std::isfinite(profile.q3Error) ||
            !std::isfinite(profile.q4Error) || profile.q2Error < profile.q3Error ||
            profile.q3Error < profile.q4Error || profile.q2Bytes == 0 ||
            profile.q2Bytes > profile.q3Bytes || profile.q3Bytes > profile.q4Bytes) {
            plan.error = "invalid activation quality profile";
            return false;
        }
        if (!checkedAdd(total, profile.q2Bytes, total)) {
            plan.error = "minimum activation allocation overflows";
            return false;
        }
        const double weighted = profile.activationEnergy * profile.q2Error;
        plan.baselineWeightedError += weighted;
        plan.weightedError += weighted;
        plan.allocations.push_back({profile.layer, profile.expert,
                                    ExpertPrecision::Q2_K, profile.q2Bytes,
                                    weighted});
    }
    if (total > budgetBytes) {
        plan.error = "budget cannot retain every profile at Q2_K";
        return false;
    }

    struct Upgrade {
        size_t index = 0;
        ExpertPrecision from = ExpertPrecision::Q2_K;
        ExpertPrecision to = ExpertPrecision::Q3_K;
        uint64_t deltaBytes = 0;
        double errorReduction = 0.0;
        double ratio = 0.0;
    };
    auto candidate = [&](size_t index, ExpertPrecision from, ExpertPrecision to) {
        const auto& p = profiles[index];
        const uint64_t fromBytes = from == ExpertPrecision::Q2_K ? p.q2Bytes : p.q3Bytes;
        const uint64_t toBytes = to == ExpertPrecision::Q3_K ? p.q3Bytes : p.q4Bytes;
        const double fromError = from == ExpertPrecision::Q2_K ? p.q2Error : p.q3Error;
        const double toError = to == ExpertPrecision::Q3_K ? p.q3Error : p.q4Error;
        Upgrade u;
        u.index = index;
        u.from = from;
        u.to = to;
        u.deltaBytes = toBytes - fromBytes;
        u.errorReduction = p.activationEnergy * (fromError - toError);
        u.ratio = u.deltaBytes ? u.errorReduction / double(u.deltaBytes) : 0.0;
        return u;
    };

    while (true) {
        std::vector<Upgrade> upgrades;
        for (size_t i = 0; i < profiles.size(); ++i) {
            const auto precision = plan.allocations[i].precision;
            if (precision == ExpertPrecision::Q2_K)
                upgrades.push_back(candidate(i, precision, ExpertPrecision::Q3_K));
            else if (precision == ExpertPrecision::Q3_K)
                upgrades.push_back(candidate(i, precision, ExpertPrecision::Q4_K));
        }
        std::sort(upgrades.begin(), upgrades.end(), [&](const Upgrade& a, const Upgrade& b) {
            if (a.ratio != b.ratio) return a.ratio > b.ratio;
            if (a.errorReduction != b.errorReduction) return a.errorReduction > b.errorReduction;
            if (profiles[a.index].layer != profiles[b.index].layer)
                return profiles[a.index].layer < profiles[b.index].layer;
            return profiles[a.index].expert < profiles[b.index].expert;
        });
        const Upgrade* selected = nullptr;
        for (const auto& upgrade : upgrades) {
            if (upgrade.deltaBytes <= budgetBytes - total && upgrade.errorReduction > 0.0) {
                selected = &upgrade;
                break;
            }
        }
        if (!selected) break;
        auto& allocation = plan.allocations[selected->index];
        allocation.precision = selected->to;
        allocation.bytes += selected->deltaBytes;
        total += selected->deltaBytes;
        plan.weightedError -= selected->errorReduction;
    }
    plan.totalBytes = total;
    plan.success = true;
    return true;
}

} } // namespace Deep2::ReapQuant
