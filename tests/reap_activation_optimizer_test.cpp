#include "deep2/ReapActivationOptimizer.hpp"

#include <cstdio>
#include <limits>
#include <vector>

using namespace Deep2::ReapQuant;

int main() {
    int pass = 0;
    int fail = 0;
    const auto check = [&](bool ok, const char* name) {
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
        ok ? ++pass : ++fail;
    };

    const std::vector<ActivationQualityProfile> profiles = {
        {0, 0, 100.0, 1.00, 0.35, 0.08, 100, 140, 180},
        {0, 1, 1.0, 1.00, 0.95, 0.90, 100, 140, 180},
        {1, 0, 20.0, 0.70, 0.25, 0.04, 100, 140, 180},
    };
    ActivationPlan plan;
    check(buildActivationWeightedPlan(profiles, 420, plan),
          "activation-weighted plan builds");
    check(plan.success && plan.totalBytes <= plan.budgetBytes,
          "activation plan stays within hard budget");
    check(plan.baselineWeightedError > plan.weightedError,
          "activation-weighted reconstruction error improves");
    check(plan.allocations[0].precision == ExpertPrecision::Q4_K,
          "high-energy high-loss expert reaches Q4_K");
    check(plan.allocations[1].precision == ExpertPrecision::Q2_K,
          "low-energy expert remains at Q2_K");
    check(plan.allocations[2].precision == ExpertPrecision::Q3_K,
          "next best activation gain reaches Q3_K");

    ActivationPlan repeat;
    check(buildActivationWeightedPlan(profiles, 420, repeat) &&
              repeat.totalBytes == plan.totalBytes &&
              repeat.weightedError == plan.weightedError &&
              repeat.allocations[0].precision == plan.allocations[0].precision &&
              repeat.allocations[2].precision == plan.allocations[2].precision,
          "activation allocation is deterministic");

    ActivationPlan rejected;
    check(!buildActivationWeightedPlan(profiles, 299, rejected) &&
              rejected.error.find("Q2_K") != std::string::npos,
          "activation budget below Q2 floor rejected");
    auto invalid = profiles;
    invalid[1].q3Error = std::numeric_limits<double>::quiet_NaN();
    check(!buildActivationWeightedPlan(invalid, 1000, rejected),
          "nonfinite reconstruction metric rejected");

    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n", pass, fail);
    return fail ? 1 : 0;
}
