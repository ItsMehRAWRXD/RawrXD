#include "deep2/ReapMixedPrecisionPlanner.hpp"

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

    const std::vector<ExpertImportance> experts = {
        {0, 0, 100.0, 100, 140, 180},
        {0, 1, 20.0, 100, 140, 180},
        {1, 0, 60.0, 100, 140, 180},
        {1, 1, 5.0, 100, 140, 180},
    };
    MixedPrecisionPlan plan;
    check(buildMixedPrecisionPlan(experts, 580, plan), "mixed precision plan builds");
    check(plan.success && plan.totalBytes <= plan.budgetBytes,
          "allocation stays within hard budget");
    check(plan.allocations.size() == experts.size(), "one allocation per expert");
    check(plan.allocations[0].precision == ExpertPrecision::Q4_K,
          "highest-importance expert reaches Q4_K");
    check(plan.allocations[2].precision == ExpertPrecision::Q4_K,
          "second high-importance expert reaches Q4_K");
    check(plan.allocations[3].precision == ExpertPrecision::Q2_K,
          "low-importance expert remains at Q2_K");
    check(plan.qualityScore > 0.0, "quality objective is measured");

    MixedPrecisionPlan repeat;
    check(buildMixedPrecisionPlan(experts, 580, repeat) &&
              repeat.totalBytes == plan.totalBytes &&
              repeat.qualityScore == plan.qualityScore &&
              repeat.allocations.size() == plan.allocations.size() &&
              repeat.allocations[0].precision == plan.allocations[0].precision &&
              repeat.allocations[2].precision == plan.allocations[2].precision,
          "allocation is deterministic");

    MixedPrecisionPlan rejected;
    check(!buildMixedPrecisionPlan(experts, 399, rejected) &&
              rejected.error.find("Q2_K") != std::string::npos,
          "budget below Q2 floor rejected");
    const std::vector<ExpertImportance> invalid = {
        {0, 0, std::numeric_limits<double>::quiet_NaN(), 100, 140, 180}};
    check(!buildMixedPrecisionPlan(invalid, 1000, rejected),
          "nonfinite importance rejected");
    check(!buildMixedPrecisionPlan({}, 1000, rejected),
          "empty importance input rejected");

    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n", pass, fail);
    return fail ? 1 : 0;
}
