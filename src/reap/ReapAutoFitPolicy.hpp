#pragma once

#include <cstdint>
#include <string>

namespace RawrXD::Reap {

// Unified, non-destructive optimization policy.  This describes the search
// contract; it does not claim that an unvalidated kernel, precision, or
// pruning choice is safe.  Candidate selection remains fail-closed until the
// hard constraints are measured for the requested model and device.
struct AutoFitPolicy {
    static constexpr const char* kSchema = "rawrxd.reap.autofit.policy.v1";

    bool maximumQuality = true;
    bool qualityPerformance = true;
    bool maximumThroughput = true;
    bool minimumMemory = true;
    bool qualityConstraintRequired = true;
    bool paretoOptimization = true;
    bool iterativeCalibration = true;
    bool automaticProfiling = true;
    bool automaticRefinement = true;
    uint64_t targetTps = 150;
    uint32_t targetAgents = 6;
    std::string outputFormat = "DEEP2_NATIVE";

    static AutoFitPolicy All() { return {}; }

    bool valid(std::string& error) const {
        error.clear();
        if (!maximumQuality || !qualityPerformance || !maximumThroughput || !minimumMemory) {
            error = "POLICY_ALL_REQUIRES_ALL_OBJECTIVES";
            return false;
        }
        if (!qualityConstraintRequired) {
            error = "QUALITY_CONSTRAINT_REQUIRED";
            return false;
        }
        if (!paretoOptimization || !iterativeCalibration || !automaticProfiling ||
            !automaticRefinement) {
            error = "POLICY_ALL_REQUIRES_ADAPTIVE_SEARCH_FLAGS";
            return false;
        }
        if (targetTps == 0 || targetAgents == 0) {
            error = "TARGETS_MUST_BE_NONZERO";
            return false;
        }
        if (outputFormat != "DEEP2_NATIVE") {
            error = "UNSUPPORTED_AUTOFIT_OUTPUT_FORMAT";
            return false;
        }
        return true;
    }

    std::string json() const {
        return std::string("{\"schema\":\"") + kSchema +
            "\",\"policy\":\"ALL\",\"optimization_mode\":\"MULTI_OBJECTIVE\""+
            ",\"maximum_quality\":true,\"quality_performance\":true"+
            ",\"maximum_throughput\":true,\"minimum_memory\":true"+
            ",\"quality_constraint\":\"REQUIRED\",\"pareto_optimization\":true"+
            ",\"iterative_calibration\":true,\"automatic_profiling\":true"+
            ",\"automatic_refinement\":true,\"target_tps\":" +
            std::to_string(targetTps) + ",\"target_agents\":" +
            std::to_string(targetAgents) + ",\"output_format\":\"" +
            outputFormat + "\"}";
    }
};

} // namespace RawrXD::Reap
