#pragma once

#include "reap_cli_contract.hpp"

#include <string>

namespace RawrXD::Reap {

struct PipelineResult {
    int exitCode = 4;
    std::string receipt;
};

// Runs policy validation, MoE inventory, the existing writer gate, and
// EvaluateAdmission. Deep2 generation runs only after admission succeeds
// and a candidate path was published. The source GGUF is not rewritten here.
PipelineResult RunPipeline(const CliRequest& request, const std::string& prompt);

} // namespace RawrXD::Reap
