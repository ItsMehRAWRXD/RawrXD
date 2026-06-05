#pragma once

#include "../core/patch_result.hpp"

#include <cstdint>
#include <string>

namespace RawrXD::Inference {

// Converts a model file loadable by ModelLoader into RXQF container format.
// Fail-closed: returns PatchResult::error on any parse or write failure.
PatchResult ConvertModelToRXQF(const std::string& input_model_path,
                               const std::string& output_rxqf_path,
                               bool emit_name_table = true,
                               uint64_t global_alignment = 64);

} // namespace RawrXD::Inference
