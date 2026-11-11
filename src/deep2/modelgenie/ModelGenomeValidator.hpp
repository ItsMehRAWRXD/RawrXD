//=============================================================================
// ModelGenomeValidator - Completeness and Correctness Checks
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//=============================================================================

#pragma once

#include "ModelGenome.hpp"
#include <vector>
#include <string>

namespace RawrXD {
namespace Deep2 {
namespace ModelGenie {

struct ValidationResult {
    bool valid = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    
    void AddError(const std::string& msg) {
        valid = false;
        errors.push_back(msg);
    }
    
    void AddWarning(const std::string& msg) {
        warnings.push_back(msg);
    }
};

bool ValidateModelGenome(const ModelGenome& genome, ValidationResult& result);

} // namespace ModelGenie
} // namespace Deep2
} // namespace RawrXD