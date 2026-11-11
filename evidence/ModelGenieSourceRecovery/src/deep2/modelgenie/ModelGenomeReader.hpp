//=============================================================================
// ModelGenomeReader - Loads Frozen NUGVERSE_ESTIMATOR_001 Evidence
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//=============================================================================

#pragma once

#include "ModelGenome.hpp"

namespace RawrXD {
namespace Deep2 {
namespace ModelGenie {

// Load ModelGenome from frozen NUGVERSE_ESTIMATOR_001 evidence
bool LoadModelGenomeFromEvidence(const std::string& evidenceDir, ModelGenome& genome);

} // namespace ModelGenie
} // namespace Deep2
} // namespace RawrXD