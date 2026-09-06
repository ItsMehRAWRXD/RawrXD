// RegenerativeVerify.hpp — C++ mirror of VerifyAndRegenerateRuntimeImage
#pragma once
#include "RegenerativeTypes.hpp"

namespace Deep2 {
namespace Regenerative {

// PATCH_HISTORY_IS_NOT_RUNTIME_AUTHORITY: no patch-history parameter exists.
inline int VerifyAndRegenerateRuntimeImage(const GenerationAuthorityRecord* rec) {
    if (!rec) return 0;
    if (rec->retainedProofsTablePtr == 0) return 0;
    if (rec->currentBudgetLimitMsFixed == 0) return 0;
    return 1;
}

} // namespace Regenerative
} // namespace Deep2
