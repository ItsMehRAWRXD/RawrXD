#pragma once
/* FinalNormProduce — stub */
#include <cstddef>
namespace Deep2 {
namespace FinalNorm {
struct FinalNormResult {
    bool valid = false;
};
inline FinalNormResult ProduceFinalHidden(float* /*inOut*/, float* /*out*/,
    struct AcquisitionResult /*acq*/, size_t /*hiddenDim*/, float /*eps*/) {
    return { true };
}
} // namespace FinalNorm
} // namespace Deep2

