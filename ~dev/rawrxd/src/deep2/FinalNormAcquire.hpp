#pragma once
/* FinalNormAcquire — stub */
#include <cstddef>
namespace Deep2 {
namespace FinalNorm {
struct AcquisitionResult {
    bool valid = false;
    float rms = 0.f;
};
inline AcquisitionResult Acquire(class WeightTensor&, size_t /*hiddenDim*/,
    float* /*inOut*/, float* /*out*/,
    const char* /*modelPath*/) {
    return { true, 1.0f };
}
} // namespace FinalNorm
} // namespace Deep2

