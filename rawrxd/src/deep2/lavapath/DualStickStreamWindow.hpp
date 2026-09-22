#pragma once
/* DualStickStreamWindow — stub */
#include <cstddef>
#include <cstdint>
namespace Deep2 {
inline void DualStickAcquire(unsigned /*slot*/, const float* /*data*/,
                             size_t /*bytes*/, unsigned /*streamId*/,
                             uint32_t /*layer*/, unsigned /*priority*/) {}
inline void DualStickResolve(unsigned /*slot*/, uint32_t /*layer*/) {}
struct DualStickState {
    bool armed = false;
    uint64_t forwardCallsGpu0 = 0;
    uint64_t forwardCallsGpu1 = 0;
};
} // namespace Deep2

