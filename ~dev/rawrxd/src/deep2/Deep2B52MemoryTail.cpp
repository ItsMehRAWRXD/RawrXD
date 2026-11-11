#include "Deep2B52MemoryTail.hpp"
#include <algorithm>

namespace Deep2 {

B52MemoryPlan B52MemoryTail::make(const B52MemoryShape& s) noexcept {
    B52MemoryPlan p{};
    p.vectorBytes = s.quantBits <= 4 ? 16u : 32u;
    p.burstBytes = s.cols >= 8192 ? 256u : 128u;
    p.rowsPerGroup = s.rows >= 16384 ? 8u : (s.rows >= 8192 ? 4u : 2u);
    p.xBroadcastTile = s.cols >= 8192 ? 1024u : 512u;
    p.prefetchDistance = s.cols >= 8192 ? 12u : 8u;
    return p;
}

double B52MemoryTail::payloadEfficiency(const B52MemoryShape& s,
                                        uint64_t actualBytesRead) noexcept {
    if (!actualBytesRead) return 0.0;
    const uint64_t bits = s.quantBits;
    const uint64_t q = (uint64_t(s.rows) * uint64_t(s.cols) * bits + 7ull) / 8ull;
    const uint64_t groups = (uint64_t(s.cols) + s.blockSize - 1ull) / s.blockSize;
    const uint64_t scales = uint64_t(s.rows) * groups * 4ull;
    const uint64_t x = uint64_t(s.cols) * 4ull;
    const uint64_t y = uint64_t(s.rows) * 4ull;
    const double useful = double(q + scales + x + y);
    return useful / double(actualBytesRead);
}

}
