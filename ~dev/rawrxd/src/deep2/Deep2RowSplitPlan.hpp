#pragma once
// Deep2RowSplitPlan.hpp — pure deterministic two-device row partition.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace Deep2 {

struct RowSplitPlan {
    bool valid = false;
    uint32_t row0Begin = 0;
    uint32_t row0Count = 0;
    uint32_t row1Begin = 0;
    uint32_t row1Count = 0;
};

inline RowSplitPlan Deep2ChooseRowSplit(
    uint32_t rows, uint64_t capacity0, uint64_t capacity1) noexcept
{
    RowSplitPlan p{};
    if (rows < 2 || capacity0 == 0 || capacity1 == 0) return p;
    if (capacity0 > std::numeric_limits<uint64_t>::max() - capacity1)
        return p;
    const uint64_t total = capacity0 + capacity1;

    long double exact =
        static_cast<long double>(rows) *
        static_cast<long double>(capacity0) /
        static_cast<long double>(total);
    uint32_t n0 = static_cast<uint32_t>(exact + 0.5L);
    n0 = std::max<uint32_t>(1, std::min<uint32_t>(rows - 1, n0));
    const uint32_t n1 = rows - n0;

    p.valid = n0 != 0 && n1 != 0;
    p.row0Begin = 0;
    p.row0Count = n0;
    p.row1Begin = n0;
    p.row1Count = n1;
    return p;
}

} // namespace Deep2
