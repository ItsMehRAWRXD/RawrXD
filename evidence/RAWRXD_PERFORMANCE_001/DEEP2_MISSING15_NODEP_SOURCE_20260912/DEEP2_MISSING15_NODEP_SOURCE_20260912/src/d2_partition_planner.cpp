#include "d2_nodep.h"
#include <limits>

extern "C" int d2_plan_rows_bw(uint32_t total_rows, uint64_t bw0, uint64_t bw1, uint64_t bytes_per_row, D2FabricPlan* out) {
    if (!out || !total_rows || !bw0 || !bw1 || !bytes_per_row) return 0;
    const uint64_t sum = bw0 + bw1;
    if (sum < bw0) return 0;
    uint64_t rows0 = (uint64_t(total_rows) * bw0 + (sum / 2)) / sum;
    if (rows0 == 0) rows0 = 1;
    if (rows0 >= total_rows) rows0 = total_rows - 1;
    const uint32_t r0 = static_cast<uint32_t>(rows0);
    const uint32_t r1 = total_rows - r0;
    out->lane[0] = {0u, 0u, r0, uint64_t(r0) * bytes_per_row, {0u, uint64_t(r0) * bytes_per_row}};
    out->lane[1] = {1u, r0, r1, uint64_t(r1) * bytes_per_row, {uint64_t(r0) * bytes_per_row, uint64_t(r1) * bytes_per_row}};
    out->total_rows = total_rows;
    out->valid = 1;
    return 1;
}
