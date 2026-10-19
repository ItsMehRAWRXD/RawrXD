#include "d2_nodep.h"

extern "C" int d2_validate_local_plan(const D2FabricPlan* p) {
    if (!p || !p->valid || p->total_rows == 0) return 0;
    const D2FabricSlice& a = p->lane[0];
    const D2FabricSlice& b = p->lane[1];
    if (a.gpu_index == b.gpu_index) return 0;
    if (a.row_count == 0 || b.row_count == 0) return 0;
    if (a.row_begin != 0 || b.row_begin != a.row_count) return 0;
    if (a.row_count + b.row_count != p->total_rows) return 0;
    if (a.local_weight_bytes == 0 || b.local_weight_bytes == 0) return 0;
    if (a.range.bytes != a.local_weight_bytes || b.range.bytes != b.local_weight_bytes) return 0;
    if (a.range.offset + a.range.bytes > b.range.offset) return 0;
    return 1;
}
