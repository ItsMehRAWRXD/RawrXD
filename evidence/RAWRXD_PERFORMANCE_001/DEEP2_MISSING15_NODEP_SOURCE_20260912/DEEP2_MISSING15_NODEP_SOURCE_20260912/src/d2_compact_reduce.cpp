#include "d2_nodep.h"

extern "C" int d2_compact_reduce(const D2FabricTicket* a, const D2FabricTicket* b, D2ReduceReceipt* out) {
    if (!a || !b || !out) return 0;
    D2SsVkBinding bind{};
    if (!d2_get_ssvk(&bind)) return 0;
    *out = {};
    return bind.reduce(bind.ctx, a, b, out) ? 1 : 0;
}
