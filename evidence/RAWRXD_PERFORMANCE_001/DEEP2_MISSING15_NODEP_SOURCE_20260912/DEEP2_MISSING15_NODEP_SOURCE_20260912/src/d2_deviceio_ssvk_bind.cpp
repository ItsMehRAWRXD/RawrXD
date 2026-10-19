#include "d2_nodep.h"
#include <atomic>

static D2SsVkBinding g_binding{};
static std::atomic<uint32_t> g_bound{0};

extern "C" int d2_bind_ssvk(const D2SsVkBinding* b) {
    if (!b || !b->ctx || !b->enqueue || !b->collect || !b->reduce) return 0;
    g_binding = *b;
    g_bound.store(1, std::memory_order_release);
    return 1;
}

extern "C" int d2_get_ssvk(D2SsVkBinding* out) {
    if (!out || !g_bound.load(std::memory_order_acquire)) return 0;
    *out = g_binding;
    return 1;
}
