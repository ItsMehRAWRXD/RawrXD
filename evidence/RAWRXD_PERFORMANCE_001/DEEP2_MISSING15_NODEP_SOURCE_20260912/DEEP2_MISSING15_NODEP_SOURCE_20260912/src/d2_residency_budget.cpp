#include "d2_nodep.h"
#include <algorithm>

static uint64_t d2_score(const D2ResidencyItem& x) {
    if (x.pinned) return ~0ull;
    if (!x.bytes) return 0;
    const unsigned long long a = x.reuse_ppm ? x.reuse_ppm : 1;
    const unsigned long long b = x.criticality_ppm ? x.criticality_ppm : 1;
    // Overflow-safe ordering proxy: scale each term before multiply.
    return ((a >> 10) + 1) * ((b >> 10) + 1) * 1000000ull / ((x.bytes >> 20) + 1);
}

extern "C" int d2_residency_solve(D2ResidencyItem* items, size_t count, uint64_t budget, uint64_t* selected_bytes) {
    if (!items || !selected_bytes) return 0;
    *selected_bytes = 0;
    for (size_t i=0;i<count;i++) items[i].selected = 0;
    // First pass: mandatory pins.
    for (size_t i=0;i<count;i++) if (items[i].pinned) {
        if (items[i].bytes > budget - *selected_bytes) return 0;
        items[i].selected = 1;
        *selected_bytes += items[i].bytes;
    }
    // O(n^2) selection keeps the drop allocation-free and deterministic.
    for (;;) {
        size_t best = count; uint64_t best_score = 0;
        for (size_t i=0;i<count;i++) {
            if (items[i].selected || items[i].pinned || !items[i].bytes) continue;
            if (items[i].bytes > budget - *selected_bytes) continue;
            uint64_t s=d2_score(items[i]);
            if (best==count || s>best_score) { best=i; best_score=s; }
        }
        if (best==count) break;
        items[best].selected=1;
        *selected_bytes += items[best].bytes;
    }
    return 1;
}
