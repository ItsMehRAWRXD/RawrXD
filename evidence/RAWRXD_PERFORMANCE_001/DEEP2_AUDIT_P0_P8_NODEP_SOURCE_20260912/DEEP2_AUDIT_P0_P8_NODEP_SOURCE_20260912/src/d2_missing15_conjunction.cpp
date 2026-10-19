#include "deep2_audit_nodep.h"
extern "C" int d2_missing15_all(const D2Missing15Bits* b) {
    if (!b) return 0;
    for (uint32_t i=0;i<15;i++) if (!b->bit[i]) return 0;
    return 1;
}
