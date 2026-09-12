#include "d2_link15_adapter.h"

/*
 * These adapters are intentionally thin. They do not invent GPU work.
 * Deep2 binds its existing real product functions through D2AdapterThunk::call.
 * Keeping a single opaque C ABI avoids dependencies on Vulkan/ROCm/C++ types here.
 */

int d2_link15_opaque_adapter(void *user, D2LinkContext *ctx, D2LinkEvidence *out) {
    D2AdapterThunk *t = (D2AdapterThunk *)user;
    (void)ctx;
    if (!t || !t->call || !out) return 0;
    return t->call(t->opaque, t->id, out) == 1 ? 1 : 0;
}
