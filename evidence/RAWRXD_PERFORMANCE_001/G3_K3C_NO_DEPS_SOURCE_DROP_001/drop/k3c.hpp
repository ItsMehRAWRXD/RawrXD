#pragma once
/* G3_K3C_NO_DEPS_SOURCE_DROP_001 — STUB-ONLY drop surface (not live product).
 * PROMOTE=0 TIP_CLIMB=HOLD. Real bind lives in src/deep2/lavapath/k3c_token.cpp. */

#ifdef __cplusplus
extern "C" {
#endif

unsigned k3c(unsigned token); /* FAIL_CLOSED identity under this drop */

#ifdef __cplusplus
}
#endif

/* Drive shape only. Do not claim product generate PASS from stub bind. */
static inline void k3c_drive(unsigned token) {
    for (;;) token = k3c(token); /* stub: echo; live tree: ProductRuntime decode */
}
