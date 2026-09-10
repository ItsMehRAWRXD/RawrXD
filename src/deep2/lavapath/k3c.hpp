#pragma once
/* Live TOKEN <-> K3-C public surface. PROMOTE=0 TIP_CLIMB=HOLD.
 * Real decode only when a ProductRuntime session is bound + model loaded.
 * Unbound = FAIL_CLOSED identity echo (PRODUCT_DECODE_PASS stays 0). */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

unsigned k3c(unsigned token);
unsigned k3c_token(unsigned token, void* state);

/* Bind product session owner. Pass nullptr to unbind (fail-closed). */
void k3c_bind_product(void* product_runtime);

int k3c_product_bound(void);
int k3c_last_token_survived(void);
int k3c_last_product_decode(void);

#ifdef __cplusplus
}

/* C++ drive shape — finite callers must break; infinite is product authority. */
inline void k3c_drive(unsigned token) {
    for (;;) token = k3c(token); /* TOKEN <-> K3-C; decode authority = bound ProductRun */
}
#endif
