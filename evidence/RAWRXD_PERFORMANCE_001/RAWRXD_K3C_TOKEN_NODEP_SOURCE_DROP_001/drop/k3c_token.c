/* k3c_token.c — no-dep body. PROMOTE=0. ≤99. */
#include "k3c_token.h"

typedef struct K3CState {
    unsigned remain;
    unsigned last;
} K3CState;

unsigned k3c_token(unsigned token, void *state) {
    K3CState *st = (K3CState *)state;
    if (!st) return token;
    st->last = token;
    if (st->remain) --st->remain;
    return token + 1u;
}

/* Hot path shape: for(;;) token = K3C(token); */
unsigned k3c_run(unsigned token, void *state) {
    void *k3c_state = state;
    K3CState *st = (K3CState *)state;
    if (!st) return token;
    for (;;) {
        token = K3C(token);
        if (st->remain == 0u) return token;
    }
}
