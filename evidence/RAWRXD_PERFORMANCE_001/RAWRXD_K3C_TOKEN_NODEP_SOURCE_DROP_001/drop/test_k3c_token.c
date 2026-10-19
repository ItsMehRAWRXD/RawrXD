/* test_k3c_token.c — no-dep smoke. */
#include "k3c_token.h"
#include <stdio.h>

typedef struct K3CState {
    unsigned remain;
    unsigned last;
} K3CState;

unsigned k3c_run(unsigned token, void *state);

int main(void) {
    K3CState st;
    st.remain = 8u;
    st.last = 0u;
    unsigned token = k3c_run(0u, &st);
    printf("K3C_NODEP=1 TOKEN=%u LAST=%u\n", token, st.last);
    return (token == 8u && st.last == 7u) ? 0 : 1;
}
