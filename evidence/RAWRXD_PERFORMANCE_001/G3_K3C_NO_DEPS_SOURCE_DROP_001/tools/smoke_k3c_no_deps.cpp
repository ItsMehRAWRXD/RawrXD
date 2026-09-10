/* smoke_k3c_no_deps.cpp — compile+run drop only; no Win32IDE / ProductRun. */
#include "../drop/k3c.hpp"
#include <cstdio>

int main() {
    unsigned token = 1u;
    for (int i = 0; i < 8; ++i)
        token = k3c(token); /* TOKEN <-> K3-C; all storage/memory/GPU/layer/expert mechanics are internal */
    std::printf("GATE=G3_K3C_NO_DEPS_SOURCE_DROP_001\n");
    std::printf("K3C_BIND=FAIL_CLOSED_STUB\n");
    std::printf("DEP_EXTERNAL=0\n");
    std::printf("PRODUCT_DECODE_PASS=0\n");
    std::printf("TOKEN_OBSERVATIONAL=%u\n", token);
    std::printf("PROMOTE=0\n");
    std::printf("TIP_CLIMB=HOLD\n");
    std::printf("SMOKE=PASS\n");
    return 0;
}
