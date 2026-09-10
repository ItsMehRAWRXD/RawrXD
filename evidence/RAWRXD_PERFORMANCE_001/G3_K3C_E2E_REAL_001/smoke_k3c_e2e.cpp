/* smoke_k3c_e2e.cpp — G3_K3C_E2E_REAL_001. Honest markers; PROMOTE=0. */
#include "k3c.hpp"
#include "ProductRuntime.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc, char** argv) {
    const char* model =
        (argc > 1 && argv[1] && argv[1][0])
            ? argv[1]
            : "G:/~dev/rawrxd/models/tinyllama.gguf";

    std::printf("GATE=G3_K3C_E2E_REAL_001\n");
    std::printf("APPLY_HOST_DECODE=0\nPROMOTE=0\nTIP_CLIMB=HOLD\n");

    /* Phase A: unbound fail-closed */
    k3c_bind_product(nullptr);
    unsigned echo = k3c(7u);
    std::printf("SOURCE_WIRED=1\n");
    std::printf("UNBOUND_FAIL_CLOSED=%d\n", echo == 7u ? 1 : 0);
    std::printf("UNBOUND_PRODUCT_DECODE=%d\n", k3c_last_product_decode());

    /* Phase B: bind ProductRuntime + one-step k3c */
    rawr::product_run::ProductRuntime rt;
    const int opened = rt.OpenSession(model) ? 1 : 0;
    std::printf("MODEL_PATH=%s\nSESSION_OPEN=%d\n", model, opened);
    if (!opened) {
        std::printf("RUNTIME_REACHED=0\nTOKEN_SURVIVED=0\nPRODUCT_DECODE_PASS=0\n");
        std::printf("VERDICT=FAIL\nBLOCKER=SESSION_OPEN_FAIL\n");
        return 2;
    }

    k3c_bind_product(&rt);
    std::printf("K3C_BOUND=%d\n", k3c_product_bound());

    std::vector<int> prompt = rt.Eng().tokenize("hi");
    unsigned seed = prompt.empty() ? 1u : (unsigned)prompt[0];
    unsigned out = k3c(seed);
    const int survived = k3c_last_token_survived();
    const int product = k3c_last_product_decode();

    std::printf("RUNTIME_REACHED=1\n");
    std::printf("TOKEN_IN=%u\nTOKEN_OUT=%u\n", seed, out);
    std::printf("TOKEN_SURVIVED=%d\nPRODUCT_DECODE=%d\n", survived, product);
    std::printf("PRODUCT_DECODE_PASS=%d\n", (survived && product && out != 0) ? 1 : 0);
    std::printf("VERDICT=%s\n",
                (survived && product) ? "PASS" : "FAIL");

    k3c_bind_product(nullptr);
    rt.CloseSession();
    return (survived && product) ? 0 : 3;
}
