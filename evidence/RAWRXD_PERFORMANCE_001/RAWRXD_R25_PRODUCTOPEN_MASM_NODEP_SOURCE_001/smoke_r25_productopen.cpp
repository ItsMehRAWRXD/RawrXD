/* smoke_r25_productopen.cpp — measure R25_ProductOpenGguf on one GGUF. */
#include "r25_productopen_bridge.hpp"
#include <cstdio>
#include <windows.h>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fwprintf(stderr, L"usage: smoke_r25_productopen <path.gguf>\n");
        return 2;
    }
    R25_GGUF_PROOF p{};
    const uint64_t st = R25_ProductOpenGguf(argv[1], &p);
    R25_CloseLastMapping();
    printf("R25_STATUS=%llu\nR25_TENSORS_SCANNED=%llu\n"
                "R25_TOKEN_EMBED=%llu\nR25_LM_HEAD=%llu\nR25_PRODUCT_OPEN=%llu\n"
                "R25_VERSION=%llu\nR25_FILE_SIZE=%llu\n",
                (unsigned long long)st, (unsigned long long)p.tensors_scanned,
                (unsigned long long)p.token_embed_found,
                (unsigned long long)p.lm_head_found,
                (unsigned long long)p.product_open,
                (unsigned long long)p.version, (unsigned long long)p.file_size);
    const int ok = (st == R25_PRODUCTOPEN_OK && p.product_open == 1 &&
                    p.tensors_scanned > 0 && p.token_embed_found &&
                    p.lm_head_found)
                       ? 1
                       : 0;
    printf("R25_SMOKE=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
