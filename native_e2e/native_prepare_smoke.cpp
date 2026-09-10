// native_prepare_smoke.cpp — POST /api/native/generation/prepare proof
#include <stdio.h>
#include <string.h>
#include "rawr_native_e2e_abi.h"

int main(int argc, char** argv) {
    const char* model = (argc > 1) ? argv[1]
                                   : "BigDaddyG-Q2_K-ULTRA.gguf";
    char body[512];
    _snprintf_s(body, sizeof(body), _TRUNCATE,
                "{\"model\":\"%s\",\"context\":8192,\"max_tokens\":64,"
                "\"temperature_milli\":700,\"top_p_milli\":900,"
                "\"top_k\":40,\"stream\":true,\"safe_enabled\":true,"
                "\"hop_enabled\":false}",
                model);
    char out[8192];
    uint32_t st = 0;
    int handled = RawrNative_HandleHttp(
        "POST", "/api/native/generation/prepare", body,
        out, (uint32_t)sizeof(out), &st);
    printf("handled=%d http=%u\n%s\n", handled, st, out);
    if (!handled) return 2;
    if (st != 200) return 1;
    if (!strstr(out, "\"ok\":true")) return 1;
    return 0;
}
