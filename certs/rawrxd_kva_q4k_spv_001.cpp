// certs/rawrxd_kva_q4k_spv_001.cpp — artifact presence for KVA SPV
#include "../src/deep2/lavapath/KernelRegistry.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>

static bool FileOk(const char* p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    return f.is_open() && f.tellg() > 0;
}

int main() {
    const int src = FileOk("G:/~dev/rawrxd/src/backend/gemv_q4k_kva.comp");
    const int spv =
        FileOk("G:/~dev/rawrxd/src/backend/gemv_q4k_kva.spv") ||
        FileOk("G:/~dev/rawrxd/build-fd/bin/gemv_q4k_kva.spv");
    const auto d = rawr::ktune::KvaSharedXDesc();
    int exec = 0;
    for (uint32_t i = 0; i < d.variantCount; ++i) {
        if (d.variants[i].executable && d.variants[i].spvName &&
            std::strstr(d.variants[i].spvName, "gemv_q4k_kva.spv"))
            exec = 1;
    }
    // Parity/measure remain OPEN until live RunTune measure hooks fire.
    const int parity = 0;
    const int measured = 0;
    const int winner = -1;
    const char* delta =
        !src ? "SOURCE" : !spv ? "SPV" : !exec ? "REGISTRY"
                      : !measured ? "MEASURE" : "NONE";
    std::printf("KVA_Q4K_SOURCE_PRESENT=%d\n", src);
    std::printf("KVA_Q4K_SPV_PRESENT=%d\n", spv);
    std::printf("KVA_Q4K_EXECUTABLE_VARIANT=%d\n", exec);
    std::printf("KVA_Q4K_PARITY=%d\n", parity);
    std::printf("KVA_Q4K_MEASURED=%d\n", measured);
    std::printf("KVA_Q4K_WINNER=%d\n", winner);
    std::printf("KVA_FIRST_DELTA=%s\n", delta);
    const int pass = src && spv && exec;
    std::puts(pass ? "KVA_Q4K_SPV_001=PASS" : "KVA_Q4K_SPV_001=FAIL");
    return pass ? 0 : 1;
}
