/* g3_gpu1_solo_create_disc.cpp — solo/order A0 discriminator (≤99). */
#include "dual_vk_probe_util.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int FindGpuNeedle(VkInstance inst, const char* needle, ProbePhys* out);
void EmitQueueProvenance(const char* tag, const ProbePhys& o);
int EmitA0Create(const char* tag, const ProbePhys& o, int retries);

static const char* ArgVal(int argc, char** argv, const char* key) {
    const size_t n = std::strlen(key);
    for (int i = 1; i < argc; ++i)
        if (!std::strncmp(argv[i], key, n) && argv[i][n] == '=')
            return argv[i] + n + 1;
    return nullptr;
}

int main(int argc, char** argv) {
    const char* mode = ArgVal(argc, argv, "--mode"); /* solo|dual */
    const char* only = ArgVal(argc, argv, "--only"); /* R9700|7800 */
    const char* order = ArgVal(argc, argv, "--order"); /* 9700-first|7800-first */
    const char* rtry = ArgVal(argc, argv, "--retries");
    if (!mode) mode = "dual";
    if (!order) order = "9700-first";
    const int retries = rtry ? std::atoi(rtry) : 3;

    std::printf("GATE=G3_GPU1_SOLO_CREATE_DISC_001\nBEHAVIOR_PATCH=0\n"
                "PROMOTE=0\nMODE=%s\nONLY=%s\nORDER=%s\nRETRIES=%d\n",
                mode, only ? only : "-", order, retries);

    VkInstance inst = VK_NULL_HANDLE;
    if (ProbeMakeInstance(&inst) != VK_SUCCESS) return 10;
    ProbePhys a{}, b{};
    const int okA = FindGpuNeedle(inst, "R9700", &a);
    const int okB = FindGpuNeedle(inst, "7800", &b);
    std::printf("R9700_FOUND=%d\nRX7800XT_FOUND=%d\n", okA, okB);

    int rc = 0;
    if (!std::strcmp(mode, "solo")) {
        ProbePhys* t = nullptr;
        const char* tag = only;
        if (only && !std::strcmp(only, "R9700") && okA) t = &a;
        else if (only && (!std::strcmp(only, "7800") || !std::strcmp(only, "RX7800XT")) &&
                 okB) {
            t = &b;
            tag = "RX7800XT";
        } else {
            std::printf("SOLO_TARGET_MISSING=1\n");
            vkDestroyInstance(inst, nullptr);
            return 11;
        }
        EmitQueueProvenance(tag, *t);
        rc = EmitA0Create(tag, *t, retries);
        std::printf("SOLO_CREATE_RESULT=%s\n", rc == 0 ? "PASS" : "FAIL");
    } else {
        if (!okA || !okB) {
            vkDestroyInstance(inst, nullptr);
            return 11;
        }
        const int first7800 = !std::strcmp(order, "7800-first");
        ProbePhys* first = first7800 ? &b : &a;
        ProbePhys* second = first7800 ? &a : &b;
        const char* t0 = first7800 ? "RX7800XT" : "R9700";
        const char* t1 = first7800 ? "R9700" : "RX7800XT";
        EmitQueueProvenance(t0, *first);
        const int r0 = EmitA0Create(t0, *first, retries);
        EmitQueueProvenance(t1, *second);
        const int r1 = EmitA0Create(t1, *second, retries);
        std::printf("DUAL_FIRST=%s FIRST_A0=%s\nDUAL_SECOND=%s SECOND_A0=%s\n",
                    t0, r0 == 0 ? "PASS" : "FAIL", t1, r1 == 0 ? "PASS" : "FAIL");
        rc = (r0 || r1) ? 1 : 0;
    }
    vkDestroyInstance(inst, nullptr);
    return rc;
}
