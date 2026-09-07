// deep2_nu_live_consumer_cert.cpp — NU_LIVE_CONSUMER_001
#include "NULiveConsumer.hpp"
#include "NUFusedPacker.hpp"
#include "Deep2LivePath.hpp"
#include "vulkan_compute.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;

static void SyncEnv(const char* k, const char* v) {
#ifdef _WIN32
    _putenv_s(k, v);
    SetEnvironmentVariableA(k, v);
#else
    setenv(k, v, 1);
#endif
}

static void ClearEnv(const char* k) {
#ifdef _WIN32
    _putenv_s(k, "");
    SetEnvironmentVariableA(k, nullptr);
#else
    unsetenv(k);
#endif
}

static void Fill(std::vector<float>& W, std::vector<float>& x,
                 uint32_t rows, uint32_t cols) {
    for (uint32_t r = 0; r < rows; ++r)
        for (uint32_t c = 0; c < cols; ++c)
            W[(size_t)r * cols + c] = 0.01f * (float)((r + c) % 11);
    for (uint32_t c = 0; c < cols; ++c)
        x[c] = 0.02f * (float)((c % 7) + 1);
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "CACHE");
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\NU_LIVE_CONSUMER_001", nullptr);
#endif
    printf("NU_LIVE_CONSUMER_001\n");
    ClearEnv("DEEP2_LIVE_NU");
    ClearEnv("DEEP2_LIVE_NU_AUTH");

    CPUInference::VulkanCompute vc;
    if (!vc.Initialize()) {
        printf("NU_LIVE_CONSUMER_001=FAIL vulkan_init\n");
#ifdef _WIN32
        _exit(2);
#else
        return 2;
#endif
    }
    const uint32_t rows = 32, cols = 32;
    std::vector<float> W((size_t)rows * cols), x(cols), y(rows);
    Fill(W, x, rows, cols);
    NUFusedPacker packer;
    NUPackerConfig cfg;
    packer.initialize(cfg);
    auto nu = packer.packTensor(W.data(), W.size(), NUFormatTag::NU_Q4_0);

    // 1) Default off
    NU_LiveStatsReset();
    const bool offFail =
        !NU_LiveConsumeGemv(vc, nu.data(), nu.size(), x.data(), y.data(), rows,
                            cols);
    const bool offOk = offFail && NU_LiveStatsGet().rejectOff >= 1 &&
                       NU_LiveStatsGet().ops == 0;

    // 2) Wanted + explicit AUTH=0 → rejectNoAuth
    SyncEnv("DEEP2_LIVE_NU", "1");
    SyncEnv("DEEP2_LIVE_NU_AUTH", "0");
    NU_LiveStatsReset();
    const bool rej =
        !NU_LiveConsumeGemv(vc, nu.data(), nu.size(), x.data(), y.data(), rows,
                            cols);
    const bool noAuthOk = rej && NU_LiveStatsGet().rejectNoAuth >= 1 &&
                          NU_LiveStatsGet().ops == 0;

    // 3) Wanted + AUTH=1 → consume under live generate session
    SyncEnv("DEEP2_LIVE_NU", "1");
    SyncEnv("DEEP2_LIVE_NU_AUTH", "1");
    SyncEnv("DEEP2_LIVE_MECH", "none");
    SyncEnv("DEEP2_LIVE_PATH", "1");
    NU_LiveStatsReset();
    CycloneScheduler* cyc = nullptr;
    LivePath_BeginGenerate(1, nullptr, &cyc);
    const bool liveActive = LivePath_Active();
    const bool got =
        NU_LiveConsumeGemv(vc, nu.data(), nu.size(), x.data(), y.data(), rows,
                           cols, 0x4E554C01ull);
    LivePath_EndGenerate(nullptr);
    const auto& st = NU_LiveStatsGet();
    const bool onOk = got && liveActive && st.ops >= 1 && st.bytes == nu.size() &&
                      NU_LiveActive();

    printf("OFF=%d NO_AUTH_GATE=%d ON=%d ops=%llu bytes=%llu live=%d\n",
           offOk ? 1 : 0, noAuthOk ? 1 : 0, onOk ? 1 : 0,
           (unsigned long long)st.ops, (unsigned long long)st.bytes,
           liveActive ? 1 : 0);
    NU_LiveEmit(stdout);

    const bool pass = offOk && noAuthOk && onOk;
    printf("NU_LIVE_CONSUMER_001=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\NU_LIVE_CONSUMER_001\\GATE_STATUS.txt", "w");
    if (f) {
        fprintf(f, "OFF=%d NO_AUTH=%d ON=%d\n", offOk, noAuthOk, onOk);
        NU_LiveEmit(f);
        fprintf(f, "NU_LIVE_CONSUMER_001=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    ClearEnv("DEEP2_LIVE_NU");
    ClearEnv("DEEP2_LIVE_NU_AUTH");
    vc.Cleanup();
#ifdef _WIN32
    _exit(pass ? 0 : 2);
#else
    return pass ? 0 : 2;
#endif
}
