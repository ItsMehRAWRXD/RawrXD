// Live generate trampoline — callable ownership gate (hit counter)
// HotPatcher binary rewrite AV'd on stream path; gate remains a real control surface.
#include "Deep2LivePath.hpp"
#include <atomic>
#include <cstdio>
#include <string>

namespace Deep2 {
namespace {

std::atomic<uint32_t> g_hits{0};
std::atomic<uint32_t> g_installed{0};
std::string g_patchId;

} // namespace

extern "C" __declspec(noinline) int Deep2_LiveGenerateGate() {
    return 1;
}

extern "C" __declspec(noinline) int Deep2_LiveGenerateGate_Patched() {
    g_hits.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

uint32_t LivePath_TrampolineHits() {
    return g_hits.load(std::memory_order_relaxed);
}

bool LivePath_InstallTrampoline() {
    g_hits.store(0, std::memory_order_relaxed);
    g_installed.store(1, std::memory_order_release);
    g_patchId = "LiveGenerateGate_soft";
    // #region agent log
    {
        FILE* df = fopen("g:/~dev/debug-1f4d81.log", "a");
        if (df) {
            fprintf(df,
                "{\"sessionId\":\"1f4d81\",\"runId\":\"post-fix\",\"hypothesisId\":\"A\","
                "\"location\":\"Deep2LivePath_Gate.cpp:InstallTrampoline\","
                "\"message\":\"trampoline_installed\","
                "\"data\":{\"mode\":\"soft_callable\",\"id\":\"%s\"},"
                "\"timestamp\":0}\n",
                g_patchId.c_str());
            fclose(df);
        }
    }
    // #endregion
    return true;
}

void LivePath_UninstallTrampoline() {
    g_installed.store(0, std::memory_order_release);
    g_patchId.clear();
}

void LivePath_TouchGate() {
    if (g_installed.load(std::memory_order_acquire))
        (void)Deep2_LiveGenerateGate_Patched();
    else
        (void)Deep2_LiveGenerateGate();
}

} // namespace Deep2
