// deep2_live_path_fused_control_cert.cpp — LIVE_PATH_FUSED_CONTROL_002 A/B/C
#include "Deep2LivePath.hpp"
#include "FusedLiveController.hpp"
#include "LivePathEffect.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
using namespace Deep2;
namespace fs = std::filesystem;

namespace Deep2 {
LivePathEffectSnap LivePath_FusedCertRunArm(int arm, const char* dir, uint32_t nTok,
                                            uint32_t depth, const char* prompt);
}

int main() {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    const char* dir = std::getenv("DEEP2_K2_SHARD_DIR");
    if (!dir || !dir[0]) dir = "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\LIVE_PATH_FUSED_CONTROL_002", nullptr);
    if (!fs::is_directory(dir)) {
        printf("SKIP_NO_MODEL\nLIVE_PATH_FUSED_CONTROL_002=SKIP\n");
        return 0;
    }
    uint32_t nTok = 4, depth = 4;
    if (const char* t = std::getenv("DEEP2_EFF_TOKENS")) nTok = (uint32_t)std::max(2, atoi(t));
    if (const char* d = std::getenv("DEEP2_EFF_LAYER_DEPTH"))
        depth = (uint32_t)std::max(1, atoi(d));
    static const char* kPrompt = "Write one short paragraph on local decode tok/s.";
    printf("LIVE_PATH_FUSED_CONTROL_002\nMODEL=%s\nTOKENS=%u DEPTH=%u\n", dir, nTok, depth);
    auto A = LivePath_FusedCertRunArm(0, dir, nTok, depth, kPrompt);
    auto B = LivePath_FusedCertRunArm(1, dir, nTok, depth, kPrompt);
    auto C = LivePath_FusedCertRunArm(2, dir, nTok, depth, kPrompt);
    LivePath_EmitEffect(stdout, "A_MIN", A);
    LivePath_EmitEffect(stdout, "B_INDEPENDENT", B);
    LivePath_EmitEffect(stdout, "C_FUSED", C);
    fprintf(stdout, "--- C fused counters ---\n");
    Fused_Emit(stdout);
    auto dCB = LivePath_ComputeDelta(B, C);
    printf("--- C vs B (fusion proof) ---\n");
    LivePath_EmitDelta(stdout, dCB);
    const auto& fc = Fused_Counters();
    const uint32_t ticks = fc.fastBypass + fc.decisions;
    const bool bypassMost = ticks == 0 || fc.fastBypass * 2 >= ticks;
    const bool okRun = A.decodeTps >= 0 && B.decodeTps > 0 && C.decodeTps > 0;
    const bool bytesOk = C.streamBytesPerToken <= B.streamBytesPerToken * 1.02 + 1.0;
    const bool missOk = C.cacheMisses <= B.cacheMisses;
    const bool vramOk = C.vramPeak <= (512ull << 20) || C.vramPeak <= B.vramPeak;
    const bool tpsOk = C.decodeTps + 1e-9 >= B.decodeTps;
    const bool pass = okRun && bypassMost && bytesOk && missOk && vramOk && tpsOk;
    printf("PROOF bypassMost=%d tpsOk=%d bytesOk=%d missOk=%d vramOk=%d tpsVsA=%d\n",
           bypassMost, tpsOk, bytesOk, missOk, vramOk, C.decodeTps > A.decodeTps);
    printf("LIVE_PATH_FUSED_CONTROL_002=%s\n", pass ? "PASS" : "FAIL");
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\LIVE_PATH_FUSED_CONTROL_002\\GATE_STATUS.txt", "w");
    if (f) {
        LivePath_EmitEffect(f, "A_MIN", A);
        LivePath_EmitEffect(f, "B_INDEPENDENT", B);
        LivePath_EmitEffect(f, "C_FUSED", C);
        Fused_Emit(f);
        LivePath_EmitDelta(f, dCB);
        fprintf(f, "PROOF bypassMost=%d tpsOk=%d bytesOk=%d missOk=%d vramOk=%d\n",
                bypassMost, tpsOk, bytesOk, missOk, vramOk);
        fprintf(f, "LIVE_PATH_FUSED_CONTROL_002=%s\n", pass ? "PASS" : "FAIL");
        fclose(f);
    }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
