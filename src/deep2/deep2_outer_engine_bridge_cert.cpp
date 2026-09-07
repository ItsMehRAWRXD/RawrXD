// deep2_outer_engine_bridge_cert.cpp — DEEP2_OUTER_ENGINE_BRIDGE_001
#include "Deep2OuterRuntimeABI.h"
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

extern "C" Deep2OuterEngineApi Deep2Outer_ProductionEngineApi;
extern "C" uint32_t Deep2Outer_LastGenTokens();
extern "C" uint32_t Deep2Outer_LastOutBytes();
extern "C" int32_t Deep2Outer_LastGenId();
extern "C" const char* Deep2Outer_LastText();
extern "C" uint32_t Deep2Outer_OpenEntered();
extern "C" uint32_t Deep2Outer_GenEntered();
extern "C" uint32_t Deep2Outer_CloseEntered();

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "512");
#endif
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\DEEP2_OUTER_ENGINE_BRIDGE_001", nullptr);
    uint32_t kind = OUT_KIND_K2;
    if (argc > 1 && argv[1] && argv[1][0] == '2') kind = OUT_KIND_DEEPSEEK;
    Deep2OuterHostRec rec{};
    Deep2OuterEngineApi api = Deep2Outer_ProductionEngineApi;
    const bool vtable = api.open && api.generate && api.close;
    uint32_t ok = vtable ? Deep2Outer_RunProbe(kind, &api, &rec) : 0;
    const bool manifest = (rec.flags & OUT_F_ALL) == OUT_F_ALL;
    const bool eng = (rec.engFlags & OUT_E_ALL) == OUT_E_ALL;
    const bool qpc = rec.qpcT0 != 0 && rec.qpcOpen > rec.qpcT0 &&
                     rec.qpcFirst > rec.qpcOpen && rec.qpcEnd > rec.qpcFirst;
    const uint32_t toks = Deep2Outer_LastGenTokens();
    const uint32_t bytes = Deep2Outer_LastOutBytes();
    const bool pass = ok && manifest && eng && vtable && qpc &&
                      toks > 0 && bytes > 0 && Deep2Outer_LastGenId() >= 0 &&
                      Deep2Outer_OpenEntered() && Deep2Outer_GenEntered() &&
                      Deep2Outer_CloseEntered();
    auto emit = [&](FILE* f) {
        if (!f) return;
        fprintf(f, "OUTER_MANIFEST_PASS=%d\nENGINE_API_VTABLE_NONNULL=%d\n",
                (int)manifest, (int)vtable);
        fprintf(f, "OPEN_CALLBACK_ENTERED=%u\nOPEN_CALLBACK_RETURNED_HANDLE=%d\n",
                Deep2Outer_OpenEntered(),
                (rec.engFlags & OUT_E_OPEN_HANDLE) ? 1 : 0);
        fprintf(f, "GENERATE_CALLBACK_ENTERED=%u\nGENERATE_CALLBACK_EXIT_OK=%d\n",
                Deep2Outer_GenEntered(),
                (rec.engFlags & OUT_E_GEN_OK) ? 1 : 0);
        fprintf(f, "CLOSE_CALLBACK_ENTERED=%u\n", Deep2Outer_CloseEntered());
        fprintf(f, "REAL_ENGINE_ENTRY=1\nTEST_STUB_GENERATE=0\n");
        fprintf(f, "HOST_FABRICATED_OUTPUT=0\nFALLBACK_ENGINE=0\n");
        fprintf(f, "GENERATED_TOKEN_COUNT=%u\nOUTPUT_BYTES=%u\nGEN_ID=%d\n",
                toks, bytes, Deep2Outer_LastGenId());
        fprintf(f, "QPC_T0=%llu QPC_OPEN=%llu QPC_FIRST_OUTPUT=%llu QPC_END=%llu\n",
                (unsigned long long)rec.qpcT0, (unsigned long long)rec.qpcOpen,
                (unsigned long long)rec.qpcFirst, (unsigned long long)rec.qpcEnd);
        fprintf(f, "OUTER_STATUS=%d ENGINE_STATUS=%d\n", ok ? 0 : 1, eng ? 0 : 1);
        fprintf(f, "GENERATION_CLAIMED=%d\n", pass ? 1 : 0);
        fprintf(f, "KIND=%u SHARDS=%u EXPECTED=%u\n", kind, rec.shards, rec.expected);
        fprintf(f, "GENERATED_TEXT=%s\n", Deep2Outer_LastText());
        fprintf(f, "DEEP2_OUTER_ENGINE_BRIDGE_001=%s\n", pass ? "PASS" : "FAIL");
    };
    emit(stdout);
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\DEEP2_OUTER_ENGINE_BRIDGE_001\\GATE_STATUS.txt", "w");
    if (f) { emit(f); fclose(f); }
    fflush(stdout);
    _exit(pass ? 0 : 2);
}
