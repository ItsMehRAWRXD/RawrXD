// runtime_seed_compat.cpp — qwen / rawrxd-e2e prepare compat only
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "rawr_native_e2e_abi.h"

extern "C" uint32_t RawrNative_RegisterRuntimeModelSrc(
    const char* model_name, const RawrNativeProfileInfo* info,
    const char* source);

extern "C" void RawrNative_SeedCompatOnce(void) {
    static volatile LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) != 0) return;
    RawrNativeProfileInfo p{};
    p.profile_id = 9001;
    p.engine_mode = RN_ENGINE_MODE_SAFEDECODE | RN_ENGINE_MODE_TENSORHOP;
    p.num_layers = 28;
    p.context_default = 8192;
    p.context_max = 32768;
    p.max_tokens = 512;
    p.tier = 1;
    p.quant_type = 1;
    p.ram_mb = 4096;
    p.vram_mb = 8192;
    (void)RawrNative_RegisterRuntimeModelSrc(
        "qwen2.5:1.5b", &p, "seed_compat");
    (void)RawrNative_RegisterRuntimeModelSrc(
        "qwen", &p, "seed_compat");
    (void)RawrNative_RegisterRuntimeModelSrc(
        "rawrxd-e2e", &p, "seed_compat");
}
