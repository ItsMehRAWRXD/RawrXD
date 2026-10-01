#include <cstdio>
#include <intrin.h>
#include <cstring>
#include <thread>

static void Print(const char* name, bool v) {
    std::printf("%-28s %s\n", name, v ? "YES" : "no");
}

int main() {
    int regs[4];
    char brand[49] = {0};

    __cpuid(regs, 0x80000000);
    const unsigned maxExt = regs[0];
    if (maxExt >= 0x80000004) {
        __cpuid(regs, 0x80000002); std::memcpy(brand +  0, regs, 16);
        __cpuid(regs, 0x80000003); std::memcpy(brand + 16, regs, 16);
        __cpuid(regs, 0x80000004); std::memcpy(brand + 32, regs, 16);
    }
    std::printf("CPU: %s\n\n", brand);

    int f1[4];
    __cpuidex(f1, 1, 0);
    const bool sse2 = (f1[3] & (1 << 26)) != 0;
    const bool fma  = (f1[2] & (1 << 12)) != 0;
    const bool avx  = (f1[2] & (1 << 28)) != 0;
    const bool f16c = (f1[2] & (1 << 29)) != 0;
    const bool fma4 = (f1[2] & (1 <<  3)) != 0;

    int f7[4];
    __cpuidex(f7, 7, 0);
    const bool avx2      = (f7[1] & (1 <<  5)) != 0;   // leaf 7 EBX bit 5
    const bool avx512f   = (f7[1] & (1 << 16)) != 0;
    const bool avx512dq  = (f7[1] & (1 << 17)) != 0;
    const bool avx512bw  = (f7[1] & (1 << 30)) != 0;
    const bool avx512vl  = (f7[1] & (1 << 31)) != 0;
    const bool avx512vbmi= (f7[2] & (1 <<  1)) != 0;
    const bool avx512vnni=(f7[2] & (1 << 11)) != 0;
    const bool avx512bf16=(f7[5] & (1 <<  5)) != 0;

    std::printf("--- baseline ---\n");
    Print("SSE2", sse2);
    Print("FMA3", fma);
    Print("FMA4", fma4);
    Print("F16C", f16c);
    Print("AVX", avx);
    Print("AVX2", avx2);
    std::printf("\n--- AVX-512 (Zen 4) ---\n");
    Print("AVX512F", avx512f);
    Print("AVX512DQ", avx512dq);
    Print("AVX512BW", avx512bw);
    Print("AVX512VL", avx512vl);
    Print("AVX512VBMI", avx512vbmi);
    Print("AVX512VNNI", avx512vnni);
    Print("AVX512_BF16", avx512bf16);

    std::printf("\n--- MSVC intrinsic availability ---\n");
    Print("_mm256_fmadd_ps", fma && avx2);
    Print("_mm512_fmadd_ps", avx512f);
    Print("_mm512_reduce_add_ps", avx512f);
    Print("_mm256_cvtph_ps (F16C)", f16c);
    std::printf("hardware_concurrency=%u\n", (unsigned)std::thread::hardware_concurrency());
    return 0;
}