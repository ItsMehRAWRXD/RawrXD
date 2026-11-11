// ============================================================================
// src/validation/kernels/masm_kernels_simple_test.cpp — MASM kernels smoke test
// ============================================================================
// RECONSTRUCTION NOTICE
// Previously absent from the tree while
// src/validation/kernels/CMakeLists.txt named it as the ONLY source of target
// `masm_kernels_test`, making `cmake` fail with "Cannot find source file"
// (and later "No SOURCES given to target" when the reference was removed
// without guarding the target).
//
// What this file is: a real, self-contained smoke test that reports honestly.
// The target `masm_kernels_test` links only `telemetry_masm_kernels`; the
// actual kernel objects (ResidencyBackends.obj, Sovereign_Q4K_Dequant.obj)
// are not in its source list and ASM_MASM is not enabled here, so this test
// verifies what IS linked and says plainly which kernels are not present,
// rather than fabricating kernel results.
//
// Exposes only main().
// ============================================================================
#include <cstdint>
#include <cstdio>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif

namespace {
inline void Cpuid(int level, int* out) {
#ifdef _MSC_VER
    __cpuid(out, level);
#else
    __cpuid(level, out[0], out[1], out[2], out[3]);
#endif
}
}  // namespace

int main() {
    std::printf("MASM Kernels Smoke Test\n");
    std::printf("=======================\n\n");

    // Verify the process actually has the SIMD levels the kernels require,
    // so a "kernels unavailable" report has a known reason.
    int cpuInfo[4] = {0, 0, 0, 0};
    Cpuid(1, cpuInfo);
    const bool hasAvx2  = ((cpuInfo[2] >> 28) & 1) != 0;   // AVX2
    const bool hasFma   = ((cpuInfo[2] >> 12) & 1) != 0;   // FMA
    Cpuid(7, cpuInfo);
    const bool hasAvx512 = ((cpuInfo[1] >> 16) & 1) != 0;  // AVX-512F

    std::printf("host CPU features:\n");
    std::printf("  AVX2    : %s\n", hasAvx2 ? "yes" : "no");
    std::printf("  FMA     : %s\n", hasFma ? "yes" : "no");
    std::printf("  AVX-512F: %s\n", hasAvx512 ? "yes" : "no");

    if (!hasAvx2 || !hasFma) {
        std::printf("\nERROR: AVX2/FMA are required by the MASM kernels\n");
        return 1;
    }

    // This target links only telemetry_masm_kernels, so the kernel objects
    // themselves are not resolvable from here. Say so rather than pretend.
    std::printf("\nnote: this target's link set is telemetry_masm_kernels only;\n");
    std::printf("      the residency/Q4_K kernel objects are not linked into it,\n");
    std::printf("      so no kernel invocation is performed by this smoke test.\n");
    std::printf("\nMASM kernels smoke verdict: HOST OK, KERNELS NOT LINKED\n");
    return 0;
}
