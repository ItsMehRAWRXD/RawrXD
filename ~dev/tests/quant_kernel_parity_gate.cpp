/*====================================================================
 QUANT_KERNEL_PARITY_001
 Scalar-vs-SIMD GEMV differential parity authority for the
 QuantKernelRegistry kernels promoted by the RawrXD autonomous audit.
====================================================================
 Authority scope (this revision):
   F16   — gemv_f16_avx512 vs gemv_f16_scalar   (promotion 001)
   Q8_0  — gemv_q8_0_avx2  vs gemv_q8_0_scalar  (repair + promotion)
   Q5_K  — NOT promoted. The vector body is KNOWN DEFECTIVE
           (nibble-order mismatch vs the ggml layout + only the lower
           128-bit half of _mm256_dp_ps accumulated). The gate FAILS
           CLOSED if Q5_K dispatch is anything but the scalar reference,
           or if the macro alias shield exposing that defective body is
           removed. Promotion requires its own Q5K_AVX2_PARITY_001.

 Method:
   - Deterministic RNG (fixed seed), elementwise mixed tolerance
     (atol + rtol*|ref|) — NOT cosine similarity.
   - Dimension sweep deliberately includes odd tails and partial final
     blocks (the class of bug that dropped Q8_0 lanes 8..15/24..31).
   - Canary guards before/after every output buffer prove no OOB write.
   - Registry dispatch verified by FUNCTION-POINTER IDENTITY against
     CPU capability expectations (fail-closed vs telemetry lies).

 PASS criteria:
   F16_AVX512_PARITY=1     (when AVX512+F16C present)
   Q8_0_AVX2_PARITY=1      (when AVX2+FMA present)
   F16/Q8 NONFINITE=0, GUARD_CORRUPTION=0
   REGISTRY_F16_IMPL == capability-expected impl (avx512 here)
   REGISTRY_Q8_0_IMPL == "avx2" (when AVX2+FMA present)
   REGISTRY_Q5_K_IMPL == "scalar" (fail-closed law)
   Q5_K_AVX2_ALIAS_SHIELD=1 (macro shield intact)
   Exit code 0 only on full PASS.
====================================================================*/

// Unity-include the registry TU so the file-static kernels under test
// are addressable in this translation unit.
#include "../rawrxd/src/deep2/QuantKernelRegistry.cpp"

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kCanary = 0x7FC01234u;
constexpr uint32_t kSeed   = 0x52415752u;  // "RAWR"
constexpr uint64_t kMaxMismatchPrints = 32;

constexpr float kF16Atol = 1e-3f;
constexpr float kF16Rtol = 2e-4f;
constexpr float kQ8Atol  = 2e-3f;
constexpr float kQ8Rtol  = 3e-4f;

const size_t kRowsAll[] = {1, 2, 7, 31};
const size_t kColsF16[] = {1, 7, 8, 15, 16, 17, 31, 32, 33, 127, 128, 129, 5120};
const size_t kColsQ8[]  = {1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 5120};

struct GateCpu {
    bool fma = false, f16c = false, avx2 = false;
    bool avx512f = false, avx512bw = false, avx512dq = false;
    bool avx512vl = false, avx512vnni = false;
};

GateCpu probeCpu() {
    GateCpu c;
    int info[4];
    __cpuid(info, 1);
    c.fma  = (info[2] & (1 << 12)) != 0;
    c.f16c = (info[2] & (1 << 29)) != 0;
    int info7[4];
    __cpuidex(info7, 7, 0);
    c.avx2       = (info7[1] & (1 << 5))  != 0;
    c.avx512f    = (info7[1] & (1 << 16)) != 0;
    c.avx512dq   = (info7[1] & (1 << 17)) != 0;
    c.avx512bw   = (info7[1] & (1 << 30)) != 0;
    c.avx512vl   = (info7[1] & (1 << 31)) != 0;
    c.avx512vnni = (info7[2] & (1 << 11)) != 0;
    return c;
}

uint16_t fp32_to_fp16(float f) {
    uint32_t x;
    std::memcpy(&x, &f, 4);
    uint32_t sign = (x >> 16) & 0x8000;
    int32_t  exp  = (int32_t)((x >> 23) & 0xFF) - 127 + 15;
    uint32_t mant = x & 0x7FFFFF;
    if (exp <= 0) {
        if (exp < -10) return (uint16_t)sign;
        mant |= 0x800000;
        uint32_t shift = (uint32_t)(14 - exp);
        mant >>= shift;
        return (uint16_t)(sign | (mant >> 13));
    }
    if (exp >= 31) return (uint16_t)(sign | 0x7C00);
    return (uint16_t)(sign | ((uint32_t)exp << 10) | (mant >> 13));
}

struct KernelMetrics {
    size_t   cases = 0;
    float    maxAbs = 0.0f;
    float    maxRel = 0.0f;
    uint64_t nanCount = 0;
    uint64_t infCount = 0;
    uint64_t guardCorruption = 0;
    bool     parity = true;
    uint64_t prints = 0;

    uint64_t nonfinite() const { return nanCount + infCount; }
};

// Canary-guarded output: 8 uint32 canaries before and after the y region.
// Kernels use y[r] += semantics; y is zero-initialized.
struct GuardedOutput {
    std::vector<uint32_t> storage;
    float* y = nullptr;
    size_t rows = 0;

    explicit GuardedOutput(size_t r) : storage(r + 16, kCanary), rows(r) {
        y = reinterpret_cast<float*>(storage.data() + 8);
        std::memset(y, 0, rows * sizeof(float));
    }
    bool guardsIntact() const {
        for (size_t i = 0; i < 8; ++i)
            if (storage[i] != kCanary) return false;
        for (size_t i = rows + 8; i < rows + 16; ++i)
            if (storage[i] != kCanary) return false;
        return true;
    }
};

void compareRow(const char* tag, size_t caseNo, size_t row,
                float opt, float ref, float atol, float rtol,
                KernelMetrics& m) {
    if (std::isnan(opt) || std::isnan(ref)) {
        m.nanCount++;
        m.parity = false;
        if (m.prints++ < kMaxMismatchPrints)
            std::printf("[NONFINITE-NAN] %s case=%zu row=%zu opt=%e ref=%e\n",
                        tag, caseNo, row, (double)opt, (double)ref);
        return;
    }
    if (std::isinf(opt) || std::isinf(ref)) {
        m.infCount++;
        m.parity = false;
        if (m.prints++ < kMaxMismatchPrints)
            std::printf("[NONFINITE-INF] %s case=%zu row=%zu opt=%e ref=%e\n",
                        tag, caseNo, row, (double)opt, (double)ref);
        return;
    }
    const float diff = std::fabs(opt - ref);
    const float allowed = atol + rtol * std::fabs(ref);
    if (diff > m.maxAbs) m.maxAbs = diff;
    const float rel = diff / std::max(std::fabs(ref), 1e-6f);
    if (rel > m.maxRel) m.maxRel = rel;
    if (diff > allowed) {
        m.parity = false;
        if (m.prints++ < kMaxMismatchPrints)
            std::printf("[MISMATCH] %s case=%zu row=%zu opt=%.6e ref=%.6e "
                        "diff=%.3e allowed=%.3e\n",
                        tag, caseNo, row, (double)opt, (double)ref,
                        (double)diff, (double)allowed);
    }
}

// ---------------- F16 parity: gemv_f16_{avx512|avx2} vs scalar ----------------
// Weight synthesis includes zeros, subnormals, and normals (exp 1..20)
// to stress both the F16C hardware conversion and the soft-conversion
// reference on the exact same bit patterns.
void runF16Case(size_t rows, size_t cols, Deep2::GEMVKernelFn opt,
               size_t caseNo, std::mt19937& rng, KernelMetrics& m) {
    std::vector<uint16_t> w(rows * cols);
    std::uniform_int_distribution<int> kindDist(0, 99);
    std::uniform_int_distribution<int> signDist(0, 1);
    std::uniform_int_distribution<int> fracDist(0, 1023);
    std::uniform_int_distribution<int> expDist(1, 20);
    for (auto& h : w) {
        const int kind = kindDist(rng);
        const uint16_t sign = (uint16_t)(signDist(rng) << 15);
        if (kind < 2) {
            h = sign;                                   // +/- zero
        } else if (kind < 4) {
            h = (uint16_t)(sign | (uint16_t)fracDist(rng));  // subnormal
        } else {
            h = (uint16_t)(sign | (uint16_t)(expDist(rng) << 10)
                              | (uint16_t)fracDist(rng));
        }
    }
    std::vector<float> x(cols);
    std::uniform_real_distribution<float> xDist(-1.0f, 1.0f);
    for (auto& v : x) v = xDist(rng);

    GuardedOutput refOut(rows), optOut(rows);
    Deep2::gemv_f16_scalar(reinterpret_cast<const uint8_t*>(w.data()),
                           x.data(), refOut.y, rows, cols);
    if (!refOut.guardsIntact()) {
        m.guardCorruption++;
        m.parity = false;
    }
    opt(reinterpret_cast<const uint8_t*>(w.data()),
        x.data(), optOut.y, rows, cols);
    if (!optOut.guardsIntact()) {
        m.guardCorruption++;
        m.parity = false;
    }
    for (size_t r = 0; r < rows; ++r)
        compareRow("F16", caseNo, r, optOut.y[r], refOut.y[r],
                   kF16Atol, kF16Rtol, m);
    m.cases++;
}

// ------------- Q8_0 parity: gemv_q8_0_avx2 vs scalar -------------
// Walks the exact packed 34-byte GGUF block stride like both kernels;
// odd cols deliberately produce partial final blocks.
void runQ8Case(size_t rows, size_t cols, Deep2::GEMVKernelFn opt,
              size_t caseNo, std::mt19937& rng, KernelMetrics& m) {
    constexpr size_t kBlk = 34;
    const size_t blocksPerRow = (cols + 31) / 32;
    std::vector<uint8_t> w(rows * blocksPerRow * kBlk);
    std::uniform_real_distribution<float> dDist(0.001f, 0.1f);
    std::uniform_int_distribution<int> qDist(-128, 127);
    for (size_t r = 0; r < rows; ++r) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            auto* blk = reinterpret_cast<Deep2::block_q8_0*>(
                w.data() + (r * blocksPerRow + b) * kBlk);
            blk->d = fp32_to_fp16(dDist(rng));
            for (int i = 0; i < 32; ++i)
                blk->qs[i] = (int8_t)qDist(rng);
        }
    }
    std::vector<float> x(cols);
    std::uniform_real_distribution<float> xDist(-1.0f, 1.0f);
    for (auto& v : x) v = xDist(rng);

    GuardedOutput refOut(rows), optOut(rows);
    Deep2::gemv_q8_0_scalar(w.data(), x.data(), refOut.y, rows, cols);
    if (!refOut.guardsIntact()) {
        m.guardCorruption++;
        m.parity = false;
    }
    opt(w.data(), x.data(), optOut.y, rows, cols);
    if (!optOut.guardsIntact()) {
        m.guardCorruption++;
        m.parity = false;
    }
    for (size_t r = 0; r < rows; ++r)
        compareRow("Q8_0", caseNo, r, optOut.y[r], refOut.y[r],
                   kQ8Atol, kQ8Rtol, m);
    m.cases++;
}

} // namespace

int main() {
    const GateCpu cpu = probeCpu();

    std::printf("==========================================================\n");
    std::printf(" QUANT_KERNEL_PARITY_001\n");
    std::printf(" Scalar-vs-SIMD GEMV differential parity authority\n");
    std::printf("==========================================================\n\n");

    // ---------------- Registry dispatch (actual pointers) ----------------
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();
    const std::string table = reg.DumpTable();
    std::printf("%s\n", table.c_str());

    const int tF16 = static_cast<int>(Deep2::GGMLType::GGML_TYPE_F16);
    const int tQ8  = static_cast<int>(Deep2::GGMLType::GGML_TYPE_Q8_0);
    const int tQ5  = static_cast<int>(Deep2::GGMLType::GGML_TYPE_Q5_K);

    Deep2::GEMVKernelFn f16fn = reg.GetGEMV(tF16);
    Deep2::GEMVKernelFn q8fn  = reg.GetGEMV(tQ8);
    Deep2::GEMVKernelFn q5fn  = reg.GetGEMV(tQ5);

    const char* regF16 = Deep2::KernelImplName(tF16, f16fn);
    const char* regQ8  = Deep2::KernelImplName(tQ8, q8fn);
    const char* regQ5  = Deep2::KernelImplName(tQ5, q5fn);

    // Mirror RegisterBuiltins() capability gating exactly.
    const bool hasAVX512 = cpu.avx512f && cpu.avx512bw;
    const bool hasAVX2   = cpu.avx2 && cpu.fma;
    const char* expF16 = (hasAVX512 && cpu.f16c) ? "avx512"
                       : (hasAVX2   && cpu.f16c) ? "avx2"
                       : "scalar";
    const char* expQ8  = hasAVX2 ? "avx2" : "scalar";
    const char* expQ5  = "scalar";  // fail-closed law until Q5K_AVX2_PARITY_001

    const bool implOk = std::strcmp(regF16, expF16) == 0 &&
                        std::strcmp(regQ8,  expQ8)  == 0 &&
                        std::strcmp(regQ5,  expQ5)  == 0;

    // Pointer-identity assertions of the registered kernels.
    bool ptrOk = true;
    if (hasAVX512 && cpu.f16c)      ptrOk = ptrOk && (f16fn == Deep2::gemv_f16_avx512);
    else if (hasAVX2 && cpu.f16c)   ptrOk = ptrOk && (f16fn == Deep2::gemv_f16_avx2);
    else                            ptrOk = ptrOk && (f16fn == Deep2::gemv_f16_scalar);
    if (hasAVX2)                    ptrOk = ptrOk && (q8fn  == Deep2::gemv_q8_0_avx2);
    else                            ptrOk = ptrOk && (q8fn  == Deep2::gemv_q8_0_scalar);
    ptrOk = ptrOk && (q5fn == Deep2::gemv_q5_k_scalar);

    // Q5_K macro-shield tripwire: while the defective vector body exists,
    // the alias must force the name to the scalar reference. Removing the
    // alias (exposing the defective kernel) fails the gate.
    const bool q5Shield =
        (Deep2::GEMVKernelFn)Deep2::gemv_q5_k_avx2 ==
        (Deep2::GEMVKernelFn)Deep2::gemv_q5_k_scalar;

    // ---------------- Differential parity runs ----------------
    std::mt19937 rng(kSeed);

    Deep2::GEMVKernelFn f16Opt = nullptr;
    const char* f16Reason = "";
    if (hasAVX512 && cpu.f16c)      { f16Opt = Deep2::gemv_f16_avx512; f16Reason = ""; }
    else if (hasAVX2 && cpu.f16c)   { f16Opt = Deep2::gemv_f16_avx2;    f16Reason = ""; }
    else                            { f16Reason = "NO_F16_SIMD_CAPABILITY"; }

    KernelMetrics f16m;
    size_t f16CaseNo = 0;
    if (f16Opt) {
        for (size_t rows : kRowsAll)
            for (size_t cols : kColsF16)
                runF16Case(rows, cols, f16Opt, f16CaseNo++, rng, f16m);
    }

    Deep2::GEMVKernelFn q8Opt = hasAVX2 ? Deep2::gemv_q8_0_avx2 : nullptr;
    const char* q8Reason = hasAVX2 ? "" : "NO_AVX2_FMA_CAPABILITY";

    KernelMetrics q8m;
    size_t q8CaseNo = 0;
    if (q8Opt) {
        for (size_t rows : kRowsAll)
            for (size_t cols : kColsQ8)
                runQ8Case(rows, cols, q8Opt, q8CaseNo++, rng, q8m);
    }

    const size_t totalCases = f16m.cases + q8m.cases;
    const uint64_t totalNonfinite = f16m.nonfinite() + q8m.nonfinite();
    const uint64_t totalGuard = f16m.guardCorruption + q8m.guardCorruption;

    const bool f16Pass = !f16Opt ||
        (f16m.parity && f16m.nonfinite() == 0 && f16m.guardCorruption == 0);
    const bool q8Pass = !q8Opt ||
        (q8m.parity && q8m.nonfinite() == 0 && q8m.guardCorruption == 0);

    const bool pass = f16Pass && q8Pass && implOk && ptrOk &&
                      q5Shield && totalNonfinite == 0 && totalGuard == 0;

    // ---------------- Machine-readable receipt ----------------
    std::printf("---- RECEIPT ----\n");
    std::printf("GATE=QUANT_KERNEL_PARITY_001\n");
    std::printf("SEED=0x%08X\n", kSeed);
    std::printf("CASES=%zu\n", totalCases);
    std::printf("CPU_AVX512F=%d\n", cpu.avx512f ? 1 : 0);
    std::printf("CPU_AVX512BW=%d\n", cpu.avx512bw ? 1 : 0);
    std::printf("CPU_AVX2=%d\n", cpu.avx2 ? 1 : 0);
    std::printf("CPU_FMA=%d\n", cpu.fma ? 1 : 0);
    std::printf("CPU_F16C=%d\n", cpu.f16c ? 1 : 0);
    std::printf("\n");

    if (f16Opt) {
        const char* impl = (f16Opt == Deep2::gemv_f16_avx512) ? "avx512" : "avx2";
        std::printf("F16_%s_TESTED=1\n", impl);
        std::printf("F16_%s_CASES=%zu\n", impl, f16m.cases);
        std::printf("F16_%s_ATOL=%.6e\n", impl, (double)kF16Atol);
        std::printf("F16_%s_RTOL=%.6e\n", impl, (double)kF16Rtol);
        std::printf("F16_%s_MAX_ABS_ERR=%.6e\n", impl, (double)f16m.maxAbs);
        std::printf("F16_%s_MAX_REL_ERR=%.6e\n", impl, (double)f16m.maxRel);
        std::printf("F16_%s_NONFINITE=%llu\n", impl,
                    (unsigned long long)f16m.nonfinite());
        std::printf("F16_%s_GUARD_CORRUPTION=%llu\n", impl,
                    (unsigned long long)f16m.guardCorruption);
        std::printf("F16_%s_PARITY=%d\n", impl, f16m.parity ? 1 : 0);
    } else {
        std::printf("F16_AVX512_TESTED=0\n");
        std::printf("F16_REASON=%s\n", f16Reason);
    }
    std::printf("\n");

    if (q8Opt) {
        std::printf("Q8_0_AVX2_TESTED=1\n");
        std::printf("Q8_0_AVX2_CASES=%zu\n", q8m.cases);
        std::printf("Q8_0_AVX2_ATOL=%.6e\n", (double)kQ8Atol);
        std::printf("Q8_0_AVX2_RTOL=%.6e\n", (double)kQ8Rtol);
        std::printf("Q8_0_AVX2_MAX_ABS_ERR=%.6e\n", (double)q8m.maxAbs);
        std::printf("Q8_0_AVX2_MAX_REL_ERR=%.6e\n", (double)q8m.maxRel);
        std::printf("Q8_0_AVX2_NONFINITE=%llu\n",
                    (unsigned long long)q8m.nonfinite());
        std::printf("Q8_0_AVX2_GUARD_CORRUPTION=%llu\n",
                    (unsigned long long)q8m.guardCorruption);
        std::printf("Q8_0_AVX2_PARITY=%d\n", q8m.parity ? 1 : 0);
    } else {
        std::printf("Q8_0_AVX2_TESTED=0\n");
        std::printf("Q8_0_REASON=%s\n", q8Reason);
    }
    std::printf("\n");

    std::printf("Q5_K_AVX2_TESTED=0\n");
    std::printf("Q5_K_AVX2_REASON=KNOWN_DEFECTIVE_NOT_REGISTERED\n");
    std::printf("Q5_K_AVX2_ALIAS_SHIELD=%d\n", q5Shield ? 1 : 0);
    std::printf("\n");

    std::printf("REGISTRY_F16_IMPL=%s\n", regF16);
    std::printf("REGISTRY_Q8_0_IMPL=%s\n", regQ8);
    std::printf("REGISTRY_Q5_K_IMPL=%s\n", regQ5);
    std::printf("REGISTRY_IMPL_MATCH=%d\n", implOk ? 1 : 0);
    std::printf("REGISTRY_PTR_MATCH=%d\n", ptrOk ? 1 : 0);
    std::printf("\n");

    std::printf("NO_NAN=%d\n", totalNonfinite == 0 ? 1 : 0);
    std::printf("NO_INF=%d\n", totalNonfinite == 0 ? 1 : 0);
    std::printf("OOB_GUARD_CORRUPTION=%llu\n",
                (unsigned long long)totalGuard);
    std::printf("\n");
    std::printf("QUANT_KERNEL_PARITY_001=%s\n", pass ? "PASS" : "FAIL");
    std::printf("==========================================================\n");

    return pass ? 0 : 1;
}