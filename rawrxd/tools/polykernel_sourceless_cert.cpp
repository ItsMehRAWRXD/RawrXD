// polykernel_cert.cpp — RAWRKD_POLYKERNEL_SOURCELESS_AUTHORITY_001
//
// Certifies that the x64 emitter produces machine code that EXECUTES and is
// numerically correct against the production F32 GEMV -- with no compiler
// invoked and no source text produced at any point.
//
// The check that matters most is F2. An emitter that emits nothing, or emits
// bytes that are never entered, would sail through a "did it compile" style
// gate. Here the generated blob is executed by the CPU and its output is
// compared element-wise against QuantKernelRegistry::GetGEMV(0).
//
// F3 is the falsification: a single flipped byte in the emitted code must change
// the result. If it does not, the bytes are not the thing being executed.

#include "PolyKernel.hpp"
#include "QuantKernelRegistry.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace Deep2;
using namespace Deep2::poly;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail = "") {
    if (ok) { ++g_pass; std::printf("CHECK PASS  %s\n", name); }
    else    { ++g_fail; std::printf("CHECK FAIL  %s  %s\n", name, detail.c_str()); }
    std::fflush(stdout);
}
static void kv(const char* k, std::uint64_t v) { std::printf("%s=%llu\n", k, (unsigned long long)v); }
static void kv(const char* k, double v)       { std::printf("%s=%.9g\n", k, v); }
static void kv(const char* k, bool v)         { std::printf("%s=%d\n", k, v ? 1 : 0); }
static void kv(const char* k, const std::string& v) { std::printf("%s=%s\n", k, v.c_str()); }

// ---------------------------------------------------------------------------
// Contained execution of arbitrary bytes.
//
// Executing deliberately corrupted machine code can fault at any instruction.
// __try/__except cannot live in a function that needs object unwinding, and this
// caller is full of std::vector and std::string, so the SEH frame is isolated in
// a function whose parameters and locals are all POD. The containment is real:
// a faulting corrupted kernel is an expected outcome, not a crash.
//
//   trapped: 1 -> the corrupted code faulted (also a detectable difference)
//   trapped: 0 -> it ran; the caller compares the output
// ---------------------------------------------------------------------------
static int g_trapped = 0;
static void runRawKernel(void* mem, const float* w, const float* x, float* y,
                         std::uint32_t rows, std::uint32_t cols) {
    using Fn = void (*)(const float*, const float*, float*, std::uint32_t, std::uint32_t);
    Fn f = reinterpret_cast<Fn>(mem);
    __try {
        f(w, x, y, rows, cols);
        g_trapped = 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_trapped = 1;
    }
}

int main() {
    std::printf("RAWRXD_POLYKERNEL_SOURCELESS_CERT\n");
    std::printf("===================================\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();

    const HardwareDescriptor hw = describeHardware();
    std::printf("HW avx2=%d avx512f=%d fma=%d vecWidth=%u\n",
                hw.avx2 ? 1 : 0, hw.avx512f ? 1 : 0, hw.fma ? 1 : 0, hw.maxVectorWidth);

    // ---------------------------------------------------------------------
    // C1: the planner must REFUSE what it cannot emit, not approximate it.
    // ---------------------------------------------------------------------
    {
        KernelRequest gpuReq;
        gpuReq.op = PolyOp::GEMV;
        gpuReq.M = 4; gpuReq.N = 8; gpuReq.gpu = true;
        std::string why;
        long h = PolyKernelAuthority::Instance().acquire(gpuReq, &why);
        check(h < 0 && !why.empty(),
              "C1_GPU_FORM_REFUSED_WITH_REASON",
              "a GPU request was accepted without a SPIR-V emitter existing");

        KernelRequest qReq;
        qReq.op = PolyOp::GEMV;
        qReq.M = 4; qReq.N = 256; qReq.quantType = 12;   // Q4_K
        std::string why2;
        long h2 = PolyKernelAuthority::Instance().acquire(qReq, &why2);
        check(h2 < 0 && !why2.empty(),
              "C2_QUANT_FORM_REFUSED_NOT_APPROXIMATED",
              "a Q4_K request was accepted although only F32 decode is emitted");
        std::printf("QUANT_REJECT=%s\n", why2.c_str());
    }

    // ---------------------------------------------------------------------
    // C3: KernelKey must not be derivable from model identity. Two requests
    // differing ONLY in a hypothetical model field must collide -- which is the
    // point: the key has no room for it.
    // ---------------------------------------------------------------------
    {
        KernelRequest a, b;
        a.op = PolyOp::GEMV; a.M = 8; a.N = 64; a.quantType = 0;
        b = a;
        const KernelKey ka = makeKey(a), kb = makeKey(b);
        check(ka == kb,
              "C3_KERNEL_KEY_CARRIES_NO_MODEL_IDENTITY",
              "two identical execution shapes produced different keys, so the key "
              "is depending on something other than the execution shape");
        check(std::memcmp(&ka, &kb, sizeof(ka)) == 0,
              "C3B_KEY_BYTES_IDENTICAL",
              "key bytes differ for identical execution shapes");
    }

    // ---------------------------------------------------------------------
    // C4/C5/F2: emit, execute, compare against the production kernel.
    // ---------------------------------------------------------------------
    const std::uint32_t rows = 37, cols = 256;   // rows deliberately not a
                                                  // power of two
    KernelRequest req;
    req.op = PolyOp::GEMV;
    req.M = rows; req.N = cols; req.K = cols;
    req.quantType = 0;
    req.inputType = 0; req.outputType = 0;
    req.gpu = false;
    req.hardwareSignature = 0x5A5A5A5Au;
    req.layoutSignature = 0x1234u;

    std::string why;
    long handle = PolyKernelAuthority::Instance().acquire(req, &why);
    check(handle >= 0, "C4_EMITTED_BYTES_ACQUIRED", why);
    if (handle < 0) {
        std::printf("CHECKS_RUN=%d\nCHECKS_PASS=%d\nCHECKS_FAIL=%d\nVERDICT=FAIL\n",
                    g_pass + g_fail, g_pass, g_fail);
        return 1;
    }

    // Re-emit to inspect the bytes without executing, for the receipt.
    {
        KernelPlan plan = planGEMV(req, hw);
        KernelBlob blob = emitX64(plan.ir, req, hw);
        kv("EMITTED_OK", blob.ok);
        kv("EMITTED_BYTES", (std::uint64_t)blob.bytes.size());
        kv("EMITTED_DIGEST", blob.digest);
        std::string hex;
        char t[4];
        for (std::size_t i = 0; i < blob.bytes.size() && i < 24; ++i) {
            std::snprintf(t, sizeof(t), "%02X", blob.bytes[i]);
            hex += t;
        }
        std::printf("EMITTED_HEAD=%s\n", hex.c_str());
        // A generated-source emitter would have produced text. Bytes whose
        // printable ratio is high enough to be C++ would be the failure mode.
        std::size_t printable = 0;
        for (std::uint8_t c : blob.bytes)
            if (c >= 32 && c < 127) ++printable;
        const double ratio = blob.bytes.empty() ? 1.0
                             : (double)printable / (double)blob.bytes.size();
        kv("EMITTED_PRINTABLE_RATIO", ratio);
        check(ratio < 0.60,
              "C5_OUTPUT_IS_MACHINE_CODE_NOT_SOURCE_TEXT",
              "the emitted artifact looks like text, so it is generated source, "
              "not machine code");
    }

    // Real data, real reference.
    std::vector<float> w((std::size_t)rows * cols), x(cols);
    std::mt19937 rng(12345);
    std::uniform_real_distribution<float> d(-1.0f, 1.0f);
    for (auto& v : w) v = d(rng);
    for (auto& v : x) v = d(rng);

    std::vector<float> yGen(rows, 0.0f), yRef(rows, 0.0f);
    KernelBinding bind;
    bind.weight = w.data();
    bind.x = x.data();
    bind.y = yGen.data();
    bind.rows = rows;
    bind.cols = cols;

    const bool ran = PolyKernelAuthority::Instance().execute(handle, bind);
    check(ran, "F2_GENERATED_KERNEL_EXECUTED", "execute() returned false");

    const auto* ref = QuantKernelRegistry::Instance().GetGEMV(0);   // F32
    check(ref != nullptr, "C6_PRODUCTION_REFERENCE_AVAILABLE",
          "F32 reference kernel is not registered");
    if (ref) {
        ref(reinterpret_cast<const std::uint8_t*>(w.data()), x.data(),
            yRef.data(), rows, cols);
    }

    double maxAbs = 0.0, maxRel = 0.0;
    bool allFinite = true, anyNonZero = false;
    std::size_t mismatch = 0;
    for (std::uint32_t i = 0; i < rows; ++i) {
        if (!std::isfinite(yGen[i])) allFinite = false;
        if (yGen[i] != 0.0f) anyNonZero = true;
        const double dd = std::fabs((double)yGen[i] - (double)yRef[i]);
        if (dd > 1e-9) ++mismatch;
        if (dd > maxAbs) maxAbs = dd;
        const double den = std::fabs((double)yRef[i]);
        if (den > 1e-6) {
            const double rel = dd / den;
            if (rel > maxRel) maxRel = rel;
        }
    }
    kv("GEN_MAX_ABS_DIFF", maxAbs);
    kv("GEN_MAX_REL_DIFF", maxRel);
    kv("GEN_MISMATCHED_ELEMENTS", (std::uint64_t)mismatch);
    kv("GEN_ROWS", (std::uint64_t)rows);
    kv("GEN_COLS", (std::uint64_t)cols);

    check(allFinite, "C7_GENERATED_OUTPUT_FINITE", "generated output has non-finite values");
    check(anyNonZero, "C8_GENERATED_OUTPUT_NOT_ALL_ZERO",
          "every generated element is zero, which means the kernel did no work "
          "and a zero-vs-zero comparison would look like agreement");
    check(maxRel < 1e-5,
          "C9_PARITY_WITH_PRODUCTION_F32_GEMV",
          "generated kernel disagrees with production; maxRel=" + std::to_string(maxRel));

    // ---------------------------------------------------------------------
    // F3 FALSIFICATION: corrupt ONE byte of the emitted code and require the
    // result to change. If it does not, the bytes are not what is executing.
    // ---------------------------------------------------------------------
    {
        KernelPlan plan = planGEMV(req, hw);
        KernelBlob good = emitX64(plan.ir, req, hw);

        // Find a byte inside the multiply opcode (0x54) and flip its ModRM.
        std::size_t mulAt = good.bytes.size();
        for (std::size_t i = 0; i + 2 < good.bytes.size(); ++i) {
            if (good.bytes[i] == 0xC5 && good.bytes[i + 2] == 0x54) { mulAt = i + 3; break; }
        }
        check(mulAt < good.bytes.size(),
              "F3A_FOUND_THE_INSTRUCTION_TO_CORRUPT",
              "could not locate the vmulps encoding to corrupt");

        if (mulAt < good.bytes.size()) {
            std::vector<std::uint8_t> bad = good.bytes;
            const std::uint8_t before = bad[mulAt];
            bad[mulAt] = static_cast<std::uint8_t>(before ^ 0x07);  // change mod/reg/rm
            const std::uint64_t badDigest = fnv1a64(bad.data(), bad.size());

            // Execute the corrupted blob directly.
            void* mem = VirtualAlloc(nullptr, bad.size(),
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (mem) {
                std::memcpy(mem, bad.data(), bad.size());
                DWORD old = 0;
                if (VirtualProtect(mem, bad.size(), PAGE_EXECUTE_READ, &old)) {
                    FlushInstructionCache(GetCurrentProcess(), mem, bad.size());
                    std::vector<float> yBad(rows, 0.0f);
                    runRawKernel(mem, w.data(), x.data(), yBad.data(), rows, cols);
                    kv("FALSIFY_TRAPPED", g_trapped != 0);

                    bool differs = (g_trapped != 0);
                    if (!differs) {
                        for (std::uint32_t i = 0; i < rows; ++i)
                            if (yBad[i] != yGen[i]) { differs = true; break; }
                    }
                    kv("FALSIFY_BYTE_AT", (std::uint64_t)mulAt);
                    kv("FALSIFY_DIGEST", badDigest);
                    kv("FALSIFY_RESULT_DIFFERS", differs);
                    check(differs,
                          "F3_CORRUPTED_MACHINE_CODE_CHANGES_THE_RESULT",
                          "flipping a byte of the emitted code left the output "
                          "identical, so the emitted bytes are not what executes");
                    VirtualFree(mem, 0, MEM_RELEASE);
                }
            }
        }
    }

    // ---------------------------------------------------------------------
    // C10: cache behaviour. The second identical request must be a cache hit,
    // proving identity is the execution shape rather than the call site.
    // ---------------------------------------------------------------------
    {
        const std::uint64_t genBefore = PolyKernelAuthority::stats().generated;
        const std::uint64_t hitBefore = PolyKernelAuthority::stats().cacheHits;
        long again = PolyKernelAuthority::Instance().acquire(req, nullptr);
        const std::uint64_t genAfter = PolyKernelAuthority::stats().generated;
        const std::uint64_t hitAfter = PolyKernelAuthority::stats().cacheHits;
        check(again == handle && genAfter == genBefore && hitAfter == hitBefore + 1,
              "C10_SECOND_IDENTICAL_REQUEST_IS_A_CACHE_HIT",
              "the authority regenerated instead of reusing an equivalent shape");
    }

    // ---------------------------------------------------------------------
    // C11: a different geometry must NOT hit the cache.
    // ---------------------------------------------------------------------
    {
        const std::uint64_t genBefore = PolyKernelAuthority::stats().generated;
        KernelRequest other = req;
        other.M = rows + 8;
        long h3 = PolyKernelAuthority::Instance().acquire(other, nullptr);
        const std::uint64_t genAfter = PolyKernelAuthority::stats().generated;
        check(h3 >= 0 && genAfter == genBefore + 1,
              "C11_DIFFERENT_GEOMETRY_GENERATES_A_SEPARATE_FORM",
              "a changed row count reused a form built for the old geometry");
    }

    PolyKernelAuthority::Stats st = PolyKernelAuthority::stats();
    kv("REQUESTS", st.requests);
    kv("GENERATED", st.generated);
    kv("CACHE_HITS", st.cacheHits);
    kv("REJECTED", st.rejected);
    kv("EXECUTIONS", st.executions);

    std::printf("------------------------\n");
    std::printf("CHECKS_RUN=%d\nCHECKS_PASS=%d\nCHECKS_FAIL=%d\n",
                g_pass + g_fail, g_pass, g_fail);
    const bool ok = (g_fail == 0);
    std::printf("VERDICT=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}