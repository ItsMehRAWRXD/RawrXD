// chaser_x64_cert.cpp — RAWRXD_DREAMCATCH_CHASER_X64_001
//
// The first complete chain:
//
//   FROZEN PREDICTION
//        ↓  (commit)
//   x86-64 EMITTER            real machine-code bytes, no compiler, no source
//        ↓
//   REAL INVOCATION           the emitted kernel is actually entered
//        ↓
//   PERFORMANCE_INFORMATION    facts about execution, not a reinterpretation
//        ↓
//   DREAMCATCH MATCH/MISMATCH
//        ↓
//   tryRewrite() STILL FALSE   non-retroactive
//
// The negative control is the part that makes this worth running. A harness
// that can only report success proves nothing about its endpoint checker, so a
// deliberately corrupted instruction is put through the identical pipeline and
// REQUIRED to fail. If the corrupted chaser ever reaches the endpoint, the
// checker is ceremonial and this certificate is worthless.

#include "CommaProof.hpp"
#include "DreamCatch.hpp"
#include "PolyKernel.hpp"
#include "QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace Deep2;
using namespace Deep2::poly;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* n, const std::string& d = "") {
    if (ok) { ++g_pass; std::printf("CHECK PASS  %s\n", n); }
    else    { ++g_fail; std::printf("CHECK FAIL  %s  %s\n", n, d.c_str()); }
    std::fflush(stdout);
}
static void kv(const char* k, std::uint64_t v) { std::printf("%s=%llu\n", k, (unsigned long long)v); }
static void kvd(const char* k, double v)       { std::printf("%s=%.9g\n", k, v); }
static void kvb(const char* k, bool v)         { std::printf("%s=%d\n", k, v ? 1 : 0); }
static void kvs(const char* k, const std::string& v) { std::printf("%s=%s\n", k, v.c_str()); }

static std::uint64_t hashBytes(const void* p, std::size_t n) {
    return poly::fnv1a64(p, n);
}

// Contained execution of arbitrary bytes: a corrupted instruction can fault.
static int g_trapped = 0;
static void runRaw(void* mem, const float* w, const float* x, float* y,
                   std::uint32_t r, std::uint32_t c) {
    using Fn = void (*)(const float*, const float*, float*, std::uint32_t, std::uint32_t);
    Fn f = reinterpret_cast<Fn>(mem);
    __try { f(w, x, y, r, c); g_trapped = 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { g_trapped = 1; }
}

// PERFORMANCE_INFORMATION: facts about an execution that already happened.
struct PerformanceInformation {
    std::uint64_t predictionId = 0;
    std::uint64_t codeBytes = 0, codeHash = 0;
    std::uint64_t inputHash = 0, weightHash = 0, outputHash = 0;
    std::uint64_t referenceOutputHash = 0;
    double maxAbsDiff = 0.0, maxRelDiff = 0.0;
    bool finite = false, boundsPass = false, semanticParityPass = false;
    std::uint64_t executionNs = 0, referenceNs = 0;
    bool endpointReached = false;
};

struct ChaserRun {
    PerformanceInformation info;
    bool corrupted = false;
    std::string realization;
};

static ChaserRun executeChaser(const std::vector<std::uint8_t>& bytes,
                               const std::vector<float>& w,
                               const std::vector<float>& x,
                               std::uint32_t rows, std::uint32_t cols,
                               const auto* ref, bool corrupt,
                               std::uint64_t predictionId) {
    ChaserRun run;
    run.corrupted = corrupt;
    run.realization = corrupt ? "X64_CORRUPTED_NEGATIVE_CONTROL" : "X64_EMITTED_AVX2";

    std::vector<std::uint8_t> code = bytes;
    if (corrupt) {
        // Flip one byte inside an instruction. Locate the vmulps opcode (0x54
        // preceded by a 2-byte VEX) and corrupt its ModRM.
        for (std::size_t i = 0; i + 2 < code.size(); ++i) {
            if (code[i] == 0xC5 && code[i + 2] == 0x54) { code[i + 3] ^= 0x07; break; }
        }
    }

    run.info.predictionId = predictionId;
    run.info.codeBytes = code.size();
    run.info.codeHash  = hashBytes(code.data(), code.size());
    run.info.inputHash = hashBytes(x.data(), x.size() * sizeof(float));
    run.info.weightHash = hashBytes(w.data(), w.size() * sizeof(float));

    void* mem = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return run;
    std::memcpy(mem, code.data(), code.size());
    DWORD old = 0;
    if (!VirtualProtect(mem, code.size(), PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return run;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, code.size());

    std::vector<float> y(rows, 0.0f), yRef(rows, 0.0f);

    LARGE_INTEGER f, t0, t1;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t0);
    runRaw(mem, w.data(), x.data(), y.data(), rows, cols);
    QueryPerformanceCounter(&t1);
    run.info.executionNs = (std::uint64_t)
        ((t1.QuadPart - t0.QuadPart) * 1000000000ll / f.QuadPart);

    if (ref) {
        QueryPerformanceCounter(&t0);
        ref(reinterpret_cast<const std::uint8_t*>(w.data()), x.data(), yRef.data(), rows, cols);
        QueryPerformanceCounter(&t1);
        run.info.referenceNs = (std::uint64_t)
            ((t1.QuadPart - t0.QuadPart) * 1000000000ll / f.QuadPart);
    }

    bool finite = true, close = true;
    for (std::uint32_t i = 0; i < rows; ++i) {
        if (!std::isfinite(y[i]))    { finite = false; close = false; }
        const double d = std::fabs((double)y[i] - (double)yRef[i]);
        if (d > run.info.maxAbsDiff) run.info.maxAbsDiff = d;
        const double den = std::fabs((double)yRef[i]);
        if (den > 1e-6) {
            const double rel = d / den;
            if (rel > run.info.maxRelDiff) run.info.maxRelDiff = rel;
        }
    }
    run.info.finite = finite;
    run.info.boundsPass = finite && !g_trapped;
    run.info.semanticParityPass = (run.info.maxRelDiff < 1e-5);
    run.info.outputHash = hashBytes(y.data(), y.size() * sizeof(float));
    run.info.referenceOutputHash = hashBytes(yRef.data(), yRef.size() * sizeof(float));
    run.info.endpointReached = run.info.boundsPass && run.info.semanticParityPass;

    VirtualFree(mem, 0, MEM_RELEASE);
    return run;
}

int main() {
    std::printf("RAWRXD_DREAMCATCH_CHASER_X64_001\n");
    std::printf("==================================\n");

    auto& reg = QuantKernelRegistry::Instance();
    reg.Initialize();
    reg.ProbeCPU();
    const poly::HardwareDescriptor hw = poly::describeHardware();
    std::printf("ISA avx2=%d avx512f=%d\n", hw.avx2 ? 1 : 0, hw.avx512f ? 1 : 0);
    if (!hw.avx2) {
        std::printf("VERDICT=NOT_APPLICABLE_NO_AVX2\n");
        return 0;
    }

    // =================================================================
    // STEP 1: DREAM. Describe a future. Emit nothing, execute nothing.
    // =================================================================
    const std::uint32_t rows = 64, cols = 512;
    dream::StateSnapshot origin;
    origin.originEpoch = 7;
    origin.residentBytes = (std::uint64_t)rows * cols * 4;
    origin.deviceCount = 2;
    origin.gpuPresent = true;
    origin.avx2 = true;

    dream::PredictedState predicted;
    predicted.endpoint.kind = dream::EndpointContract::Kind::CORRECTNESS_WITHIN_BOUND;
    predicted.endpoint.rows = rows;
    predicted.endpoint.cols = cols;
    predicted.endpoint.quantType = 0;      // F32 GEMV
    predicted.endpoint.errorBound = 1e-5;
    predicted.predictedResidentBytes = origin.residentBytes;
    predicted.predictedDeviceCount = 2;
    predicted.predictedGpuResident = false;

    const dream::DreamCatch frozen =
        dream::DreamCatch::freeze(origin, predicted, 9001);
    const std::uint64_t predictionId = frozen.dreamId();
    const std::uint64_t predictedHash = frozen.predictedHash();

    std::printf("STEP1_DREAM_PREDICTION_ID=%llu\n", (unsigned long long)predictionId);
    kvb("PREDICTION_FROZEN", frozen.isFrozen());
    kv("PREDICTED_CONTENT_HASH", predictedHash);
    kvs("PREDICTED_CHASER", "OP=GEMV QUANT=F32 ROWS=64 COLS=512 ISA=AVX2 TOL=1e-5");
    check(frozen.isFrozen(), "S1_PREDICTION_FROZEN_BEFORE_EMIT",
          "the prediction was not frozen before the emitter ran");

    // =================================================================
    // STEP 2: COMMIT. Only now is anything generated.
    // =================================================================
    KernelRequest req;
    req.op = poly::PolyOp::GEMV;
    req.M = rows; req.N = cols; req.K = cols;
    req.quantType = 0;
    req.gpu = false;

    const KernelPlan plan = poly::planGEMV(req, hw);
    check(plan.supported, "S2_PLAN_SUPPORTED", plan.rejectReason);
    const KernelBlob blob = poly::emitX64(plan.ir, req, hw);
    check(blob.ok, "S2B_EMITTED_MACHINE_CODE", blob.rejectReason);
    kv("CODE_BYTES", (std::uint64_t)blob.bytes.size());
    kv("CODE_HASH", blob.digest);
    if (!blob.ok) {
        std::printf("VERDICT=EMITTER_REFUSED\n");
        return 1;
    }

    // =================================================================
    // STEP 3: REAL EXECUTION, good chaser and negative control.
    // =================================================================
    std::vector<float> w((std::size_t)rows * cols), x(cols);
    std::mt19937 rng(4242);
    std::uniform_real_distribution<float> d(-1.0f, 1.0f);
    for (auto& v : w) v = d(rng);
    for (auto& v : x) v = d(rng);
    const auto* ref = QuantKernelRegistry::Instance().GetGEMV(0);

    const ChaserRun good = executeChaser(blob.bytes, w, x, rows, cols, ref, false, predictionId);
    const ChaserRun bad  = executeChaser(blob.bytes, w, x, rows, cols, ref, true,  predictionId);

    std::printf("---- good chaser ----\n");
    kvs("REALIZATION", good.realization);
    kv("EXECUTION_NS", good.info.executionNs);
    kv("REFERENCE_NS", good.info.referenceNs);
    kvd("MAX_ABS_DIFF", good.info.maxAbsDiff);
    kvd("MAX_REL_DIFF", good.info.maxRelDiff);
    kvb("FINITE_PASS", good.info.finite);
    kvb("BOUNDS_PASS", good.info.boundsPass);
    kvb("SEMANTIC_PARITY_PASS", good.info.semanticParityPass);
    kvb("ENDPOINT_REACHED", good.info.endpointReached);

    std::printf("---- negative control ----\n");
    kvs("REALIZATION", bad.realization);
    kv("CODE_HASH", bad.info.codeHash);
    kvd("MAX_ABS_DIFF", bad.info.maxAbsDiff);
    kvb("TRAPPED", g_trapped != 0);
    kvb("BOUNDS_PASS", bad.info.boundsPass);
    kvb("SEMANTIC_PARITY_PASS", bad.info.semanticParityPass);
    kvb("ENDPOINT_REACHED", bad.info.endpointReached);

    check(good.info.endpointReached, "S3_GOOD_CHASER_REACHES_ENDPOINT",
          "the correctly generated kernel failed its own endpoint");
    check(!bad.info.endpointReached,
          "S4_BAD_CHASER_MUST_NOT_REACH_ENDPOINT",
          "a corrupted instruction still reached the endpoint, so the checker is "
          "ceremonial and this whole certificate means nothing");
    check(good.info.codeHash != bad.info.codeHash,
          "S5_NEGATIVE_CONTROL_USED_DIFFERENT_CODE",
          "the negative control ran identical bytes, so it proved nothing");

    // =================================================================
    // STEP 4: DREAMCATCH join. Facts only.
    // =================================================================
    dream::ChaserEvidence ev;
    ev.chaserId = 1;
    ev.realization = good.realization;
    ev.endState = origin;
    ev.actualEndpoint = dream::EndpointContract::Kind::CORRECTNESS_WITHIN_BOUND;
    ev.executionNs = good.info.executionNs;
    ev.correct = good.info.semanticParityPass;
    ev.maxError = good.info.maxRelDiff;
    const bool admitted = dream::ChaserRegistry::Instance().submit(frozen, ev);
    check(admitted, "S6_CHASER_EVIDENCE_ADMITTED",
          "evidence for a frozen prediction was refused");

    auto sum = dream::ChaserRegistry::Instance().summarise(predictionId);
    kv("CHASES", (std::uint64_t)sum.chases);
    kv("CHASES_REACHED", (std::uint64_t)sum.reached);
    kv("TAMPERED", (std::uint64_t)sum.tampered);
    kvs("CONSENSUS", dream::chaseResultName(sum.consensus));

    // =================================================================
    // STEP 5: non-retroactivity, AFTER the result is known.
    // =================================================================
    dream::PredictedState retrofit = predicted;
    retrofit.endpoint.errorBound = 1e9;   // would trivially "explain" any result
    const bool rewritten = frozen.tryRewrite(retrofit);
    kv("REWRITE_AFTER_EXECUTION_SUCCEEDED", rewritten ? 1u : 0u);
    kv("CONTENT_HASH_UNCHANGED", frozen.predictedHash() == predictedHash ? 1u : 0u);
    check(!rewritten, "S7_REWRITE_AFTER_EXECUTION_REFUSED",
          "the prediction was editable once the result was known");
    check(frozen.predictedHash() == predictedHash,
          "S8_CONTENT_HASH_UNCHANGED_AFTER_RESULT",
          "the frozen content hash moved after execution");

    // =================================================================
    // STEP 6: dreamless certificate over the whole chain.
    // =================================================================
    proof::CommaProof p;
    p.observe("PREDICTION_ID", std::to_string(predictionId));
    p.observe("PREDICTED_CONTENT_HASH", std::to_string(predictedHash));
    p.observe("CODE_BYTES", std::to_string((int)blob.bytes.size()));
    p.observe("CODE_HASH", std::to_string((std::uint64_t)blob.digest));
    p.observe("EXECUTION_NS", std::to_string((std::uint64_t)good.info.executionNs));
    p.observe("REFERENCE_NS", std::to_string((std::uint64_t)good.info.referenceNs));
    p.observe("MAX_REL_DIFF", good.info.maxRelDiff == 0.0 ? "0" : "NONZERO");
    p.observe("GOOD_CHASER_ENDPOINT_REACHED", good.info.endpointReached ? "1" : "0");
    p.observe("BAD_CHASER_ENDPOINT_REACHED", bad.info.endpointReached ? "1" : "0");
    p.observe("NEGATIVE_CONTROL_CODE_DIFFERS",
              (good.info.codeHash != bad.info.codeHash) ? "1" : "0");
    p.observe("REWRITE_AFTER_EXECUTION_SUCCEEDED", rewritten ? "1" : "0");
    p.observe("CONTENT_HASH_UNCHANGED", frozen.predictedHash() == predictedHash ? "1" : "0");

    std::vector<proof::CommaProof::Requirement> reqs;
    reqs.push_back({"PREDICTION_FROZEN_BEFORE_EMIT", "0", false, false, "frozen first"});
    reqs.push_back({"GOOD_CHASER_ENDPOINT_REACHED", "1", false, false, "good reaches"});
    reqs.push_back({"BAD_CHASER_ENDPOINT_REACHED", "0", false, false, "bad must not"});
    reqs.push_back({"NEGATIVE_CONTROL_CODE_DIFFERS", "1", false, false, "control differs"});
    reqs.push_back({"REWRITE_AFTER_EXECUTION_SUCCEEDED", "0", false, false, "no retcon"});
    reqs.push_back({"CONTENT_HASH_UNCHANGED", "1", false, false, "hash intact"});
    p.declareEndpoint("GENERATED_X64_KERNEL_PRESERVES_DECLARED_GEMV_SEMANTICS", reqs);
    // Freeze state is structural, so record it as a fact rather than a constant.
    p.observe("PREDICTION_FROZEN_BEFORE_EMIT", frozen.isFrozen() ? "1" : "0");
    p.observe("PREDICTOR_AUTHORITY", "REQUIEM");

    std::printf("CHAIN_CERT=%s\n", p.toLine().c_str());
    auto v = p.verdict();
    kv("REQ_PASSED", (std::uint64_t)v.passed);
    kv("REQ_FAILED", (std::uint64_t)v.failed);
    kv("REQ_UNKNOWN", (std::uint64_t)v.unknown);
    kvb("ENDPOINT_REACHED", v.reached);

    std::printf("CHAIN_STATE: ADMISSION_CERT=SEPARATE  MEMORY_ENVELOPE_CERT=SEPARATE  "
                "ADMISSION_IMPLIES_KERNEL=0  KERNEL_IMPLIES_MODEL_CORRECTNESS=0\n");

    std::printf("------------------------\n");
    std::printf("CHECKS_RUN=%d\nCHECKS_PASS=%d\nCHECKS_FAIL=%d\n",
                g_pass + g_fail, g_pass, g_fail);
    const bool ok = (g_fail == 0) && v.reached;
    std::printf("VERDICT=%s\n", ok ? "CHASER_X64_CHAIN_COMPLETE" : "CHAIN_INCOMPLETE");
    return ok ? 0 : 1;
}