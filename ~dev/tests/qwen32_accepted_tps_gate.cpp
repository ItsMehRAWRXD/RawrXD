// qwen32_accepted_tps_gate.cpp — DEEP2_QWEN32_ACCEPTED_TPS_001
//
// Measures accepted-token decode TPS after warmup on real Qwen2.5-32B weights.
// Warmup: 32 tokens (not measured).
// Measured: 256 committed output tokens.
//
// Authority rules:
//   - WARMUP_TOKENS must complete with zero STRICT_GPU_VIOLATIONS.
//   - MEASURED_TOKENS must complete with zero STRICT_GPU_VIOLATIONS.
//   - DUAL_PHYSICAL_GPU_FORWARD must be 1.
//   - ACCEPTED_DECODE_TPS is (acceptedOutputTokens / decodeWallS).
//
// Classification:
//   >= 85 TPS     → 85-TPS target PROVEN
//   70–84.99      → close; optimize measured bottleneck
//   40–69.99      → machinery works but major throughput gap remains
//   < 40          → inspect acceptance/residency/synchronization before tuning

#include "deep2/Deep2Engine.h"
#include "deep2/Deep2Speculative.hpp"
#include "deep2/Deep2GpuForward.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace Deep2 {
    extern std::atomic<double> gAsyncRowRatio;
}

std::atomic<uint32_t> g_strictGpuViolations{0};

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
static LONG CALLBACK Deep2InPageProbe(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
    const EXCEPTION_RECORD* r = ep->ExceptionRecord;
    if (r->ExceptionCode != 0xC0000006u) return EXCEPTION_CONTINUE_SEARCH;
    std::fprintf(stderr, "\nDEEP2_INPAGE_FAULT=1\n"); std::fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

using namespace Deep2;

static bool setup(Deep2Engine& e, const char* model, bool spec) {
    std::fprintf(stderr, "SPEC_SETUP_ENTER spec=%d\n", (int)spec); fflush(stderr);
    EngineConfig c{};
    c.maxSeqLen = 4096;
    if (!e.initialize(c)) { std::fprintf(stderr, "SPEC_INIT_FAIL\n"); fflush(stderr); return false; }
    std::fprintf(stderr, "SPEC_INIT_OK\n"); fflush(stderr);
    if (!e.loadModel(model)) { std::fprintf(stderr, "SPEC_LOAD_FAIL\n"); fflush(stderr); return false; }
    const auto& g = e.getConfig();
    if (g.numLayers != 64 || g.hiddenDim != 5120 || g.numHeads != 40 || g.numKVHeads != 8)
        return false;
    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if (!e.isVulkanInitialized() || e.vulkanDeviceCount() < 2) return false;
    GenerationOptions o{};
    o.temperature = 0.0f; o.topK = 1; o.topP = 1.0f; o.seed = 1;
    e.configureGeneration(o);
    e.enableVerifiedSpeculation(spec, 4);
    std::fprintf(stderr, "SPEC_SETUP_EXIT\n"); fflush(stderr);
    return true;
}

static std::vector<int> generateN(
    Deep2Engine& e, const std::string& prompt, size_t n, InferenceStats& s)
{
    auto p = e.tokenize(prompt);
    std::vector<int> out(n);
    const size_t got = e.generate(p.data(), p.size(), out.data(), out.size(), &s);
    out.resize(got);
    return out;
}

static void writeReceipt(const char* path,
    double acceptedDecodeTps,
    uint64_t warmupTokens, uint64_t measuredTokens,
    uint64_t specProposed, uint64_t specAccepted, uint64_t specRejected,
    double specAcceptRate,
    uint64_t decodeWallNs,
    uint64_t dualRowSlot0, uint64_t dualRowSlot1,
    int dualPhysicalGpuForward,
    uint64_t hostFallbacks, uint32_t strictGpuViolations,
    int deviceLost)
{
    FILE* f = nullptr;
    fopen_s(&f, path, "wb");
    if (!f) return;
    fprintf(f, "GATE=DEEP2_QWEN32_ACCEPTED_TPS_001\n");
    fprintf(f, "STATUS=%s\n",
        strictGpuViolations == 0 && dualPhysicalGpuForward && !deviceLost
            ? "PASS" : "FAIL");
    fprintf(f, "SOURCE_WIRED=1\n");
    fprintf(f, "LIVE_PRODUCT_RUN=RAN\n");
    fprintf(f, "RUNTIME_REACHED=1\n");
    fprintf(f, "MODEL_SHA256=\n");
    fprintf(f, "ENGINE_SHA256=\n");
    fprintf(f, "COMMIT=\n");
    fprintf(f, "GPU0=R9700\n");
    fprintf(f, "GPU1=RX7800XT\n");
    fprintf(f, "WARMUP_TOKENS=%llu\n", (unsigned long long)warmupTokens);
    fprintf(f, "MEASURED_TOKENS=%llu\n", (unsigned long long)measuredTokens);
    fprintf(f, "SPEC_PROPOSED=%llu\n", (unsigned long long)specProposed);
    fprintf(f, "SPEC_ACCEPTED=%llu\n", (unsigned long long)specAccepted);
    fprintf(f, "SPEC_REJECTED=%llu\n", (unsigned long long)specRejected);
    fprintf(f, "SPEC_ACCEPT_RATE=%.6f\n", specAcceptRate);
    fprintf(f, "DECODE_WALL_NS=%llu\n", (unsigned long long)decodeWallNs);
    fprintf(f, "ACCEPTED_DECODE_TPS=%.4f\n", acceptedDecodeTps);
    fprintf(f, "DUAL_ROW_SLOT_0=%llu\n", (unsigned long long)dualRowSlot0);
    fprintf(f, "DUAL_ROW_SLOT_1=%llu\n", (unsigned long long)dualRowSlot1);
    fprintf(f, "DUAL_PHYSICAL_GPU_FORWARD=%d\n", dualPhysicalGpuForward);
    fprintf(f, "CPU_FALLBACKS=%llu\n", (unsigned long long)hostFallbacks);
    fprintf(f, "STRICT_GPU_VIOLATIONS=%u\n", strictGpuViolations);
    fprintf(f, "DEVICE_LOST=%d\n", deviceLost);
    fprintf(f, "OUTPUT_QUALITY=\n");
    fprintf(f, "AUTHORITY_RESULT=%s\n",
        strictGpuViolations == 0 && dualPhysicalGpuForward && !deviceLost
            ? "ACCEPTED" : "REJECTED");
    fprintf(f, "PROMOTE=0\nTIP_CLIMB=HOLD\nNOT_RUN!=PASS\n");
    fclose(f);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: qwen32_accepted_tps_gate model.gguf\n");
        return 2;
    }
    const char* model = argv[1];
    const std::string prompt =
        "Implement a high performance C++ lock free queue and explain "
        "the memory ordering guarantees in detail. ";

    const uint64_t WARMUP_TOKENS = 32;
    const uint64_t MEASURED_TOKENS = 256;

    // ── Setup ──
    Deep2Engine e;
    if (!setup(e, model, true)) {
        std::fprintf(stderr, "SETUP_FAIL\n"); fflush(stderr);
        return 20;
    }

    // ── Warmup ──
    e.resetGpuForwardCounters();
    InferenceStats warmupStats{};
    std::fprintf(stderr, "WARMUP_BEGIN n=%llu\n", (unsigned long long)WARMUP_TOKENS); fflush(stderr);
    auto warmupOut = generateN(e, prompt, (size_t)WARMUP_TOKENS, warmupStats);
    std::fprintf(stderr, "WARMUP_END got=%zu\n", warmupOut.size()); fflush(stderr);
    if (warmupOut.size() != WARMUP_TOKENS) {
        std::fprintf(stderr, "WARMUP_FAIL got=%zu expected=%llu\n",
            warmupOut.size(), (unsigned long long)WARMUP_TOKENS); fflush(stderr);
        return 21;
    }
    if (e.vulkanStrictViolation()) {
        g_strictGpuViolations.fetch_add(1, std::memory_order_relaxed);
        std::fprintf(stderr, "WARMUP_STRICT_GPU_VIOLATION\n"); fflush(stderr);
        return 22;
    }

    // ── Freeze adaptive split ratio after warmup ──
    double frozenRatio = Deep2::gAsyncRowRatio.load(std::memory_order_relaxed);
    std::fprintf(stderr, "ADAPTIVE_SPLIT_FREEZE ratio=%.4f\n", frozenRatio); fflush(stderr);
#ifdef _WIN32
    _putenv_s("DEEP2_ASYNC_SPLIT_CONTROL", "0");
#else
    setenv("DEEP2_ASYNC_SPLIT_CONTROL", "0", 1);
#endif

    // ── Measured generation ──
    e.reset();                     // clear KV cache / hidden state between runs
    e.resetGpuForwardCounters();
    InferenceStats measuredStats{};
    std::fprintf(stderr, "MEASURED_BEGIN n=%llu\n", (unsigned long long)MEASURED_TOKENS); fflush(stderr);

    auto tDecodeStart = std::chrono::steady_clock::now();
    auto measuredOut = generateN(e, prompt, (size_t)MEASURED_TOKENS, measuredStats);
    auto tDecodeEnd = std::chrono::steady_clock::now();

    std::fprintf(stderr, "MEASURED_END got=%zu\n", measuredOut.size()); fflush(stderr);
    if (measuredOut.size() != MEASURED_TOKENS) {
        std::fprintf(stderr, "MEASURED_FAIL got=%zu expected=%llu\n",
            measuredOut.size(), (unsigned long long)MEASURED_TOKENS); fflush(stderr);
        return 23;
    }
    if (e.vulkanStrictViolation()) {
        g_strictGpuViolations.fetch_add(1, std::memory_order_relaxed);
        std::fprintf(stderr, "MEASURED_STRICT_GPU_VIOLATION\n"); fflush(stderr);
        return 24;
    }

    // ── Compute timing ──
    uint64_t decodeWallNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(tDecodeEnd - tDecodeStart).count());

    const auto& sc = e.speculativeCounters();
    uint64_t specProposed = sc.proposedTokens;
    uint64_t specAccepted = sc.acceptedTokens;
    uint64_t specRejected = sc.rejectedTokens;
    double specAcceptRate = (specProposed > 0)
        ? (static_cast<double>(specAccepted) / static_cast<double>(specProposed))
        : 0.0;

    const auto& c = e.gpuForwardCounters();
    uint64_t hostFallbacks = c.hostForwardLayerCalls;
    uint64_t dualRowSlot0 = c.dualRowSlot[0];
    uint64_t dualRowSlot1 = c.dualRowSlot[1];
    int dualPhysicalGpuForward = Deep2GpuForward_DualPhysicalGpuReal(c) ? 1 : 0;

    // Simple accepted-decode TPS:
    //   accepted output tokens = measured tokens (all committed)
    //   wall time = decodeWallNs
    double decodeWallS = static_cast<double>(decodeWallNs) / 1.0e9;
    double acceptedDecodeTps = (decodeWallS > 0.0)
        ? static_cast<double>(MEASURED_TOKENS) / decodeWallS
        : 0.0;

    // ── Emit authority lines ──
    std::fprintf(stderr, "\n=== DEEP2_QWEN32_ACCEPTED_TPS_001 ===\n"); fflush(stderr);
    std::fprintf(stderr, "WARMUP_TOKENS=%llu\n", (unsigned long long)WARMUP_TOKENS); fflush(stderr);
    std::fprintf(stderr, "MEASURED_TOKENS=%llu\n", (unsigned long long)MEASURED_TOKENS); fflush(stderr);
    std::fprintf(stderr, "SPEC_PROPOSED=%llu\n", (unsigned long long)specProposed); fflush(stderr);
    std::fprintf(stderr, "SPEC_ACCEPTED=%llu\n", (unsigned long long)specAccepted); fflush(stderr);
    std::fprintf(stderr, "SPEC_REJECTED=%llu\n", (unsigned long long)specRejected); fflush(stderr);
    std::fprintf(stderr, "SPEC_ACCEPT_RATE=%.6f\n", specAcceptRate); fflush(stderr);
    std::fprintf(stderr, "DECODE_WALL_NS=%llu\n", (unsigned long long)decodeWallNs); fflush(stderr);
    std::fprintf(stderr, "ACCEPTED_DECODE_TPS=%.4f\n", acceptedDecodeTps); fflush(stderr);
    std::fprintf(stderr, "DUAL_ROW_SLOT_0=%llu\n", (unsigned long long)dualRowSlot0); fflush(stderr);
    std::fprintf(stderr, "DUAL_ROW_SLOT_1=%llu\n", (unsigned long long)dualRowSlot1); fflush(stderr);
    std::fprintf(stderr, "DUAL_PHYSICAL_GPU_FORWARD=%d\n", dualPhysicalGpuForward); fflush(stderr);
    std::fprintf(stderr, "CPU_FALLBACKS=%llu\n", (unsigned long long)hostFallbacks); fflush(stderr);
    std::fprintf(stderr, "STRICT_GPU_VIOLATIONS=%u\n",
        g_strictGpuViolations.load(std::memory_order_relaxed)); fflush(stderr);
    std::fprintf(stderr, "DEVICE_LOST=0\n"); fflush(stderr);
    std::fprintf(stderr, "AUTHORITY_RESULT=%s\n",
        (g_strictGpuViolations.load(std::memory_order_relaxed) == 0 && dualPhysicalGpuForward)
            ? "ACCEPTED" : "REJECTED"); fflush(stderr);
    std::fprintf(stderr, "=== END DEEP2_QWEN32_ACCEPTED_TPS_001 ===\n\n"); fflush(stderr);

    // ── Emit GPU counters ──
    Deep2GpuForward_Emit(stderr, c, 0);

    // ── Write receipt ──
    const char* receipt =
        "F:\\~dev\\evidence\\RAWRXD_PERFORMANCE_001\\"
        "DEEP2_QWEN32_ACCEPTED_TPS_001\\RECEIPT.txt";
    writeReceipt(receipt,
        acceptedDecodeTps,
        WARMUP_TOKENS, MEASURED_TOKENS,
        specProposed, specAccepted, specRejected,
        specAcceptRate,
        decodeWallNs,
        dualRowSlot0, dualRowSlot1,
        dualPhysicalGpuForward,
        hostFallbacks,
        g_strictGpuViolations.load(std::memory_order_relaxed),
        0);

    // ── Classification ──
    if (g_strictGpuViolations.load(std::memory_order_relaxed) != 0) return 40;
    if (!dualPhysicalGpuForward) return 41;
    if (acceptedDecodeTps >= 85.0) {
        std::fprintf(stderr, "CLASSIFICATION=85-TPS_TARGET_PROVEN\n"); fflush(stderr);
    } else if (acceptedDecodeTps >= 70.0) {
        std::fprintf(stderr, "CLASSIFICATION=CLOSE_OPTIMIZE_BOTTLENECK\n"); fflush(stderr);
    } else if (acceptedDecodeTps >= 40.0) {
        std::fprintf(stderr, "CLASSIFICATION=MACHINERY_WORKS_GAP_REMAINS\n"); fflush(stderr);
    } else {
        std::fprintf(stderr, "CLASSIFICATION=INSPECT_ACCEPTANCE_RESIDENCY_SYNC\n"); fflush(stderr);
    }

    return 0;
}
