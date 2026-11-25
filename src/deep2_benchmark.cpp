// ============================================================================
// deep2_benchmark.cpp — production Deep2Engine benchmark (REAP/Deep2 matrix).
// Drives the REAL engine (Deep2::Deep2Engine): GGUF load, Vulkan device
// selection, warmup/prefill/decode timing, GPU dispatch + MoE counters,
// nonfinite/fail-closed exit codes, and machine-readable JSON. No simplified
// or substitute inference path is used.
//
// Usage:
//   deep2_benchmark <model.gguf> [--gpu <name-needle>] [--ctx N] [--gen N]
//                   [--prompt "..."] [--threads N] [--reps N] [--no-gpu]
// Exit: 0 ok, 2 bad args/model, 3 load/init fail, 4 inference fault/incomplete.
// ============================================================================
#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

// MoE timing counters owned by the engine (runtime_graph_executor.cpp).
extern "C" double Deep2Bench_MoeRouterMs(void);
extern "C" double Deep2Bench_MoeExpertMs(void);
extern "C" unsigned long Deep2Bench_MoeRouterCalls(void);
extern "C" unsigned long Deep2Bench_MoeExpertCalls(void);

using namespace Deep2;

static std::string JsonEscape(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\' || c == '"') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

int main(int argc, char** argv) {
    std::string model, gpu = "R9700", prompt = "The quick brown fox jumps over the lazy dog.";
    size_t ctx = 4096, gen = 128, threads = 0, reps = 1, cancelAfter = 0;
    bool useGpu = true;
    bool medusa = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* def) -> std::string { return (i + 1 < argc) ? argv[++i] : def; };
        if (a == "--gpu") gpu = next("R9700");
        else if (a == "--ctx") ctx = std::strtoul(next("4096").c_str(), nullptr, 10);
        else if (a == "--gen") gen = std::strtoul(next("128").c_str(), nullptr, 10);
        else if (a == "--threads") threads = std::strtoul(next("0").c_str(), nullptr, 10);
        else if (a == "--reps") reps = std::strtoul(next("1").c_str(), nullptr, 10);
        else if (a == "--prompt") prompt = next("");
        else if (a == "--no-gpu") useGpu = false;
        else if (a == "--medusa") medusa = true;  // speculative block verification
        else if (a == "--cancel-after") cancelAfter = std::strtoul(next("0").c_str(), nullptr, 10);
        else if (a == "--help") {
            std::printf("deep2_benchmark <model.gguf> [--gpu NAME] [--ctx N] [--gen N] [--prompt S] [--threads N] [--reps N] [--medusa] [--cancel-after N] [--no-gpu]\n");
            return 0;
        } else if (model.empty()) model = a;
    }
    if (model.empty()) { std::fprintf(stderr, "error: model path required\n"); return 2; }
    if (reps == 0) reps = 1;

    EngineConfig cfg;
    cfg.numThreads = threads;
    cfg.maxSeqLen = ctx;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", model.c_str());

    Deep2Engine engine;
    if (!engine.initialize(cfg)) { std::fprintf(stderr, "error: engine initialize failed\n"); return 3; }
    if (useGpu) { engine.setVulkanDeviceNeedle(gpu.c_str()); engine.enableVulkan(true); }
    if (!engine.loadModel(model)) { std::fprintf(stderr, "error: loadModel failed\n"); return 3; }
    if (medusa) engine.enableMedusa(true);  // speculative block verification (needs head weights)

    // Device identity captured from the engine itself (not vulkaninfo).
    const unsigned devCount = engine.vulkanDeviceCount();
    const bool vkInit = engine.isVulkanInitialized();
    const std::string devNeedle = engine.vulkanDeviceNeedle();

    std::vector<int> promptIds = engine.tokenize(prompt);
    if (promptIds.empty()) { std::fprintf(stderr, "error: empty prompt tokens\n"); return 2; }

    std::vector<int> out(static_cast<size_t>(gen) + 1, 0);
    double prefillTpsSum = 0, decodeTpsSum = 0, totalTpsSum = 0;
    size_t okReps = 0;
    bool fault = false;
    std::string stopReason;

    for (size_t r = 0; r < reps; ++r) {
        engine.reset();
        InferenceStats st;
        size_t tokCount = 0;
        auto onTok = [&](int) {
            if (cancelAfter && ++tokCount >= cancelAfter) engine.requestCancel();
            return true;
        };
        const size_t n = engine.generate(promptIds.data(), promptIds.size(),
                                         out.data(), out.size(), &st, onTok);
        const Deep2Engine::GenerationStopReason sr = engine.generationStopReason();
        stopReason = Deep2Engine::GenerationStopReasonName(sr);
        const bool ok = (n > 0) &&
            (sr == Deep2Engine::GenerationStopReason::COMPLETED || sr == Deep2Engine::GenerationStopReason::EOS ||
             sr == Deep2Engine::GenerationStopReason::BUDGET_EXHAUSTED ||
             (cancelAfter > 0 && sr == Deep2Engine::GenerationStopReason::CANCELLED));
        if (!ok) { fault = true; break; }
        prefillTpsSum += st.prefillTokensPerSecond;
        decodeTpsSum  += st.decodeTokensPerSecond;
        totalTpsSum   += st.tokensPerSecond;
        ++okReps;
    }

    const double inv = okReps ? (1.0 / static_cast<double>(okReps)) : 0.0;
    const double prefillTps = prefillTpsSum * inv;
    const double decodeTps  = decodeTpsSum * inv;
    const double totalTps   = totalTpsSum * inv;

    // GPU dispatch + MoE counters (from the engine / engine lib).
    const unsigned long long gemvOk   = engine.vulkanGemvSuccessCount();
    const unsigned long long gemvFail = engine.vulkanGemvFallbackCount();
    const unsigned long long unplanned= engine.vulkanUnplannedFallbacks();
    const unsigned long long cpuOps   = engine.plannedCpuGemvOps();
    const unsigned long long gpuOps   = engine.plannedGpuGemvOps();
    const double moeRouterMs = Deep2Bench_MoeRouterMs();
    const double moeExpertMs = Deep2Bench_MoeExpertMs();
    const unsigned long moeRouterCalls = Deep2Bench_MoeRouterCalls();
    const unsigned long moeExpertCalls = Deep2Bench_MoeExpertCalls();

    // Fail-closed: a fault, zero reps, or unplanned CPU fallback is INCOMPLETE.
    const bool incomplete = fault || okReps == 0 || unplanned > 0;

    std::printf(
        "{\"tool\":\"deep2_benchmark\",\"model\":\"%s\",\"gpu_requested\":\"%s\","
        "\"gpu_device_count\":%u,\"gpu_initialized\":%s,\"gpu_needle\":\"%s\","
        "\"ctx\":%zu,\"gen\":%zu,\"threads\":%zu,\"reps\":%zu,\"ok_reps\":%zu,"
        "\"prefill_tps\":%.3f,\"decode_tps\":%.3f,\"total_tps\":%.3f,"
        "\"gemv_ok\":%llu,\"gemv_fallback\":%llu,\"unplanned_fallback\":%llu,"
        "\"planned_cpu_ops\":%llu,\"planned_gpu_ops\":%llu,"
        "\"moe_router_ms\":%.3f,\"moe_router_calls\":%lu,\"moe_expert_ms\":%.3f,\"moe_expert_calls\":%lu,"
        "\"cancel_after\":%zu,\"cancelled\":%s,"
        "\"stop_reason\":\"%s\",\"result\":\"%s\"}\n",
        JsonEscape(model).c_str(), JsonEscape(gpu).c_str(), devCount, vkInit ? "true" : "false",
        JsonEscape(devNeedle).c_str(), ctx, gen, threads, reps, okReps,
        prefillTps, decodeTps, totalTps,
        gemvOk, gemvFail, unplanned, cpuOps, gpuOps,
        moeRouterMs, moeRouterCalls, moeExpertMs, moeExpertCalls,
        cancelAfter, (stopReason == "CANCELLED" ? "true" : "false"),
        stopReason.c_str(), incomplete ? "INCOMPLETE" : "PASS");

    return incomplete ? 4 : 0;
}