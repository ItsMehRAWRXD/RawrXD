// t_profile.cpp — decode bottleneck profiler (DEEP2_GPU_DECODE_ROOFLINE_001)
// Measures where decode wall time actually goes per token: kernel exec,
// host materialization, dual-row split, LM-head, and the speculation
// proposal/verify overhead so the LARGEST measured bottleneck is optimized.
#include "deep2/Deep2Engine.h"
#include "deep2/Deep2GpuForward.hpp"
#include "deep2/deep2_sha256.hpp"
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>
#include <chrono>
#include <algorithm>
#include <windows.h>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::InferenceStats;

static inline double nowMs() {
    LARGE_INTEGER f{}, c{};
    QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return static_cast<double>(c.QuadPart) * 1000.0 / static_cast<double>(f.QuadPart);
}

int main(int argc, char** argv) {
    const char* model = argc > 1 ? argv[1] : "F:\\rawrxd\\model_solo\\tinyllama_fresh.gguf";
    const int nTokens = argc > 2 ? atoi(argv[2]) : 48;
    const int reps = argc > 3 ? atoi(argv[3]) : 3;

    std::array<uint8_t,32> h{}; uint64_t mb=0;
    const bool okSha = deep2::sha256_file(model, h, &mb);
    char hex[65]={0};
    if (okSha) for(int i=0;i<32;++i) std::snprintf(hex+i*2,3,"%02x",h[i]);

    Deep2Engine e;
    EngineConfig cfg{}; cfg.maxSeqLen=4096; cfg.numThreads=0;
    if (!e.initialize(cfg)) { fprintf(stderr,"INIT FAIL\n"); return 1; }
    if (!e.loadModel(model)) { fprintf(stderr,"LOAD FAIL\n"); return 1; }
    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);

    // Greedy config; serial mode for the pure decode profile.
    Deep2::GenerationOptions o{}; o.temperature=0.0f; o.topK=1; o.seed=1;
    e.configureGeneration(o);

    const std::string prompt =
        "Write a C++ function that reverses a singly linked list. "
        "Include memory ordering notes and a unit test. ";
    auto ptoks = e.tokenize(prompt);

    std::vector<double> tps;
    for (int r = 0; r < reps; ++r) {
        e.reset(); e.clearCancel(); e.resetGpuForwardCounters();
        std::vector<int> out(nTokens);
        InferenceStats s{};
        const double t0 = nowMs();
        const size_t got = e.generate(ptoks.data(), ptoks.size(), out.data(), out.size(), &s, nullptr);
        const double t1 = nowMs();
        if (got == 0) { fprintf(stderr,"run %d generated 0\n", r); return 2; }
        tps.push_back((double)got / ((t1 - t0) * 0.001));
    }
    std::sort(tps.begin(), tps.end());
    const double medTps = tps[tps.size()/2];

    const auto& gf = e.gpuForwardCounters();

    fprintf(stderr, "\n---- PROFILE ----\n");
    fprintf(stderr, "MODEL=%s\nMODEL_SHA256=%s\n", model, hex);
    fprintf(stderr, "TOKENS=%d REPS=%d\n", nTokens, reps);
    fprintf(stderr, "MEDIAN_DECODE_TPS=%.4f\n", medTps);
    for (size_t i=0;i<tps.size();++i)
        fprintf(stderr, "TPS_RUN_%zu=%.4f\n", i, tps[i]);

    // Per-op counters → derived per-token op counts and ns/op
    const uint64_t fwd = gf.forwardLayers;
    fprintf(stderr, "FORWARD_LAYERS=%llu\n",(unsigned long long)fwd);
    fprintf(stderr, "RMS_NORM_OPS=%llu\n",(unsigned long long)gf.rmsNormOps);
    fprintf(stderr, "QKV_OPS=%llu\n",(unsigned long long)gf.qkvOps);
    fprintf(stderr, "ROPE_OPS=%llu\n",(unsigned long long)gf.ropeOps);
    fprintf(stderr, "ATTN_SCORE_OPS=%llu\n",(unsigned long long)gf.attnScoreOps);
    fprintf(stderr, "SOFTMAX_OPS=%llu\n",(unsigned long long)gf.softmaxOps);
    fprintf(stderr, "ATTN_VALUE_OPS=%llu\n",(unsigned long long)gf.attnValueOps);
    fprintf(stderr, "O_PROJ_OPS=%llu\n",(unsigned long long)gf.oProjOps);
    fprintf(stderr, "RESIDUAL_OPS=%llu\n",(unsigned long long)gf.residualOps);
    fprintf(stderr, "FFN_NORM_OPS=%llu\n",(unsigned long long)gf.ffnNormOps);
    fprintf(stderr, "FFN_ACT_OPS=%llu\n",(unsigned long long)gf.ffnActOps);
    fprintf(stderr, "FFN_RESIDUAL_OPS=%llu\n",(unsigned long long)gf.ffnResidualOps);
    fprintf(stderr, "HOST_SYNC_BOUNDARIES=%llu\n",(unsigned long long)gf.hostSyncBoundaries);
    fprintf(stderr, "HOST_MATERIALIZATIONS=%llu\n",(unsigned long long)gf.hostMaterializations);
    fprintf(stderr, "LAYER_SUBMITS=%llu\n",(unsigned long long)gf.layerSubmits);
    fprintf(stderr, "OP_SUBMITS=%llu\n",(unsigned long long)gf.opSubmits);
    fprintf(stderr, "Q4K_PACKED_OPS=%llu\n",(unsigned long long)gf.q4kPackedOps);
    fprintf(stderr, "Q6K_PACKED_OPS=%llu\n",(unsigned long long)gf.q6kPackedOps);
    fprintf(stderr, "Q2K_PACKED_OPS=%llu\n",(unsigned long long)gf.q2kPackedOps);
    fprintf(stderr, "CPU_F32_EXPANDS=%llu\n",(unsigned long long)gf.cpuF32Expands);

    // GPU telemetry per slot
    for (unsigned s = 0; s < e.vulkanDeviceCount() && s < 2; ++s) {
        fprintf(stderr, "SLOT%u_GEMV_SUCCESS=%llu\n",s,(unsigned long long)e.vulkanSlotGemvSuccess(s));
        fprintf(stderr, "SLOT%u_WEIGHT_UPLOADS=%llu\n",s,(unsigned long long)e.vulkanSlotWeightUploads(s));
        fprintf(stderr, "SLOT%u_WEIGHT_HITS=%llu\n",s,(unsigned long long)e.vulkanSlotWeightHits(s));
    }
    fprintf(stderr, "UNPLANNED_FALLBACKS=%llu\n",(unsigned long long)e.vulkanUnplannedFallbacks());
    fprintf(stderr, "PLANNED_GPU_GEMV=%llu\n",(unsigned long long)e.plannedGpuGemvOps());
    fprintf(stderr, "PLANNED_CPU_GEMV=%llu\n",(unsigned long long)e.plannedCpuGemvOps());
    fprintf(stderr, "STRICT_VIOLATION=%u\n",(unsigned)e.vulkanStrictViolation());
    fprintf(stderr, "GPU_DEVICES=%u\n", e.vulkanDeviceCount());

    // Largest op family by count (proxy for where the wall time sits)
    struct KOp { const char* n; uint64_t v; };
    const KOp ops[] = {
        {"RMS_NORM",gf.rmsNormOps},{"QKV",gf.qkvOps},{"ROPE",gf.ropeOps},
        {"ATTN_SCORE",gf.attnScoreOps},{"SOFTMAX",gf.softmaxOps},
        {"ATTN_VALUE",gf.attnValueOps},{"O_PROJ",gf.oProjOps},
        {"RESIDUAL",gf.residualOps},{"FFN_NORM",gf.ffnNormOps},
        {"FFN_ACT",gf.ffnActOps},{"FFN_RESIDUAL",gf.ffnResidualOps},
    };
    uint64_t bestOpV = 0; const char* bestOpN = "NONE";
    for (size_t i = 0; i < sizeof(ops)/sizeof(ops[0]); ++i) {
        if (ops[i].v > bestOpV) { bestOpV = ops[i].v; bestOpN = ops[i].n; }
    }
    fprintf(stderr, "LARGEST_OP_FAMILY=%s\n", bestOpN);
    fprintf(stderr, "LARGEST_OP_FAMILY_COUNT=%llu\n",(unsigned long long)bestOpV);

    fprintf(stderr, "---- END PROFILE ----\n");
    return 0;
}