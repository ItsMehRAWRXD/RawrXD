// ============================================================================
// mla_forward_chain_cert.cpp
//   RAWRXD_GPU_DLWVECTOR_CONTRACT_AUDIT_001 — the last unobserved link.
//
// The transfer contract is already runtime-proven by
// tools/mla_upload_contract_cert.cpp. What is NOT yet observed is the chain
// above it, for a real MLA model:
//
//   computeAttention (Deep2Engine.cpp:3689)
//     -> computeMLAAttentionGpu
//       -> RunMLAAttentionHost
//     -> throw runtime_error on failure          (:3692)
//   forwardTokenGpuHybrid catches                (Deep2Engine_GpuMoEMLA.cpp:446)
//   forward router -> blockCommittedFallback    (Deep2Engine.cpp:4730)
//     -> ForwardResult{ok=false, "committed_fallback_blocked"}
//     -> vulkanStrictViolation_ = true           (:4718)
//
// This cert loads the model, prints whether admission classified it as MLA,
// runs ONE forward token with Vulkan enabled, and prints the ForwardResult
// verbatim. Every field is measured. The verdict is not asserted here: the
// interesting content is the observed value, and the receipt reads it.
//
// Usage: mla_forward_chain_cert <model.gguf> [threads]
// ============================================================================
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "deep2/Deep2Engine.h"

using Deep2::Deep2Engine;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: mla_forward_chain_cert <model.gguf> [threads]\n");
        return 2;
    }
    const std::string model = argv[1];
    const int threads = (argc > 2) ? std::atoi(argv[2]) : 0;

    Deep2Engine engine;
    engine.enableVulkan(true);
    // Strict native, so a committed GPU state cannot be silently downgraded to
    // the CPU. That is the mode the analysis describes; the receipt records
    // which mode produced the observation.
    engine.setVulkanStrictNoCpuFallback(true);

    std::printf("MODEL=%s\n", model.c_str());
    std::printf("VULKAN_REQUESTED=1\n");
    std::printf("STRICT_NO_CPU_FALLBACK=1\n");
    std::fflush(stdout);

    Deep2::EngineConfig config;
    config.numThreads = threads;
    if (!engine.initialize(config)) {
        std::printf("INIT_OK=0\nVERDICT=INCONCLUSIVE stage=initialize\n");
        return 3;
    }
    std::printf("INIT_OK=1\n");
    std::fflush(stdout);

    Deep2::ModelLoadDiag diag;
    if (!engine.loadModel(model, &diag)) {
        std::printf("LOAD_OK=0\n");
        std::printf("LOAD_STAGE=%s\n", !diag.stageName.empty() ? diag.stageName.c_str() : "(none)");
        std::printf("LOAD_MESSAGE=%s\n", !diag.message.empty() ? diag.message.c_str() : "(none)");
        std::printf("VERDICT=INCONCLUSIVE stage=load_model\n");
        return 4;
    }
    std::printf("LOAD_OK=1\n");
    std::printf("LOAD_STAGE=%s\n", !diag.stageName.empty() ? diag.stageName.c_str() : "(none)");
    std::fflush(stdout);

    // One token of shape [1, hidden].
    const size_t H = engine.hiddenDim();
    std::printf("HIDDEN_DIM=%zu\n", H);
    if (H == 0) {
        std::printf("VERDICT=INCONCLUSIVE stage=no_hidden_dim\n");
        return 5;
    }

    std::vector<float> hidden(H, 0.0f);
    const Deep2Engine::ForwardResult r = engine.forwardTokenAllLayers(hidden.data(), 1);
    std::printf("FORWARD_OK=%d\n", r.ok ? 1 : 0);
    std::printf("FORWARD_ROUTE=%d\n", static_cast<int>(r.actualRoute));
    std::printf("FORWARD_GPU_COMMITTED=%d\n", r.gpuCommitted ? 1 : 0);
    std::printf("FORWARD_FAILURE_STAGE=%s\n",
                r.failureStage ? r.failureStage : "(none)");

    // The specific signature the static analysis predicted. The engine prints it
    // itself; these greps only summarise what this cert observed.
    std::printf("EXPECTED_ABORT_SIGNATURE=COMMITTED_FALLBACK_BLOCKED=1 "
                "STRICT_NATIVE_ABORT=1 VERDICT=FAIL stage=moe_hybrid\n");
    std::printf("EXPECTED_THROW_TEXT=attention: GPU MLA path failed or unsupported\n");
    std::fflush(stdout);
    return r.ok ? 0 : 6;
}
