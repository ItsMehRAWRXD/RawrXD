// ============================================================================
// RawrAutoBackendPolicy.cpp — Automatic model fit, backend selection, recovery
// Dependency-free C++20 implementation for Windows.
// ============================================================================

#include "RawrAutoBackendPolicy.hpp"
#include "../deep2/GGUFLoader.hpp"
#include "../deep2/GpuPreflight.hpp"

#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {

// ============================================================================
// InspectModel — read GGUF metadata and estimate residency requirements
// ============================================================================
bool AutoBackendController::InspectModel(
    const std::filesystem::path& modelPath,
    ModelFit& fit) const
{
    GGUFLoadOptions options{};
    options.mmap = false;        // Inspection only — don't map tensors
    options.loadTensors = false; // Metadata only
    options.verbose = false;

    GGUFLoadResult result = GGUFLoader::Load(modelPath.string().c_str(), options);
    if (!result.success) {
        fprintf(stderr,
            "[AUTO_BACKEND] GGUF inspect failed: %s\n", result.error);
        return false;
    }

    // --- Weight bytes from actual tensor descriptors ---
    uint64_t totalWeights = 0;
    for (const auto& t : result.tensors) {
        totalWeights = SaturatingAdd(totalWeights, t.size);
    }
    fit.weightsBytes = totalWeights;

    // --- Architecture metadata ---
    fit.hiddenDim = result.metadata.hiddenSize;
    fit.numLayers = result.metadata.numLayers;
    fit.numExperts = result.metadata.numExperts;
    fit.numExpertsPerToken = result.metadata.numExpertsPerToken;
    fit.vocabSize = result.metadata.vocabSize;

    // Context length: use a realistic default for generation (2048 tokens),
    // not the GGUF's maximum supported context. KV cache grows dynamically.
    fit.contextLen = 2048;

    // Head dim / KV heads for KV cache estimation
    size_t headDim = 128;   // Nemotron default
    size_t numKVHeads = result.metadata.numKeyValueHeads;
    if (numKVHeads == 0) numKVHeads = 8;

    // --- KV cache estimate ---
    fit.kvBytes = EstimateKvBytes(ModelFit{
        .hiddenDim = fit.hiddenDim,
        .numLayers = fit.numLayers,
        .contextLen = fit.contextLen,
        .headDim = headDim,
        .numKVHeads = numKVHeads,
    });

    // --- Scratch estimate ---
    fit.scratchBytes = EstimateScratchBytes(ModelFit{
        .hiddenDim = fit.hiddenDim,
        .numLayers = fit.numLayers,
    });

    // --- MoE detection ---
    fit.isMoE = result.metadata.numExperts > 0;
    fit.supportsStreaming = fit.isMoE &&
        (result.metadata.numExperts > 0);
    fit.supportsDualGpu = true;  // MARS controller supports dual-GPU placement

    // Expert working set: active experts * per-expert weight size
    if (fit.isMoE && fit.numExperts > 0 && fit.numExpertsPerToken > 0) {
        size_t expertIntermediate = result.metadata.moeIntermediateSize;
        if (expertIntermediate == 0) expertIntermediate = fit.hiddenDim * 4;
        uint64_t perExpert =
            static_cast<uint64_t>(expertIntermediate) *
            static_cast<uint64_t>(fit.hiddenDim) * 3u * 4u;
        fit.expertWorkingSetBytes =
            perExpert * static_cast<uint64_t>(fit.numExpertsPerToken);
    }

    fprintf(stderr,
        "[AUTO_BACKEND] model=%s weights=%lluMB kv=%lluMB scratch=%lluMB "
        "moe=%d experts=%zu ctx=%zu\n",
        modelPath.string().c_str(),
        (unsigned long long)(fit.weightsBytes / (1024ull * 1024ull)),
        (unsigned long long)(fit.kvBytes / (1024ull * 1024ull)),
        (unsigned long long)(fit.scratchBytes / (1024ull * 1024ull)),
        fit.isMoE ? 1 : 0, fit.numExperts, fit.contextLen);
    fflush(stderr);

    return true;
}

// ============================================================================
// MeasureHostBudget — physical RAM and commit headroom (Windows)
// ============================================================================
bool AutoBackendController::MeasureHostBudget(DeviceBudget& budget) const
{
    // Physical memory
    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        budget.availableRam = memStatus.ullAvailPhys;
        budget.availableCommit = memStatus.ullAvailPageFile;
    }

    fprintf(stderr,
        "[AUTO_BACKEND] host RAM=%lluMB commit=%lluMB\n",
        (unsigned long long)(budget.availableRam / (1024ull * 1024ull)),
        (unsigned long long)(budget.availableCommit / (1024ull * 1024ull)));
    fflush(stderr);

    return true;
}

// ============================================================================
// MeasureGpuBudget — GPU preflight + compute validation
// ============================================================================
bool AutoBackendController::MeasureGpuBudget(DeviceBudget& budget) const
{
    // Windows PnP health
    auto gpus = EnumerateGpuHealth();
    for (const auto& g : gpus) {
        fprintf(stderr,
            "[AUTO_BACKEND] GPU %ls status=%lu problem=%lu healthy=%d\n",
            g.friendlyName.c_str(), g.status, g.problem,
            g.healthy ? 1 : 0);
    }
    fflush(stderr);

    // Identify primary (R9700) and secondary (RX 7800 XT) by friendly name
    for (const auto& g : gpus) {
        std::wstring name = g.friendlyName;
        bool isR9700 = name.find(L"R9700") != std::wstring::npos ||
                       name.find(L"Radeon AI PRO R9700") != std::wstring::npos;
        bool is7800XT = name.find(L"RX 7800 XT") != std::wstring::npos ||
                        name.find(L"Radeon RX 7800 XT") != std::wstring::npos;

        if (g.healthy) {
            if (isR9700 && !budget.primaryReady) {
                budget.primaryReady = true;
                budget.primaryVram = 32ull * 1024ull * 1024ull * 1024ull; // 32 GB
            } else if (is7800XT && !budget.secondaryReady) {
                budget.secondaryReady = true;
                budget.secondaryVram = 16ull * 1024ull * 1024ull * 1024ull; // 16 GB
            }
        }
    }

    // Vulkan ICD readiness
    budget.vulkanInstanceCreated = VulkanIcdReady();
    if (budget.vulkanInstanceCreated) {
        fprintf(stderr, "[AUTO_BACKEND] Vulkan ICD ready\n");
    } else {
        fprintf(stderr, "[AUTO_BACKEND] Vulkan ICD not ready\n");
    }
    fflush(stderr);

    return true;
}

// ============================================================================
// Stage progress markers for stall detection
// ============================================================================
void AutoBackendController::MarkPrefillStart() {
    stage_.prefillStarted = true;
    stage_.prefillCompleted = false;
    prefillStart_ = std::chrono::steady_clock::now();
}

void AutoBackendController::MarkPrefillComplete(double elapsedMs) {
    stage_.prefillCompleted = true;
    stage_.elapsedPrefillMs = elapsedMs;
}

void AutoBackendController::MarkDecodeStart() {
    stage_.decodeStarted = true;
    decodeStart_ = std::chrono::steady_clock::now();
}

void AutoBackendController::MarkDecodeToken(double /*elapsedMs*/,
                                            size_t cumulativeTokens) {
    stage_.tokensCommitted = cumulativeTokens;
}

// ============================================================================
// CheckStall — determine if prefill or decode has exceeded its time budget
// ============================================================================
StageFailure AutoBackendController::CheckStall(
    const ExecutionPolicy& p) const
{
    StageFailure f = stage_;

    auto now = std::chrono::steady_clock::now();

    if (stage_.prefillStarted && !stage_.prefillCompleted) {
        double elapsed = std::chrono::duration<double,
            std::milli>(now - prefillStart_).count();
        if (elapsed > p.prefillTimeoutMs) {
            f.failureClass = "PREFILL_TIMEOUT";
            f.autoRecovery = "GPU_REPLAN_CANDIDATE";
            f.elapsedPrefillMs = elapsed;
        }
    }

    if (stage_.decodeStarted) {
        double elapsed = std::chrono::duration<double,
            std::milli>(now - decodeStart_).count();
        if (elapsed > p.decodeTimeoutMs && stage_.tokensCommitted == 0) {
            f.failureClass = "DECODE_TIMEOUT_FIRST_TOKEN";
            f.autoRecovery = "GPU_REPLAN_CANDIDATE";
            f.elapsedDecodeMs = elapsed;
        }
    }

    return f;
}

// ============================================================================
// ShouldRecover — decide whether to retry on a different backend
// ============================================================================
bool AutoBackendController::ShouldRecover(
    const BackendDecision& decision,
    const StageFailure& failure) const noexcept
{
    // Never recover from a Reject decision — no backend was feasible.
    if (decision.backend == Backend::Reject) return false;

    // Recover only on explicit timeout classes, not on non-finite logits etc.
    if (failure.failureClass == "PREFILL_TIMEOUT" ||
        failure.failureClass == "DECODE_TIMEOUT_FIRST_TOKEN") {
        return failure.autoRecovery == "GPU_REPLAN_CANDIDATE";
    }

    // Non-finite logits, zero tokens, or other numerical defects do not
    // automatically imply a backend problem — they may be model defects.
    return false;
}

} // namespace Deep2
