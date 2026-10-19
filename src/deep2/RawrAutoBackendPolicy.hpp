#pragma once

// ============================================================================
// RawrAutoBackendPolicy.hpp — Automatic model fit, backend selection, recovery
// Dependency-free C++20 selection layer. Uses measured memory estimates and
// verified device availability; does not implement GPU offloading or MoE
// streaming itself.
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace Deep2 {

// ============================================================================
// Backend enumeration
// ============================================================================
enum class Backend {
    CPU,
    VulkanPrimary,
    VulkanDual,
    MoEStreaming,
    Reject
};

// ============================================================================
// ModelFit — estimated residency requirements from GGUF metadata + weights
// ============================================================================
struct ModelFit {
    uint64_t weightsBytes = 0;           // Sum of all weight tensor sizeBytes
    uint64_t kvBytes = 0;                // Estimated KV cache bytes (context-dependent)
    uint64_t scratchBytes = 0;           // Activations, Q/K/V, FFN intermediates
    uint64_t expertWorkingSetBytes = 0;  // Active expert bytes for MoE streaming

    bool isMoE = false;
    bool supportsStreaming = false;
    bool supportsDualGpu = false;

    // Architecture discovery
    size_t hiddenDim = 0;
    size_t numLayers = 0;
    size_t numExperts = 0;
    size_t numExpertsPerToken = 0;
    size_t vocabSize = 0;
    size_t contextLen = 0;
    size_t headDim = 128;       // Derived from GGUF or default
    size_t numKVHeads = 8;      // Derived from GGUF or default

    bool hasFFNWeightsPerLayer() const noexcept {
        // True when every attention layer that needs FFN has wUp/wDown populated.
        // Callers should verify this separately per layer before skipping FFN.
        return true;
    }
};

// ============================================================================
// DeviceBudget — measured available resources
// ============================================================================
struct DeviceBudget {
    uint64_t availableRam = 0;           // Physical RAM available for weights
    uint64_t availableCommit = 0;        // Windows commit limit headroom
    uint64_t primaryVram = 0;            // R9700 VRAM
    uint64_t secondaryVram = 0;          // RX 7800 XT VRAM

    bool primaryReady = false;           // Windows PnP started + problem-free
    bool secondaryReady = false;
    bool primaryComputeValidated = false; // Known-answer dispatch passed
    bool secondaryComputeValidated = false;

    // Vulkan instance / device state
    bool vulkanInstanceCreated = false;
    uint32_t vulkanDeviceCount = 0;
};

// ============================================================================
// ExecutionPolicy — CLI flags and performance constraints
// ============================================================================
struct ExecutionPolicy {
    bool forceCPU = false;
    bool forceGPU = false;
    bool allowCPUFallback = true;
    bool allowStreaming = true;

    // 0 disables performance-based CPU rejection.
    double estimatedCpuTPS = 0.0;
    double minimumCpuTPS = 0.0;

    // Stall detection time budgets (milliseconds)
    double prefillTimeoutMs = 30000.0;   // 30 s default prefill budget
    double decodeTimeoutMs = 10000.0;    // 10 s default per-token decode budget
};

// ============================================================================
// BackendDecision — result of SelectBackend
// ============================================================================
struct BackendDecision {
    Backend backend = Backend::Reject;
    std::string reason;
};

// ============================================================================
// StageFailure — stall / timeout diagnostic record
// ============================================================================
struct StageFailure {
    bool prefillStarted = false;
    bool prefillCompleted = false;
    bool decodeStarted = false;
    size_t tokensCommitted = 0;
    std::string failureClass;   // e.g. "PREFILL_TIMEOUT", "DECODE_TIMEOUT", "NONFINITE_LOGITS"
    std::string autoRecovery;   // e.g. "GPU_REPLAN_CANDIDATE", "NONE"
    double elapsedPrefillMs = 0.0;
    double elapsedDecodeMs = 0.0;
};

// ============================================================================
// Helpers
// ============================================================================
inline uint64_t SaturatingAdd(uint64_t a, uint64_t b) noexcept {
    return b > (UINT64_MAX - a) ? UINT64_MAX : a + b;
}

// Estimate KV cache bytes: layers * 2 * context * headDim * numKVHeads * sizeof(float)
// (K and V each, Q4_K quantized would reduce this; use F32 upper bound for safety)
inline uint64_t EstimateKvBytes(const ModelFit& m) noexcept {
    if (m.contextLen == 0 || m.numLayers == 0 || m.headDim == 0 || m.numKVHeads == 0)
        return 0;
    // K + V per layer per token per head per headDim, 4 bytes F32
    const uint64_t perToken = static_cast<uint64_t>(m.headDim) *
                              static_cast<uint64_t>(m.numKVHeads) * 2u * 4u;
    return perToken * static_cast<uint64_t>(m.contextLen) *
           static_cast<uint64_t>(m.numLayers);
}

// Estimate scratch: hiddenDim * 4 buffers (input, Q/K/V concat, output, temp)
inline uint64_t EstimateScratchBytes(const ModelFit& m) noexcept {
    if (m.hiddenDim == 0 || m.numLayers == 0) return 0;
    const uint64_t perLayer =
        static_cast<uint64_t>(m.hiddenDim) * 4u * 4u; // 4 float buffers
    return perLayer * static_cast<uint64_t>(m.numLayers);
}

// ============================================================================
// SelectBackend — pure policy decision, no side effects
// ============================================================================
inline BackendDecision SelectBackend(
    const ModelFit& m,
    const DeviceBudget& d,
    const ExecutionPolicy& p)
{
    if (p.forceCPU && p.forceGPU) {
        return {Backend::Reject, "Conflicting CPU/GPU flags"};
    }

    const uint64_t hostNeed = SaturatingAdd(
        SaturatingAdd(m.weightsBytes, m.kvBytes), m.scratchBytes);

    const bool cpuFits =
        hostNeed <= d.availableRam &&
        hostNeed <= d.availableCommit;

    const bool cpuFastEnough =
        p.minimumCpuTPS <= 0.0 ||
        (p.estimatedCpuTPS > 0.0 &&
         p.estimatedCpuTPS >= p.minimumCpuTPS);

    // ---- Explicit CPU -------------------------------------------------------
    if (p.forceCPU) {
        if (!cpuFits) {
            return {Backend::Reject, "Insufficient CPU memory for forced CPU"};
        }
        return {Backend::CPU, "CPU explicitly requested"};
    }

    // ---- GPU primary --------------------------------------------------------
    const uint64_t gpuNeed = SaturatingAdd(
        m.weightsBytes,
        SaturatingAdd(m.kvBytes, m.scratchBytes));

    const bool primaryUsable =
        d.primaryReady && d.primaryComputeValidated && d.vulkanInstanceCreated;

    if (primaryUsable && gpuNeed <= d.primaryVram) {
        return {Backend::VulkanPrimary, "Primary GPU fits weights+KV+scratch"};
    }

    // ---- Dual GPU -----------------------------------------------------------
    // Requires verified cross-device placement; aggregate capacity alone is insufficient.
    if (primaryUsable && d.secondaryReady && d.secondaryComputeValidated &&
        m.supportsDualGpu &&
        gpuNeed <= SaturatingAdd(d.primaryVram, d.secondaryVram)) {
        return {Backend::VulkanDual, "Dual GPU candidate"};
    }

    // ---- MoE streaming ------------------------------------------------------
    if (m.isMoE && m.supportsStreaming && p.allowStreaming && primaryUsable &&
        m.expertWorkingSetBytes > 0 &&
        m.expertWorkingSetBytes <= d.primaryVram) {
        return {Backend::MoEStreaming, "MoE streaming candidate"};
    }

    // ---- Explicit GPU but no plan -------------------------------------------
    if (p.forceGPU) {
        return {Backend::Reject, "No eligible GPU execution plan"};
    }

    // ---- CPU fallback -------------------------------------------------------
    if (p.allowCPUFallback && cpuFits && cpuFastEnough) {
        return {Backend::CPU, "CPU fallback fits policy"};
    }

    // ---- Reject -------------------------------------------------------------
    if (cpuFits) {
        return {Backend::Reject, "CPU below performance policy"};
    }
    return {Backend::Reject, "Insufficient host memory"};
}

// ============================================================================
// BackendName — human-readable backend label
// ============================================================================
inline const char* BackendName(Backend b) noexcept {
    switch (b) {
        case Backend::CPU: return "CPU";
        case Backend::VulkanPrimary: return "VulkanPrimary";
        case Backend::VulkanDual: return "VulkanDual";
        case Backend::MoEStreaming: return "MoEStreaming";
        case Backend::Reject: return "Reject";
        default: return "Unknown";
    }
}

// ============================================================================
// AutoBackendController — orchestrates selection, stall detection, recovery
// ============================================================================
class AutoBackendController {
public:
    AutoBackendController() = default;

    // Inspect a GGUF model path and populate ModelFit from actual tensor data.
    // Returns false if the model cannot be inspected.
    bool InspectModel(const std::filesystem::path& modelPath,
                      ModelFit& fit) const;

    // Measure available system RAM and commit headroom (Windows).
    bool MeasureHostBudget(DeviceBudget& budget) const;

    // Run GPU preflight and compute validation; populate DeviceBudget GPU fields.
    bool MeasureGpuBudget(DeviceBudget& budget) const;

    // Select a backend using SelectBackend().
    BackendDecision Decide(const ModelFit& m,
                           const DeviceBudget& d,
                           const ExecutionPolicy& p) const {
        return SelectBackend(m, d, p);
    }

    // Record stage progress for stall detection.
    void MarkPrefillStart();
    void MarkPrefillComplete(double elapsedMs);
    void MarkDecodeStart();
    void MarkDecodeToken(double elapsedMs, size_t cumulativeTokens);
    StageFailure CheckStall(const ExecutionPolicy& p) const;

    // Determine whether recovery should attempt a different backend.
    bool ShouldRecover(const BackendDecision& decision,
                       const StageFailure& failure) const noexcept;

    // Reset stage state for a new generation attempt.
    void ResetStages() {
        stage_.prefillStarted = false;
        stage_.prefillCompleted = false;
        stage_.decodeStarted = false;
        stage_.tokensCommitted = 0;
        stage_.elapsedPrefillMs = 0.0;
        stage_.elapsedDecodeMs = 0.0;
        stage_.failureClass.clear();
        stage_.autoRecovery.clear();
    }

    const StageFailure& LastFailure() const noexcept { return stage_; }

private:
    StageFailure stage_;
    std::chrono::steady_clock::time_point prefillStart_;
    std::chrono::steady_clock::time_point decodeStart_;
};

} // namespace Deep2
