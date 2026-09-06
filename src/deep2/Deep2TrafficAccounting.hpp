#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <atomic>
#include <cstdint>
#include <iostream>

namespace rawrxd::deep2 {

static_assert(
    std::atomic<uint64_t>::is_always_lock_free,
    "Traffic counters must remain lock-free on the certification target."
);

struct SovereignTrafficLimits
{
    // Populate from the certified machine rather than baking marketing
    // numbers into the accounting layer.
    double hostSustainableGBps = 0.0;
    double pcieH2DSustainableGBps = 0.0;
    double pcieD2DSustainableGBps = 0.0;
    double nvmeSustainableGBps = 0.0;
};

struct SovereignTrafficSnapshot
{
    // -----------------------------------------------------------------
    // Static model facts
    // -----------------------------------------------------------------
    uint64_t modelTotalParams = 0;
    uint64_t modelPackedBytes = 0;
    double   effectiveBitsPerParam = 0.0;
    uint32_t configuredExpertsPerLayer = 0;

    // -----------------------------------------------------------------
    // Run
    // -----------------------------------------------------------------
    uint64_t tokensGenerated = 0;
    double   evalSeconds = 0.0;
    double   evalTPS = 0.0;

    // -----------------------------------------------------------------
    // Expert topology / residency
    // -----------------------------------------------------------------
    uint64_t expertSelections = 0;
    uint64_t activeParamsAccumulated = 0;
    double   activeParamsPerToken = 0.0;

    uint64_t vramCacheHits = 0;
    uint64_t vramCacheMisses = 0;
    double   vramCacheHitRatio = 0.0;

    // -----------------------------------------------------------------
    // Logical consumption.
    //
    // These numbers come from the actual selected expert/layer sizes.
    // They are NOT claimed to be physical memory-controller traffic.
    // -----------------------------------------------------------------
    uint64_t gpuLogicalWeightBytes = 0;
    uint64_t hostLogicalWeightBytes = 0;

    // -----------------------------------------------------------------
    // Software-observed COMPLETED transfers.
    //
    // Increment only after the operation actually completes.
    // -----------------------------------------------------------------
    uint64_t nvmeCompletedBytes = 0;
    uint64_t h2dCompletedBytes = 0;
    uint64_t d2dCompletedBytes = 0;

    // -----------------------------------------------------------------
    // Optional physical counters.
    //
    // Populate these only from real driver/hardware telemetry.
    // Zero means "not observed", not "zero traffic."
    // -----------------------------------------------------------------
    uint64_t physicalPcieRxBytes = 0;
    uint64_t physicalPcieTxBytes = 0;
    uint64_t physicalVramReadBytes = 0;

    bool physicalPcieTelemetryValid = false;
    bool physicalVramTelemetryValid = false;

    uint64_t ringStarvationEvents = 0;

    // -----------------------------------------------------------------
    // Per-token derived
    // -----------------------------------------------------------------
    double gpuLogicalGBPerToken = 0.0;
    double hostLogicalGBPerToken = 0.0;
    double nvmeGBPerToken = 0.0;
    double h2dGBPerToken = 0.0;
    double d2dGBPerToken = 0.0;

    // -----------------------------------------------------------------
    // Required sustained rates
    // -----------------------------------------------------------------
    double gpuLogicalRequiredGBps = 0.0;
    double hostLogicalRequiredGBps = 0.0;
    double nvmeRequiredGBps = 0.0;
    double h2dRequiredGBps = 0.0;
    double d2dRequiredGBps = 0.0;

    // Physical, when available.
    double physicalPcieRxGBps = 0.0;
    double physicalPcieTxGBps = 0.0;
    double physicalVramReadGBps = 0.0;
};


class SovereignTrafficAccounting final
{
public:
    SovereignTrafficAccounting() noexcept
    {
        LARGE_INTEGER f{};
        ::QueryPerformanceFrequency(&f);
        qpcFrequency_ = static_cast<uint64_t>(f.QuadPart);
    }

    // -------------------------------------------------------------
    // Load-time static facts. Call before BeginEvaluation().
    // -------------------------------------------------------------
    void SetModelFacts(
        uint64_t totalParams,
        uint64_t packedBytes,
        uint32_t expertsPerLayer) noexcept
    {
        modelTotalParams_ = totalParams;
        modelPackedBytes_ = packedBytes;
        configuredExpertsPerLayer_ = expertsPerLayer;

        effectiveBitsPerParam_ =
            totalParams != 0
                ? (static_cast<double>(packedBytes) * 8.0) /
                      static_cast<double>(totalParams)
                : 0.0;
    }

    // -------------------------------------------------------------
    // Run lifecycle
    // -------------------------------------------------------------
    void BeginEvaluation() noexcept
    {
        ResetRunCounters();

        LARGE_INTEGER q{};
        ::QueryPerformanceCounter(&q);

        evalStartQpc_ = static_cast<uint64_t>(q.QuadPart);
        evalEndQpc_ = 0;
    }

    void EndEvaluation() noexcept
    {
        LARGE_INTEGER q{};
        ::QueryPerformanceCounter(&q);

        evalEndQpc_ = static_cast<uint64_t>(q.QuadPart);
    }

    // -------------------------------------------------------------
    // Token / expert routing
    // -------------------------------------------------------------
    void RecordTokenComplete() noexcept
    {
        tokensGenerated_.fetch_add(1, std::memory_order_relaxed);
    }

    void RecordExpertSelection(
        uint64_t activeParameterCount,
        uint64_t packedExpertBytes,
        bool alreadyGpuResident) noexcept
    {
        expertSelections_.fetch_add(1, std::memory_order_relaxed);

        activeParamsAccumulated_.fetch_add(
            activeParameterCount,
            std::memory_order_relaxed);

        if (alreadyGpuResident)
        {
            vramCacheHits_.fetch_add(1, std::memory_order_relaxed);

            // Logical weight demand serviced by resident GPU storage.
            gpuLogicalWeightBytes_.fetch_add(
                packedExpertBytes,
                std::memory_order_relaxed);
        }
        else
        {
            vramCacheMisses_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // If CPU/AVX execution consumes a packed weight region directly
    // from host memory, account for that separately.
    void RecordHostWeightConsumption(uint64_t bytes) noexcept
    {
        hostLogicalWeightBytes_.fetch_add(
            bytes,
            std::memory_order_relaxed);
    }

    // -------------------------------------------------------------
    // Completed I/O.
    //
    // These must be called from COMPLETION paths, not submission paths.
    // -------------------------------------------------------------
    void RecordNvmeReadCompletion(uint64_t actualBytes) noexcept
    {
        nvmeCompletedBytes_.fetch_add(
            actualBytes,
            std::memory_order_relaxed);
    }

    void RecordH2DCompletion(uint64_t actualBytes) noexcept
    {
        h2dCompletedBytes_.fetch_add(
            actualBytes,
            std::memory_order_relaxed);
    }

    void RecordD2DCompletion(uint64_t actualBytes) noexcept
    {
        d2dCompletedBytes_.fetch_add(
            actualBytes,
            std::memory_order_relaxed);
    }

    void RecordRingStarvation() noexcept
    {
        ringStarvationEvents_.fetch_add(
            1,
            std::memory_order_relaxed);
    }

    // -------------------------------------------------------------
    // Optional driver/hardware telemetry.
    //
    // Feed these from your existing IOCTL/device-counter path.
    // They must represent deltas for THIS evaluation interval.
    // -------------------------------------------------------------
    void RecordPhysicalPcieDelta(
        uint64_t rxBytes,
        uint64_t txBytes) noexcept
    {
        physicalPcieRxBytes_.store(rxBytes, std::memory_order_relaxed);
        physicalPcieTxBytes_.store(txBytes, std::memory_order_relaxed);

        physicalPcieTelemetryValid_.store(
            true,
            std::memory_order_release);
    }

    void RecordPhysicalVramReadDelta(uint64_t bytes) noexcept
    {
        physicalVramReadBytes_.store(
            bytes,
            std::memory_order_relaxed);

        physicalVramTelemetryValid_.store(
            true,
            std::memory_order_release);
    }

    [[nodiscard]]
    SovereignTrafficSnapshot Snapshot() const noexcept
    {
        SovereignTrafficSnapshot s{};

        s.modelTotalParams = modelTotalParams_;
        s.modelPackedBytes = modelPackedBytes_;
        s.effectiveBitsPerParam = effectiveBitsPerParam_;
        s.configuredExpertsPerLayer = configuredExpertsPerLayer_;

        s.tokensGenerated =
            tokensGenerated_.load(std::memory_order_relaxed);

        s.expertSelections =
            expertSelections_.load(std::memory_order_relaxed);

        s.activeParamsAccumulated =
            activeParamsAccumulated_.load(std::memory_order_relaxed);

        s.vramCacheHits =
            vramCacheHits_.load(std::memory_order_relaxed);

        s.vramCacheMisses =
            vramCacheMisses_.load(std::memory_order_relaxed);

        s.gpuLogicalWeightBytes =
            gpuLogicalWeightBytes_.load(std::memory_order_relaxed);

        s.hostLogicalWeightBytes =
            hostLogicalWeightBytes_.load(std::memory_order_relaxed);

        s.nvmeCompletedBytes =
            nvmeCompletedBytes_.load(std::memory_order_relaxed);

        s.h2dCompletedBytes =
            h2dCompletedBytes_.load(std::memory_order_relaxed);

        s.d2dCompletedBytes =
            d2dCompletedBytes_.load(std::memory_order_relaxed);

        s.ringStarvationEvents =
            ringStarvationEvents_.load(std::memory_order_relaxed);

        s.physicalPcieRxBytes =
            physicalPcieRxBytes_.load(std::memory_order_relaxed);

        s.physicalPcieTxBytes =
            physicalPcieTxBytes_.load(std::memory_order_relaxed);

        s.physicalVramReadBytes =
            physicalVramReadBytes_.load(std::memory_order_relaxed);

        s.physicalPcieTelemetryValid =
            physicalPcieTelemetryValid_.load(std::memory_order_acquire);

        s.physicalVramTelemetryValid =
            physicalVramTelemetryValid_.load(std::memory_order_acquire);

        if (evalEndQpc_ > evalStartQpc_ && qpcFrequency_ != 0)
        {
            s.evalSeconds =
                static_cast<double>(evalEndQpc_ - evalStartQpc_) /
                static_cast<double>(qpcFrequency_);
        }

        if (s.evalSeconds > 0.0)
        {
            s.evalTPS =
                static_cast<double>(s.tokensGenerated) /
                s.evalSeconds;
        }

        const double tokens =
            static_cast<double>(s.tokensGenerated);

        constexpr double kGB = 1000000000.0;

        if (tokens > 0.0)
        {
            s.activeParamsPerToken =
                static_cast<double>(s.activeParamsAccumulated) /
                tokens;

            s.gpuLogicalGBPerToken =
                static_cast<double>(s.gpuLogicalWeightBytes) /
                tokens / kGB;

            s.hostLogicalGBPerToken =
                static_cast<double>(s.hostLogicalWeightBytes) /
                tokens / kGB;

            s.nvmeGBPerToken =
                static_cast<double>(s.nvmeCompletedBytes) /
                tokens / kGB;

            s.h2dGBPerToken =
                static_cast<double>(s.h2dCompletedBytes) /
                tokens / kGB;

            s.d2dGBPerToken =
                static_cast<double>(s.d2dCompletedBytes) /
                tokens / kGB;

            const uint64_t cacheTotal =
                s.vramCacheHits + s.vramCacheMisses;

            if (cacheTotal != 0)
            {
                s.vramCacheHitRatio =
                    static_cast<double>(s.vramCacheHits) /
                    static_cast<double>(cacheTotal);
            }
        }

        s.gpuLogicalRequiredGBps =
            s.gpuLogicalGBPerToken * s.evalTPS;

        s.hostLogicalRequiredGBps =
            s.hostLogicalGBPerToken * s.evalTPS;

        s.nvmeRequiredGBps =
            s.nvmeGBPerToken * s.evalTPS;

        s.h2dRequiredGBps =
            s.h2dGBPerToken * s.evalTPS;

        s.d2dRequiredGBps =
            s.d2dGBPerToken * s.evalTPS;

        if (s.evalSeconds > 0.0 &&
            s.physicalPcieTelemetryValid)
        {
            s.physicalPcieRxGBps =
                static_cast<double>(s.physicalPcieRxBytes) /
                s.evalSeconds / kGB;

            s.physicalPcieTxGBps =
                static_cast<double>(s.physicalPcieTxBytes) /
                s.evalSeconds / kGB;
        }

        if (s.evalSeconds > 0.0 &&
            s.physicalVramTelemetryValid)
        {
            s.physicalVramReadGBps =
                static_cast<double>(s.physicalVramReadBytes) /
                s.evalSeconds / kGB;
        }

        return s;
    }

private:
    void ResetRunCounters() noexcept
    {
        tokensGenerated_.store(0, std::memory_order_relaxed);

        expertSelections_.store(0, std::memory_order_relaxed);
        activeParamsAccumulated_.store(0, std::memory_order_relaxed);

        vramCacheHits_.store(0, std::memory_order_relaxed);
        vramCacheMisses_.store(0, std::memory_order_relaxed);

        gpuLogicalWeightBytes_.store(0, std::memory_order_relaxed);
        hostLogicalWeightBytes_.store(0, std::memory_order_relaxed);

        nvmeCompletedBytes_.store(0, std::memory_order_relaxed);
        h2dCompletedBytes_.store(0, std::memory_order_relaxed);
        d2dCompletedBytes_.store(0, std::memory_order_relaxed);

        ringStarvationEvents_.store(0, std::memory_order_relaxed);

        physicalPcieRxBytes_.store(0, std::memory_order_relaxed);
        physicalPcieTxBytes_.store(0, std::memory_order_relaxed);
        physicalVramReadBytes_.store(0, std::memory_order_relaxed);

        physicalPcieTelemetryValid_.store(
            false,
            std::memory_order_relaxed);

        physicalVramTelemetryValid_.store(
            false,
            std::memory_order_relaxed);
    }

private:
    // Static facts; immutable while a generation run is active.
    uint64_t modelTotalParams_ = 0;
    uint64_t modelPackedBytes_ = 0;
    double effectiveBitsPerParam_ = 0.0;
    uint32_t configuredExpertsPerLayer_ = 0;

    uint64_t qpcFrequency_ = 0;
    uint64_t evalStartQpc_ = 0;
    uint64_t evalEndQpc_ = 0;

    // Separate cache lines reduce hot-counter contention.
    alignas(64)
    std::atomic<uint64_t> tokensGenerated_{0};

    alignas(64)
    std::atomic<uint64_t> expertSelections_{0};

    std::atomic<uint64_t> activeParamsAccumulated_{0};
    std::atomic<uint64_t> vramCacheHits_{0};
    std::atomic<uint64_t> vramCacheMisses_{0};

    alignas(64)
    std::atomic<uint64_t> gpuLogicalWeightBytes_{0};

    std::atomic<uint64_t> hostLogicalWeightBytes_{0};

    alignas(64)
    std::atomic<uint64_t> nvmeCompletedBytes_{0};

    std::atomic<uint64_t> h2dCompletedBytes_{0};
    std::atomic<uint64_t> d2dCompletedBytes_{0};

    std::atomic<uint64_t> ringStarvationEvents_{0};

    alignas(64)
    std::atomic<uint64_t> physicalPcieRxBytes_{0};

    std::atomic<uint64_t> physicalPcieTxBytes_{0};
    std::atomic<uint64_t> physicalVramReadBytes_{0};

    std::atomic<bool> physicalPcieTelemetryValid_{false};
    std::atomic<bool> physicalVramTelemetryValid_{false};
};

} // namespace rawrxd::deep2
