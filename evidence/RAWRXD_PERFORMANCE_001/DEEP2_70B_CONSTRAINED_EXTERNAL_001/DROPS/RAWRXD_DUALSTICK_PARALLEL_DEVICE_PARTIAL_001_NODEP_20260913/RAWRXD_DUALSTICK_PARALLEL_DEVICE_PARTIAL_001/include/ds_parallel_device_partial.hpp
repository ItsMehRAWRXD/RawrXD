#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::deep2::dsdp {

struct WorkItem {
    int32_t expertId = -1;
    float weight = 0.0f;
    uint32_t residentHandle = 0;
};

struct Counters {
    uint64_t selected = 0;
    uint64_t executed = 0;
    uint64_t stickStarts[2] = {0, 0};
    uint64_t stickFinishes[2] = {0, 0};
    uint64_t deviceDownVectors = 0;
    uint64_t devicePartialAccums = 0;
    uint64_t d2hPartialVectors = 0;
    uint64_t hostExpertDownVectors = 0;
    uint64_t layerJoins = 0;
    uint64_t workerFailures = 0;
    uint64_t exceptionFailures = 0;
    uint64_t maxConcurrentWorkers = 0;
};

struct DevicePartial {
    // Opaque backend handle. Zero means invalid/unallocated.
    uint64_t handle = 0;
    uint32_t elements = 0;
};

class Backend {
public:
    virtual ~Backend() = default;

    // Prepare one persistent device partial per stick for this layer.
    virtual bool BeginLayer(uint32_t hidden, DevicePartial out[2],
                            std::string& error) = 0;

    // Must leave expert Down on-device and apply weight into stickPartial.
    // No per-expert host Down vector is permitted on success.
    virtual bool ExecWeightedExpert(unsigned stick, const WorkItem& item,
                                    DevicePartial& stickPartial,
                                    std::string& error) = 0;

    // Download exactly one final H-vector for this stick after all experts.
    virtual bool DownloadPartial(unsigned stick, const DevicePartial& partial,
                                 float* host, uint32_t hidden,
                                 std::string& error) = 0;

    // Required on every failure path; must be idempotent.
    virtual void AbortLayer(DevicePartial partial[2]) noexcept = 0;
    virtual void EndLayer(DevicePartial partial[2]) noexcept = 0;

    // Live RawrXD/Vulkan adapter must attest true. Tests/simulators stay false.
    virtual bool ProductBackendAttested() const noexcept = 0;
};

struct Result {
    bool ok = false;
    bool productAuthorityEligible = false;
    std::string error;
    Counters counters{};
};

// Executes both non-empty stick worklists concurrently. All backend calls for a
// given stick remain on that stick's worker thread. Final host join occurs once,
// after both workers have completed and after one partial download per stick.
Result RunLayer(Backend& backend,
                const std::vector<WorkItem>& stick0,
                const std::vector<WorkItem>& stick1,
                uint32_t hidden,
                float* accum);

} // namespace rawrxd::deep2::dsdp
