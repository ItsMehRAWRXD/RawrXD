#include "ds_parallel_device_partial.hpp"

#include <algorithm>
#include <atomic>
#include <exception>
#include <thread>

namespace rawrxd::deep2::dsdp {
namespace {

struct WorkerResult {
    bool ok = true;
    uint64_t executed = 0;
    uint64_t deviceDownVectors = 0;
    uint64_t devicePartialAccums = 0;
    std::string error;
};

} // namespace

Result RunLayer(Backend& backend,
                const std::vector<WorkItem>& stick0,
                const std::vector<WorkItem>& stick1,
                uint32_t hidden,
                float* accum) {
    Result r{};
    r.counters.selected = stick0.size() + stick1.size();
    if (!hidden || !accum) {
        r.error = "DSDP_BAD_ARGS";
        return r;
    }
    if (stick0.empty() && stick1.empty()) {
        r.ok = true;
        r.productAuthorityEligible = false;
        return r;
    }

    DevicePartial partial[2]{};
    if (!backend.BeginLayer(hidden, partial, r.error)) {
        backend.AbortLayer(partial);
        r.counters.workerFailures++;
        return r;
    }
    const bool need0 = !stick0.empty();
    const bool need1 = !stick1.empty();
    if ((need0 && !partial[0].handle) || (need1 && !partial[1].handle)) {
        r.error = "DSDP_INVALID_DEVICE_PARTIAL";
        backend.AbortLayer(partial);
        r.counters.workerFailures++;
        return r;
    }

    std::atomic<uint32_t> active{0};
    std::atomic<uint32_t> maxActive{0};
    WorkerResult wr[2]{};

    auto worker = [&](unsigned stick, const std::vector<WorkItem>& work) noexcept {
        r.counters.stickStarts[stick] = 1;
        const uint32_t now = active.fetch_add(1, std::memory_order_acq_rel) + 1;
        uint32_t seen = maxActive.load(std::memory_order_relaxed);
        while (seen < now &&
               !maxActive.compare_exchange_weak(seen, now,
                                                std::memory_order_relaxed)) {}
        try {
            for (const WorkItem& item : work) {
                if (item.expertId < 0 || !item.residentHandle) {
                    wr[stick].ok = false;
                    wr[stick].error = "DSDP_INVALID_WORK_ITEM";
                    break;
                }
                if (!backend.ExecWeightedExpert(stick, item, partial[stick],
                                                wr[stick].error)) {
                    wr[stick].ok = false;
                    if (wr[stick].error.empty())
                        wr[stick].error = "DSDP_EXPERT_EXEC_FAILED";
                    break;
                }
                ++wr[stick].executed;
                ++wr[stick].deviceDownVectors;
                ++wr[stick].devicePartialAccums;
            }
        } catch (...) {
            wr[stick].ok = false;
            wr[stick].error = "DSDP_WORKER_EXCEPTION";
            r.counters.exceptionFailures++;
        }
        active.fetch_sub(1, std::memory_order_acq_rel);
        r.counters.stickFinishes[stick] = 1;
    };

    std::thread t0, t1;
    try {
        if (need0) t0 = std::thread(worker, 0u, std::cref(stick0));
        if (need1) t1 = std::thread(worker, 1u, std::cref(stick1));
    } catch (...) {
        if (t0.joinable()) t0.join();
        if (t1.joinable()) t1.join();
        backend.AbortLayer(partial);
        r.error = "DSDP_THREAD_CREATE_FAILED";
        r.counters.exceptionFailures++;
        return r;
    }
    if (t0.joinable()) t0.join();
    if (t1.joinable()) t1.join();

    r.counters.maxConcurrentWorkers = maxActive.load(std::memory_order_relaxed);
    r.counters.executed = wr[0].executed + wr[1].executed;
    r.counters.deviceDownVectors =
        wr[0].deviceDownVectors + wr[1].deviceDownVectors;
    r.counters.devicePartialAccums =
        wr[0].devicePartialAccums + wr[1].devicePartialAccums;

    if (!wr[0].ok || !wr[1].ok || r.counters.executed != r.counters.selected) {
        r.counters.workerFailures += (!wr[0].ok ? 1u : 0u) +
                                     (!wr[1].ok ? 1u : 0u);
        r.error = !wr[0].ok ? wr[0].error :
                  (!wr[1].ok ? wr[1].error : "DSDP_SELECTED_EXECUTED_MISMATCH");
        backend.AbortLayer(partial);
        return r;
    }

    std::vector<float> p0(hidden, 0.0f), p1(hidden, 0.0f);
    if (need0) {
        if (!backend.DownloadPartial(0u, partial[0], p0.data(), hidden, r.error)) {
            backend.AbortLayer(partial);
            r.counters.workerFailures++;
            return r;
        }
        ++r.counters.d2hPartialVectors;
    }
    if (need1) {
        if (!backend.DownloadPartial(1u, partial[1], p1.data(), hidden, r.error)) {
            backend.AbortLayer(partial);
            r.counters.workerFailures++;
            return r;
        }
        ++r.counters.d2hPartialVectors;
    }

    for (uint32_t i = 0; i < hidden; ++i) accum[i] += p0[i] + p1[i];
    ++r.counters.layerJoins;
    backend.EndLayer(partial);

    r.ok = true;
    r.productAuthorityEligible = backend.ProductBackendAttested() &&
        (!need0 || r.counters.stickStarts[0] == 1) &&
        (!need1 || r.counters.stickStarts[1] == 1) &&
        (!(need0 && need1) || r.counters.maxConcurrentWorkers >= 2) &&
        r.counters.executed == r.counters.selected &&
        r.counters.hostExpertDownVectors == 0 &&
        r.counters.d2hPartialVectors == (uint64_t(need0) + uint64_t(need1)) &&
        r.counters.layerJoins == 1 && r.counters.workerFailures == 0 &&
        r.counters.exceptionFailures == 0;
    return r;
}

} // namespace rawrxd::deep2::dsdp
