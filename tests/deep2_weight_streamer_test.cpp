#include "deep2/VulkanWeightStreamer.hpp"
#include "deep2/ResidencyReplay.hpp"
#include "deep2/StreamLinkBudget.hpp"

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace {
class FakeTransferBackend final : public Deep2::IWeightTransferBackend {
public:
    bool submitCopy(const void*, size_t bytes, uint32_t slot,
                    uint64_t signal) override {
        ++submits;
        lastBytes = bytes;
        lastSlot = slot;
        pending = signal;
        return true;
    }
    bool wait(uint64_t signal) override {
        if (!pending || signal != pending) return false;
        completed = signal;
        pending = 0;
        return true;
    }
    uint64_t completedValue() const noexcept override { return completed; }
    uint64_t submits = 0, completed = 0, pending = 0;
    size_t lastBytes = 0;
    uint32_t lastSlot = 0;
};
}

void deep2_stream_transfer_emit_compile_anchor();

int main() {
    using namespace Deep2;
    assert(StreamLinkBudget_BytesPerToken() > 359e6 &&
           StreamLinkBudget_BytesPerToken() < 361e6);
    assert(StreamLinkBudget_Status(0, 0) == std::string("NOT_RUN"));
    assert(StreamLinkBudget_Status(360000000, 1) == std::string("PASS"));
    assert(StreamLinkBudget_Status(360000001, 1) == std::string("FAIL"));
    std::vector<uint8_t> payload(1024, 0x5a);

    // Strict mode must fail closed without a real transfer backend.
    VulkanWeightStreamer noBackend;
    WeightStreamConfig cfg;
    cfg.vramBudgetBytes = 4096;
    cfg.stagingBudgetBytes = 2048;
    cfg.slotCount = 2;
    assert(!noBackend.initialize(cfg));
    assert(!noBackend.prefetch(1, payload.data(), payload.size()).valid());

    FakeTransferBackend backend;
    VulkanWeightStreamer stream(&backend);
    assert(stream.initialize(cfg));
    const auto a = stream.prefetch(11, payload.data(), payload.size());
    assert(a.valid() && backend.submits == 1);
    assert(!stream.ready(a));
    // A second request for the same tensor is a cache hit, not a duplicate copy.
    const auto aHit = stream.prefetch(11, payload.data(), payload.size());
    assert(aHit.valid() && aHit.id == a.id && stream.snapshot().cacheHits == 1);
    ResidentBinding binding{};
    assert(!stream.bindResident(11, binding));
    assert(stream.waitReady(a));
    assert(stream.ready(a));
    assert(stream.bindResident(11, binding));
    assert(binding.valid());

    // A dispatch lease pins the allocation. Eviction/release is denied until
    // the compute dependency is explicitly retired.
    ResidentBinding dispatchBinding{};
    assert(stream.acquireForDispatch(a, dispatchBinding));
    assert(dispatchBinding.dispatchLease != 0);
    assert(!stream.release(binding));
    assert(stream.releaseAfterGpuCompletion(dispatchBinding));
    assert(!stream.releaseAfterGpuCompletion(dispatchBinding));

    // A second slot can be submitted while the first binding is live. A third
    // request is rejected instead of evicting a live GPU buffer.
    const auto b = stream.prefetch(12, payload.data(), payload.size());
    assert(b.valid());
    const auto cBlocked = stream.prefetch(13, payload.data(), payload.size());
    assert(!cBlocked.valid());
    assert(stream.waitReady(b));

    // Releasing and reusing the slot invalidates old bindings/tickets.
    assert(stream.release(binding));
    assert(!stream.release(binding));
    const auto c = stream.prefetch(13, payload.data(), payload.size());
    assert(c.valid());
    assert(c.allocationEpoch != a.allocationEpoch);
    assert(!stream.waitReady(a));
    assert(stream.waitReady(c));

    // Predictive planning and deterministic replay are source-only evidence;
    // they must never be confused with a live Vulkan transfer receipt.
    ExpertResidencyPlanner planner(2048, 4);
    const auto plan = planner.plan({
        {101, 1024, 0.9, 8.0, 2.0, 2, 1},
        {102, 1024, 0.2, 2.0, 1.0, 2, 0},
        {103, 2048, 1.0, 9.0, 1.0, 2, 2}}, 0);
    assert(plan.size() == 3 && plan[0].candidate.tensor == 101);
    assert(plan[0].admitted && !plan[1].admitted);

    ResidencyTraceRecorder trace;
    ResidencyReplaySimulator replay(2048);
    const auto replayResult = replay.run({{101, 1024}, {102, 1024},
                                         {101, 1024}, {103, 2048}}, &trace);
    assert(replayResult.requests == 4);
    assert(replayResult.transfers == 3);
    assert(replayResult.cacheHits == 1);
    assert(replayResult.evictions == 2);
    assert(replayResult.status == "PASS");
    assert(!trace.events().empty());

    const auto m = stream.snapshot();
    assert(m.submitted == 3);
    assert(m.completed == 3);
    assert(m.failures >= 1); // the third request was intentionally fail-closed
    assert(m.staleTickets >= 1);
    deep2_stream_transfer_emit_compile_anchor();
    return 0;
}
