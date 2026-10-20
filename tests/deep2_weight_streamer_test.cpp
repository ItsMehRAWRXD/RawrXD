#include "deep2/VulkanWeightStreamer.hpp"
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
    // A second request for the same tensor is a cache hit, not a duplicate copy.
    const auto aHit = stream.prefetch(11, payload.data(), payload.size());
    assert(aHit.valid() && aHit.id == a.id && stream.snapshot().cacheHits == 1);
    ResidentBinding binding{};
    assert(!stream.bindResident(11, binding));
    assert(stream.waitReady(a));
    assert(stream.bindResident(11, binding));
    assert(binding.valid());

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
    assert(!stream.waitReady(a));
    assert(stream.waitReady(c));

    const auto m = stream.snapshot();
    assert(m.submitted == 3);
    assert(m.completed == 3);
    assert(m.failures >= 1); // the third request was intentionally fail-closed
    assert(m.staleTickets >= 1);
    deep2_stream_transfer_emit_compile_anchor();
    return 0;
}
