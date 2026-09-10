/* FutureConsumer_Register.cpp — logical consumer + chair bind (no scan). */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

ConsumerId Register(uint16_t layer, uint8_t op, uint8_t device,
                    uint64_t logicalBytes, uint32_t nextUse) {
    if (!detail::Live() && !InitFromPhysicalPool()) return 0;
    std::lock_guard<std::mutex> lock(detail::Mu());
    uint64_t& n = detail::ConsumerN();
    if (n >= FUTURE_CONSUMER_CAP) n = FUTURE_CONSUMER_CAP / 2;
    const uint64_t idx = n++;
    FutureConsumer& c = detail::Consumers()[idx % FUTURE_CONSUMER_CAP];
    c.consumerId = idx + 1;
    c.logicalBegin = detail::LogicalCursor();
    c.logicalEnd = c.logicalBegin + (logicalBytes ? logicalBytes : 1);
    detail::LogicalCursor() = c.logicalEnd;
    c.firstUse = c.lastUse = c.nextUse = nextUse;
    c.layer = layer;
    c.op = op;
    c.preferredDevice = device;
    c.tier = Tier::Future5;
    c.chairId = CHAIR_INVALID;
    c.expectedGeneration = 0;
    detail::ExecCounters& e = detail::Exec();
    e.consumersRegistered = n;
    e.logicalBytes = detail::LogicalCursor();
    const uint32_t page = freetoken::PickZone(device & 3u);
    if (page < FREETOKEN_ZONE_COUNT) {
        Chair& p = detail::Pages()[page];
        p.resourceId = page;
        c.chairId = page;
        if (!p.current) {
            p.current = c.consumerId;
            c.expectedGeneration = p.generation;
            c.tier = Tier::Current;
        } else if (!p.next) {
            p.next = c.consumerId;
            c.expectedGeneration = p.generation + 1;
            e.queueDepthNow++;
            if (e.queueDepthNow > e.maxFutureQueueDepth)
                e.maxFutureQueueDepth = e.queueDepthNow;
            c.tier = Tier::Future1;
        } else {
            e.doubleOwner++;
            p.next = c.consumerId;
            c.expectedGeneration = p.generation + 1;
            c.tier = Tier::Future2;
        }
    }
    return c.consumerId;
}

} // namespace future
} // namespace Deep2
