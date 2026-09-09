/* FutureConsumer_Register.cpp — logical consumer registration only. */
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
    detail::ExecCounters& e = detail::Exec();
    e.consumersRegistered = n;
    e.logicalBytes = detail::LogicalCursor();
    const uint32_t page = freetoken::PickZone(device & 3u);
    if (page < FREETOKEN_ZONE_COUNT) {
        PhysicalPage& p = detail::Pages()[page];
        if (!p.current) {
            p.current = c.consumerId;
        } else if (!p.next) {
            p.next = c.consumerId;
            e.queueDepthNow++;
            if (e.queueDepthNow > e.maxFutureQueueDepth)
                e.maxFutureQueueDepth = e.queueDepthNow;
        } else {
            e.doubleOwner++;
            p.next = c.consumerId;
        }
        c.tier = Tier::Future2;
    }
    return c.consumerId;
}

} // namespace future
} // namespace Deep2
