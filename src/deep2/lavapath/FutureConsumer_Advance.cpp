/* FutureConsumer_Advance.cpp — O(1) ownership handoff; no object scan. */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

FutureConsumer* ConsumerAt(ConsumerId id) {
    if (!detail::Live() || !id) return nullptr;
    FutureConsumer& c =
        detail::Consumers()[(id - 1) % FUTURE_CONSUMER_CAP];
    return (c.consumerId == id) ? &c : nullptr;
}

Chair* ChairAt(ChairId id) {
    if (!detail::Live() || id >= FREETOKEN_ZONE_COUNT) return nullptr;
    return &detail::Pages()[id];
}

static void SetTier(ConsumerId id, Tier t) {
    if (FutureConsumer* c = ConsumerAt(id)) c->tier = t;
}

bool AdvanceOwnership(uint32_t pageIdx, ConsumerId next) {
    if (!detail::Live() || pageIdx >= FREETOKEN_ZONE_COUNT) return false;
    std::lock_guard<std::mutex> lock(detail::Mu());
    Chair& p = detail::Pages()[pageIdx];
    const ConsumerId take = next ? next : p.next;
    if (p.current) SetTier(p.current, Tier::Past);
    p.current = take;
    if (p.next && take == p.next) {
        p.next = 0;
        if (detail::Exec().queueDepthNow) detail::Exec().queueDepthNow--;
    } else {
        p.next = 0;
    }
    p.generation++;
    p.resourceId = pageIdx;
    detail::OwnershipAdvances()++;
    detail::Exec().ownershipAdvances = detail::OwnershipAdvances();
    detail::Exec().pastToFutureRebinds++;
    if (take) {
        SetTier(take, Tier::Current);
        if (FutureConsumer* c = ConsumerAt(take)) {
            c->chairId = pageIdx;
            c->expectedGeneration = p.generation;
        }
    }
    return true;
}

/* O(1): consumer.chairId — never for(pages) / for(consumers). */
int PageForConsumer(ConsumerId id) {
    FutureConsumer* c = ConsumerAt(id);
    if (!c || c->chairId == CHAIR_INVALID) return -1;
    if (c->chairId >= FREETOKEN_ZONE_COUNT) return -1;
    Chair* ch = ChairAt(c->chairId);
    if (!ch) return -1;
    if (ch->current != id && ch->next != id) return -1;
    return (int)c->chairId;
}

} // namespace future
} // namespace Deep2
