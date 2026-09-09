/* FutureConsumer_Advance.cpp — ownership handoff + page lookup. */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

bool AdvanceOwnership(uint32_t pageIdx, ConsumerId next) {
    if (!detail::Live() || pageIdx >= FREETOKEN_ZONE_COUNT) return false;
    std::lock_guard<std::mutex> lock(detail::Mu());
    PhysicalPage& p = detail::Pages()[pageIdx];
    const ConsumerId take = next ? next : p.next;
    if (p.current) {
        FutureConsumer* cs = detail::Consumers();
        for (uint64_t i = 0; i < detail::ConsumerN() && i < FUTURE_CONSUMER_CAP;
             ++i) {
            if (cs[i].consumerId == p.current) {
                cs[i].tier = Tier::Past;
                break;
            }
        }
    }
    p.current = take;
    if (p.next && take == p.next) {
        p.next = 0;
        if (detail::Exec().queueDepthNow) detail::Exec().queueDepthNow--;
    } else {
        p.next = 0;
    }
    p.generation++;
    detail::OwnershipAdvances()++;
    detail::Exec().ownershipAdvances = detail::OwnershipAdvances();
    detail::Exec().pastToFutureRebinds++;
    if (take) {
        FutureConsumer* cs = detail::Consumers();
        for (uint64_t i = 0; i < detail::ConsumerN() && i < FUTURE_CONSUMER_CAP;
             ++i) {
            if (cs[i].consumerId == take) {
                cs[i].tier = Tier::Current;
                break;
            }
        }
    }
    return true;
}

int PageForConsumer(ConsumerId id) {
    if (!detail::Live() || !id) return -1;
    PhysicalPage* pages = detail::Pages();
    for (int i = 0; i < FREETOKEN_ZONE_COUNT; ++i)
        if (pages[i].current == id || pages[i].next == id) return i;
    return -1;
}

} // namespace future
} // namespace Deep2
