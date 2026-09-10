/* FutureConsumer_Space.cpp — Space singleton + Init/Shutdown + pool queries. */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"
#include <mutex>

namespace Deep2 {
namespace future {

namespace detail {

struct Space {
    FutureConsumer consumers[FUTURE_CONSUMER_CAP]{};
    PhysicalPage   pages[FREETOKEN_ZONE_COUNT]{};
    uint64_t       consumerN = 0;
    uint64_t       logicalCursor = 0;
    uint64_t       ownershipAdvances = 0;
    ExecCounters   exec{};
    bool           live = false;
    std::mutex     mu;
};

Space& S() {
    static Space s;
    return s;
}

uint64_t& ConsumerN() { return S().consumerN; }
uint64_t& LogicalCursor() { return S().logicalCursor; }
uint64_t& OwnershipAdvances() { return S().ownershipAdvances; }
bool& Live() { return S().live; }
PhysicalPage* Pages() { return S().pages; }
FutureConsumer* Consumers() { return S().consumers; }
ExecCounters& Exec() { return S().exec; }
std::mutex& Mu() { return S().mu; }

} // namespace detail

bool InitFromPhysicalPool() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    if (detail::Live()) return true;
    if (!freetoken::Pool().live)
        freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
    freetoken::ZonePool& zp = freetoken::Pool();
    PhysicalPage* pages = detail::Pages();
    for (int i = 0; i < FREETOKEN_ZONE_COUNT; ++i) {
        pages[i].base = zp.zones[i].base;
        pages[i].bytes = zp.zones[i].capacity;
        pages[i].current = pages[i].next = 0;
        pages[i].generation = 0;
        pages[i].readyGeneration = 0;
        pages[i].resourceId = (ResourceId)i;
        pages[i].waitOwner = 0;
        pages[i].continuation = nullptr;
        pages[i].continuationCtx = nullptr;
    }
    detail::ConsumerN() = 0;
    detail::LogicalCursor() = 0;
    detail::OwnershipAdvances() = 0;
    detail::Exec() = {};
    detail::Live() = true;
    return true;
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(detail::Mu());
    detail::Live() = false;
    detail::ConsumerN() = 0;
    detail::LogicalCursor() = 0;
}

uint64_t LogicalBytes() { return detail::LogicalCursor(); }
uint64_t ConsumerCount() { return detail::ConsumerN(); }
uint64_t PhysicalPoolBytes() {
    return (uint64_t)FREETOKEN_ZONE_COUNT * FREETOKEN_ZONE_BYTES;
}
int PhysicalPoolGrows() { return PHYSICAL_PAGE_POOL_GROWS; }

} // namespace future
} // namespace Deep2
