/* FutureConsumer_Emit.cpp — law / invariant receipt. */
#include "FutureConsumerSpace.hpp"
#include "FutureConsumer_Internal.hpp"

namespace Deep2 {
namespace future {

void EmitLaw(FILE* f) {
    if (!f) f = stderr;
    std::fprintf(f,
        "ADDRESSABILITY_OWNER=FUTURE_CONSUMER_SPACE\n"
        "RESIDENCY_OWNER=FIXED_FREETOKEN_POOL\n"
        "EVICTION_POLICY=NONE\n"
        "REASSIGNMENT_POLICY=ADVANCE_OWNERSHIP\n"
        "CACHE_POLICY=TIME_UNTIL_CONSUMER\n"
        "PHYSICAL_POOL_BYTES=%llu\n"
        "PHYSICAL_POOL_GROWS=0\n"
        "FUTURE_CONSUMER_SPACE_GROWS=%d\n"
        "LOGICAL_ADDRESS_SPACE_GROWS=%d\n"
        "PHYSICAL_PAGE_POOL_GROWS=%d\n"
        "HOTPATH_ALLOCATIONS=%llu\n"
        "FREE_REQUIRED=%d\n"
        "REUSE_REQUIRED=%d\n"
        "LOGICAL_CONSUMERS=%llu\n"
        "LOGICAL_ADDRESS_BYTES=%llu\n"
        "PHYSICAL_PAGE_POOL_BYTES=%llu\n"
        "PHYSICAL_PAGES=%d\n"
        "OWNERSHIP_ADVANCES=%llu\n"
        "PAST_OWNER_TO_FUTURE_OWNER=1\n"
        "CACHE_METRIC=TIME_UNTIL_CONSUMER\n",
        (unsigned long long)PhysicalPoolBytes(),
        FUTURE_CONSUMER_SPACE_GROWS,
        LOGICAL_ADDRESS_SPACE_GROWS,
        PHYSICAL_PAGE_POOL_GROWS,
        (unsigned long long)freetoken::Pool().allocsAfterInit,
        FREE_REQUIRED,
        REUSE_REQUIRED,
        (unsigned long long)detail::ConsumerN(),
        (unsigned long long)detail::LogicalCursor(),
        (unsigned long long)PhysicalPoolBytes(),
        FREETOKEN_ZONE_COUNT,
        (unsigned long long)detail::OwnershipAdvances());
}

} // namespace future
} // namespace Deep2
