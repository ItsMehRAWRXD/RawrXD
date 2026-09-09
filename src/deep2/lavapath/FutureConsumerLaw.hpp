#pragma once
/* FUTURE_CONSUMER_SPACE — logical addresses grow; physical pool does not. */
#include <cstdint>
/*
 * ADDRESSABILITY_OWNER=FUTURE_CONSUMER_SPACE
 * RESIDENCY_OWNER=FIXED_FREETOKEN_POOL
 * EVICTION_POLICY=NONE
 * REASSIGNMENT_POLICY=ADVANCE_OWNERSHIP
 * CACHE_POLICY=TIME_UNTIL_CONSUMER
 */
#define FUTURE_CONSUMER_SPACE_GROWS 1
#define LOGICAL_ADDRESS_SPACE_GROWS 1
#define PHYSICAL_PAGE_POOL_GROWS 0
#define HOTPATH_ALLOCATIONS_FORBIDDEN 1
#define FREE_REQUIRED 0
#define REUSE_REQUIRED 1

namespace Deep2 {
namespace future {

enum class Tier : uint8_t {
    Future5 = 5,
    Future4 = 4,
    Future3 = 3,
    Future2 = 2,
    Future1 = 1,
    Current = 0,
    Past    = 6
};

} // namespace future
} // namespace Deep2
