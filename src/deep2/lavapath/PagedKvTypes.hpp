#pragma once
/* PagedKvTypes — logical page vs fixed physical pool. LIVE=0. ≤99.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

enum class KvTier : uint8_t {
    None = 0,
    Ram = 1,
    LocalGpu = 2,
    Backing = 3
};

struct KvVirtualPage {
    uint64_t logicalPage = 0;
    uint64_t backingOff = 0;
    uint32_t physicalPage = 0xffffffffu;
    uint32_t lastUseToken = 0;
    KvTier tier = KvTier::None;
    uint8_t dirty = 0;
    uint8_t valid = 0;
};

struct KvPhysicalPage {
    uint32_t id = 0;
    uint64_t owner = ~0ull;
    uint32_t lastUseToken = 0;
    uint8_t busy = 0;
};

enum : uint32_t {
    kKvInvalidPage = 0xffffffffu,
    kKvPhysicalPagesDefault = 256,
    kKvVirtualMapDefault = 8192
};

} /* namespace scoreboard */
} /* namespace Deep2 */
