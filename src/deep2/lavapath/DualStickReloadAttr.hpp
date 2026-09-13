#pragma once
/* Pin key class + MoE reload-after-eviction attribution. */
#include <cstdint>
#include <cstddef>

namespace Deep2 {

enum class PinWeightClass : uint8_t { MoE = 0, Mla = 1, General = 2 };

inline PinWeightClass ClassifyPinKey(uint64_t key) {
    const uint64_t role = key & 0xffu;
    if ((key >> 24) != 0 && role >= 1u && role <= 3u)
        return PinWeightClass::MoE;
    /* MLA: layer<<8|tag (tag 1..7), below MoE layer<<24 space. */
    if ((key >> 24) == 0 && role >= 1u && role <= 7u && (key >> 8) != 0)
        return PinWeightClass::Mla;
    return PinWeightClass::General;
}

/* Physical MoE pin upload after EnsurePinned miss — auth reload meter. */
void DualStickNoteMoePinUpload(uint64_t pinKey, size_t bytes, int firstEver);

/* Mark MoE pin key as LRU-evicted (for reused-key attribution). */
void DualStickMarkMoeKeyEvicted(uint64_t pinKey);

} // namespace Deep2
