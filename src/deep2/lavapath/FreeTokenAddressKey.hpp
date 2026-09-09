#pragma once
/* Address-keyed expert identity — access by (layer,expert) ∨ fileOffset.
 * Public loaders key soft names; we key stable GGUF addresses (1>0 close). */
#include <cstdint>

namespace Deep2 {
namespace freetoken {

/* 64-bit key: [layer:24][expert:24][tag:16] — tag=0 live, 1=offset-alias */
inline uint64_t ExpertIdKey(uint32_t layer, uint32_t expert) {
    return (uint64_t(layer & 0xFFFFFFu) << 40) |
           (uint64_t(expert & 0xFFFFFFu) << 16);
}

inline uint64_t OffsetKey(uint64_t fileOffset) {
    /* Top bit marks offset-primary; low 63 = offset (GGUF range). */
    return 0x8000000000000000ull | (fileOffset & 0x7FFFFFFFFFFFFFFFull);
}

inline uint32_t KeyLayer(uint64_t k) {
    if (k & 0x8000000000000000ull) return ~0u;
    return (uint32_t)((k >> 40) & 0xFFFFFFu);
}

inline uint32_t KeyExpert(uint64_t k) {
    if (k & 0x8000000000000000ull) return ~0u;
    return (uint32_t)((k >> 16) & 0xFFFFFFu);
}

} // namespace freetoken
} // namespace Deep2
