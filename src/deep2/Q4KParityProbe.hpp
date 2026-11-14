#pragma once
/* Q4KParityProbe — WS2 stub so MiniMax MoE rebuild can link while Q-family
 * probe lands. No-op dump; PROMOTE=0 CROSS_SHA_CREDIT=0. */
#include <cstddef>
#include <cstdint>
namespace Deep2 {
namespace q4k_probe {
inline void MaybeDumpWoBlock0(const char* /*name*/, const void* /*data*/,
                              size_t /*sizeBytes*/) {}
}
}