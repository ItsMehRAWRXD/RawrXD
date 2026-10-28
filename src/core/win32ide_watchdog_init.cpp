// Watchdog init — MagBuf CRC join (B04).
// Publishes a fixed region so batch_005 verify can recompute CRC32.
// Separate TU from batch_004 to avoid hotpatch/snapshot ODR with MASM.
// HMAC product key is NOT here: asm_watchdog_get_baseline →
// asm_camellia256_get_hmac_key (evidence/WATCHDOG_HMAC_PRODUCT_001).
// Product ASM restored (WATCHDOG_ASM_BIND_001); MagBuf CRC stays C-owned.
// HMAC .text body is MASM; do not dual-link without gating these C exports.
#include "mag_registry.hpp"

#include <cstdint>
#include <cstring>

namespace {

alignas(64) uint8_t g_wdRegion[128]{};

uint32_t crc32Ieee(const uint8_t* data, uint32_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint32_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            const uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

} // namespace

extern "C" bool asm_watchdog_init() {
    constexpr uint32_t kTrailer = static_cast<uint32_t>(sizeof(uint32_t));
    constexpr uint32_t kPayload = static_cast<uint32_t>(sizeof(g_wdRegion) - kTrailer);
    for (uint32_t i = 0; i < kPayload; ++i) {
        g_wdRegion[i] = static_cast<uint8_t>(0x5Au ^ static_cast<uint8_t>(i));
    }
    const uint32_t baselineCrc = crc32Ieee(g_wdRegion, kPayload);
    std::memcpy(g_wdRegion + kPayload, &baselineCrc, sizeof(baselineCrc));
    mag_publish_watchdog_region(g_wdRegion, static_cast<uint32_t>(sizeof(g_wdRegion)));
    return true;
}
