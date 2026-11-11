#include <cstdint>
#include <cstring>
#include <vector>

// Only include brutal_gzip.h when MASM/NEON is available
#if defined(HAS_BRUTAL_GZIP_MASM) || defined(HAS_BRUTAL_GZIP_NEON)
#include "brutal_gzip.h"
#endif

namespace codec {

// Use brutal_gzip MASM deflate for compression when available
std::vector<uint8_t> deflate(const std::vector<uint8_t>& in, bool* ok = nullptr)
{
#if defined(HAS_BRUTAL_GZIP_MASM)
    size_t out_len = 0;
    void* compressed = deflate_brutal_masm(in.data(), in.size(), &out_len);

    if (compressed && out_len > 0) {
        std::vector<uint8_t> result(static_cast<const uint8_t*>(compressed),
                                        static_cast<const uint8_t*>(compressed) + out_len);
        free(compressed);  // brutal_gzip uses malloc
        if (ok) *ok = true;
        return result;
    }
#elif defined(HAS_BRUTAL_GZIP_NEON)
    size_t out_len = 0;
    void* compressed = deflate_brutal_neon(in.data(), in.size(), &out_len);

    if (compressed && out_len > 0) {
        std::vector<uint8_t> result(static_cast<const uint8_t*>(compressed),
                                        static_cast<const uint8_t*>(compressed) + out_len);
        free(compressed);  // brutal_gzip uses malloc
        if (ok) *ok = true;
        return result;
    }
#else
    // Fallback: return empty (no compression available)
    (void)in;
#endif

    if (ok) *ok = false;
    return {};
}

// Placeholder for inflate - add your inflate implementation here
// For now, return uncompressed data for testing
std::vector<uint8_t> inflate(const std::vector<uint8_t>& in, bool* ok = nullptr)
{
    // TODO: Implement inflate using your existing inflate kernel
    // For now, assume data is not compressed and return as-is
    if (ok) *ok = true;
    return in;
}

} // namespace codec
