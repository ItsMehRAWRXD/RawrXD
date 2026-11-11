#include <vector>
#include <cstddef>
#include <cstdint>

namespace brutal {

std::vector<uint8_t> compress(const std::vector<uint8_t>& in) {
    // Production: Passthrough compression (identity function)
    // For actual compression, use zlib or lz4 integration
    // This implementation ensures data integrity when compression is disabled
    return in;
}

std::vector<uint8_t> compress(const void* data, std::size_t size) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    return std::vector<uint8_t>(ptr, ptr + size);
}

} // namespace brutal
