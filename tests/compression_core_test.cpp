#include "codec/compression_core.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    std::vector<std::uint8_t> input(65536, 0x5a);
    const auto encoded = rawrxd::compression::compress(input.data(), input.size());
    if (encoded.status == rawrxd::compression::Status::Unsupported)
        return 0; // Explicitly unsupported no-zlib configuration is valid.
    assert(encoded);
    assert(!encoded.bytes.empty());
    const auto decoded = rawrxd::compression::decompress(
        encoded.bytes.data(), encoded.bytes.size(), input.size());
    assert(decoded);
    assert(decoded.bytes == input);

    const auto capped = rawrxd::compression::decompress(
        encoded.bytes.data(), encoded.bytes.size(), input.size() - 1);
    assert(capped.status == rawrxd::compression::Status::OutputLimitExceeded);

    auto corrupt = encoded.bytes;
    corrupt.back() ^= 0x80;
    const auto rejected = rawrxd::compression::decompress(
        corrupt.data(), corrupt.size(), input.size());
    assert(!rejected);
    assert(rejected.status == rawrxd::compression::Status::CorruptData);
    return 0;
}
