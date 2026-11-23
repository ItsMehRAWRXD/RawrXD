#include "codec/compression_core.h"
#ifndef RAWRXD_HAVE_ZLIB
#error "zlib provider test must only be built when a zlib provider was detected"
#endif
#if !RAWRXD_HAVE_ZLIB
#error "RAWRXD_HAVE_ZLIB must be enabled for this target"
#endif
#include <zlib.h>
#include <array>
#include <cstdint>
#include <cstring>

int main() {
    if (zlibVersion() == nullptr) return 1;
    const std::array<std::uint8_t, 32> input = {
        'R','a','w','r','X','D',' ','z','l','i','b',' ','p','r','o','v',
        'i','d','e','r',' ','s','m','o','k','e',' ','t','e','s','t','!'
    };
    const auto encoded = rawrxd::compression::compress(input.data(), input.size());
    if (encoded.status != rawrxd::compression::Status::Ok) return 2;
    const auto decoded = rawrxd::compression::decompress(
        encoded.bytes.data(), encoded.bytes.size(), input.size());
    if (decoded.status != rawrxd::compression::Status::Ok) return 3;
    if (decoded.bytes.size() != input.size()) return 4;
    return std::memcmp(decoded.bytes.data(), input.data(), input.size()) == 0 ? 0 : 5;
}
