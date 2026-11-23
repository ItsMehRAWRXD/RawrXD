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
#include <vector>

namespace {
using rawrxd::compression::Result;
using rawrxd::compression::Status;

bool roundTrip(const std::uint8_t* data, std::size_t size) {
    const Result encoded = rawrxd::compression::compress(data, size);
    if (encoded.status != Status::Ok || encoded.bytes.empty()) return false;
    const Result decoded = rawrxd::compression::decompress(
        encoded.bytes.data(), encoded.bytes.size(), size);
    return decoded.status == Status::Ok &&
           decoded.bytes.size() == size &&
           (size == 0 || std::memcmp(decoded.bytes.data(), data, size) == 0);
}
} // namespace

int main() {
    if (zlibVersion() == nullptr) return 1;

    // Compile/link and exercise the actual zlib-backed provider, not merely
    // the no-zlib Unsupported implementation.
    const std::array<std::uint8_t, 32> input = {
        'R','a','w','r','X','D',' ','z','l','i','b',' ','p','r','o','v',
        'i','d','e','r',' ','s','m','o','k','e',' ','t','e','s','t','!'
    };
    if (!roundTrip(input.data(), input.size())) return 2;

    // Empty input is a valid zlib stream and must survive the same adapter
    // path as non-empty binary data.
    if (!roundTrip(nullptr, 0)) return 3;

    // Invalid pointer/length pairs must be rejected before entering zlib.
    if (rawrxd::compression::compress(nullptr, 1).status != Status::InvalidInput)
        return 4;
    if (rawrxd::compression::decompress(nullptr, 1, 64).status != Status::InvalidInput)
        return 5;

    // A caller-supplied ceiling is a hard bound, including a zero-byte cap.
    const Result encoded = rawrxd::compression::compress(input.data(), input.size());
    if (encoded.status != Status::Ok) return 6;
    if (rawrxd::compression::decompress(
            encoded.bytes.data(), encoded.bytes.size(), input.size() - 1).status !=
        Status::OutputLimitExceeded) return 7;
    if (rawrxd::compression::decompress(
            encoded.bytes.data(), encoded.bytes.size(), 0).status !=
        Status::OutputLimitExceeded) return 8;

    // Truncation must be reported as corrupt data, never as a successful
    // partial decode.
    if (encoded.bytes.size() < 2) return 9;
    const Result truncated = rawrxd::compression::decompress(
        encoded.bytes.data(), encoded.bytes.size() - 1, input.size());
    if (truncated.status != Status::CorruptData) return 10;

    // Empty compressed input preserves the documented legacy contract.
    const Result empty = rawrxd::compression::decompress(nullptr, 0, 0);
    if (empty.status != Status::Ok || !empty.bytes.empty()) return 11;

    return 0;
}
