#include "codec/compression_core.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <algorithm>
#include <vector>

int main() {
    std::vector<std::uint8_t> input(65536, 0x5a);
    const auto encoded = rawrxd::compression::compress(input.data(), input.size());
    if (encoded.status == rawrxd::compression::Status::Unsupported) {
#ifdef RAWRXD_TEST_REQUIRE_ZLIB
        return 2; // Strict provider smoke must exercise the real codec.
#else
        return 0; // No-zlib configurations are permitted outside strict CI.
#endif
    }
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
    // Incompressible binary data exercises the codec's expansion path.
    std::vector<std::uint8_t> binary(131072);
    std::uint32_t state = 0x12345678u;
    for (auto& byte : binary) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte = static_cast<std::uint8_t>(state);
    }
    const auto binaryEncoded = rawrxd::compression::compress(binary.data(), binary.size());
    assert(binaryEncoded);
    const auto binaryDecoded = rawrxd::compression::decompress(
        binaryEncoded.bytes.data(), binaryEncoded.bytes.size(), binary.size());
    assert(binaryDecoded && binaryDecoded.bytes == binary);

    // A truncated stream must not be accepted as a complete tensor block.
    auto truncated = binaryEncoded.bytes;
    truncated.resize(truncated.size() / 2);
    const auto truncatedResult = rawrxd::compression::decompress(
        truncated.data(), truncated.size(), binary.size());
    assert(!truncatedResult);
    // zlib may report Z_BUF_ERROR for truncated streams at the output cap.
    assert(truncatedResult.status == rawrxd::compression::Status::CorruptData ||
           truncatedResult.status == rawrxd::compression::Status::OutputLimitExceeded);

    // The output ceiling is exact: a single byte less must be rejected.
    const auto binaryCapped = rawrxd::compression::decompress(
        binaryEncoded.bytes.data(), binaryEncoded.bytes.size(), binary.size() - 1);
    assert(binaryCapped.status == rawrxd::compression::Status::OutputLimitExceeded);
    return 0;
}
