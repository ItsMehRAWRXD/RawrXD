#include "brutal_gzip.h"
#include <zlib.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <vector>

namespace {
bool roundTrip(const std::vector<std::uint8_t>& input) {
    std::size_t encodedSize = 999;
    void* raw = deflate_brutal_masm(input.empty() ? nullptr : input.data(),
                                    input.size(), &encodedSize);
    if (!raw || encodedSize < 23) return false;
    const auto* encoded = static_cast<const std::uint8_t*>(raw);
    const bool headerOk =
        encoded[0] == 0x1f && encoded[1] == 0x8b &&
        encoded[2] == 8 && encoded[3] == 0 &&
        encoded[4] == 0 && encoded[5] == 0 &&
        encoded[6] == 0 && encoded[7] == 0 &&
        encoded[8] == 0 && encoded[9] == 0xff;
    const std::size_t blocks = input.empty() ? 1 : (input.size() + 65534) / 65535;
    const std::size_t expectedSize = input.size() + blocks * 5 + 18;
    if (!headerOk || encodedSize != expectedSize) {
        std::free(raw);
        return false;
    }

    std::vector<std::uint8_t> output(input.size() ? input.size() : 1);
    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(encoded));
    stream.avail_in = static_cast<uInt>(encodedSize);
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    const int init = inflateInit2(&stream, MAX_WBITS + 16);
    if (init != Z_OK) {
        std::free(raw);
        return false;
    }
    const int rc = inflate(&stream, Z_FINISH);
    const bool ok = rc == Z_STREAM_END &&
                    stream.total_out == input.size() &&
                    (input.empty() || std::memcmp(output.data(), input.data(), input.size()) == 0);
    inflateEnd(&stream);
    std::free(raw);
    return ok;
}
}

int main() {
    std::vector<std::uint8_t> empty;
    if (!roundTrip(empty)) return 1;

    std::vector<std::uint8_t> repeated(1u << 20, 0x5a);
    if (!roundTrip(repeated)) return 2;

    std::vector<std::uint8_t> randomish(1u << 20);
    std::uint32_t state = 0x12345678u;
    for (auto& byte : randomish) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte = static_cast<std::uint8_t>(state >> 24);
    }
    if (!roundTrip(randomish)) return 3;

    std::size_t outputSize = 7;
    if (deflate_brutal_masm(nullptr, 16, &outputSize) != nullptr || outputSize != 0)
        return 4;
    if (deflate_brutal_masm(nullptr, 0, nullptr) != nullptr)
        return 5;
    return 0;
}
