#include "brutal_gzip.h"
#include <zlib.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

static bool roundtrip(const std::vector<std::uint8_t>& input) {
    std::size_t encoded_size = 0;
    void* encoded = deflate_brutal_masm(
        input.empty() ? nullptr : input.data(), input.size(), &encoded_size);
    if (!encoded || encoded_size < 18u) { std::free(encoded); return false; }

    std::vector<std::uint8_t> decoded(input.size() ? input.size() : 1u);
    z_stream stream{};
    stream.next_in = static_cast<Bytef*>(encoded);
    stream.avail_in = static_cast<uInt>(encoded_size);
    stream.next_out = decoded.data();
    stream.avail_out = static_cast<uInt>(decoded.size());
    if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK) {
        std::free(encoded);
        return false;
    }
    const int status = inflate(&stream, Z_FINISH);
    const bool ok = status == Z_STREAM_END &&
                    stream.total_out == input.size() &&
                    (input.empty() ||
                     std::memcmp(decoded.data(), input.data(), input.size()) == 0);
    inflateEnd(&stream);
    std::free(encoded);
    return ok;
}

int main() {
    for (const std::size_t size : {std::size_t(0), 1u, 31u, 65535u, 65536u,
                                   1048576u}) {
        std::vector<std::uint8_t> data(size);
        std::mt19937 rng(0x52415752u + static_cast<std::uint32_t>(size));
        for (auto& byte : data) byte = static_cast<std::uint8_t>(rng());
        if (!roundtrip(data)) {
            std::fprintf(stderr, "gzip roundtrip failed at %zu bytes\n", size);
            return 1;
        }
    }
    std::size_t length = 123;
    if (deflate_brutal_masm(nullptr, 1, &length) != nullptr || length != 0)
        return 2;
    if (deflate_brutal_masm(nullptr, 0, nullptr) != nullptr)
        return 3;
    return 0;
}
