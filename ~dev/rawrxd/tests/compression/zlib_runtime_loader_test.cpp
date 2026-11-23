#include "zlib_runtime_loader.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    RawrXD::Compression::ZlibRuntimeLoader zlib;
    if (!zlib.Load()) {
        std::puts("SKIP: no compatible system zlib runtime found");
        return 77;
    }

    std::vector<std::uint8_t> source(256 * 1024);
    for (std::size_t i = 0; i < source.size(); ++i)
        source[i] = static_cast<std::uint8_t>((i / 128) & 0x0f);

    std::vector<std::uint8_t> compressed(source.size() + 1024);
    std::uint32_t compressedBytes =
        static_cast<std::uint32_t>(compressed.size());
    if (!zlib.Compress(compressed.data(), &compressedBytes,
                       source.data(), static_cast<std::uint32_t>(source.size()), 6)) {
        std::puts("FAIL: zlib compression failed");
        return 1;
    }
    if (compressedBytes >= source.size()) {
        std::puts("FAIL: repetitive input did not compress");
        return 2;
    }
    compressed.resize(compressedBytes);

    std::vector<std::uint8_t> decoded(source.size());
    std::uint32_t decodedBytes = static_cast<std::uint32_t>(decoded.size());
    if (!zlib.Decompress(decoded.data(), &decodedBytes,
                         compressed.data(), compressedBytes)) {
        std::puts("FAIL: zlib decompression failed");
        return 3;
    }
    if (decodedBytes != source.size() || decoded != source) {
        std::puts("FAIL: zlib round trip mismatch");
        return 4;
    }

    std::puts("PASS: runtime zlib discovery, compression, and decompression");
    return 0;
}
