#include <zlib.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    std::vector<uint8_t> input(1024 * 1024);
    for (size_t i = 0; i < input.size(); ++i)
        input[i] = static_cast<uint8_t>((i * 131u + (i >> 7)) & 0xffu);

    uLongf bound = compressBound(static_cast<uLong>(input.size()));
    std::vector<uint8_t> compressed(static_cast<size_t>(bound));
    int rc = compress2(compressed.data(), &bound, input.data(),
                       static_cast<uLong>(input.size()), Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        std::fprintf(stderr, "compress2 failed: %d\n", rc);
        return 1;
    }
    compressed.resize(static_cast<size_t>(bound));

    uLongf decodedSize = static_cast<uLongf>(input.size());
    std::vector<uint8_t> decoded(input.size());
    rc = uncompress(decoded.data(), &decodedSize, compressed.data(),
                    static_cast<uLong>(compressed.size()));
    if (rc != Z_OK || decodedSize != input.size() || decoded != input) {
        std::fprintf(stderr, "uncompress roundtrip failed: %d\n", rc);
        return 2;
    }

    const uint8_t empty = 0;
    bound = compressBound(0);
    compressed.resize(static_cast<size_t>(bound));
    rc = compress2(compressed.data(), &bound, &empty, 0, Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) return 3;
    decodedSize = 0;
    rc = uncompress(&empty, &decodedSize, compressed.data(), bound);
    if (rc != Z_OK || decodedSize != 0) return 4;

    std::puts("zlib auto-detect compile/link + roundtrip PASS");
    return 0;
}
