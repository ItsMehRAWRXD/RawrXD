#include <zlib.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

extern "C" void* deflate_brutal_masm(const void* source, size_t length, size_t* outputLength);

static bool roundTrip(const std::vector<uint8_t>& input) {
    size_t encodedLength = 0;
    void* encoded = deflate_brutal_masm(input.empty() ? nullptr : input.data(),
                                        input.size(), &encodedLength);
    if (!encoded || encodedLength < 23) {
        std::free(encoded);
        return false;
    }

    std::vector<uint8_t> decoded(input.size() + 1);
    z_stream stream{};
    stream.next_in = static_cast<Bytef*>(encoded);
    stream.avail_in = static_cast<uInt>(encodedLength);
    stream.next_out = decoded.data();
    stream.avail_out = static_cast<uInt>(decoded.size());
    int rc = inflateInit2(&stream, MAX_WBITS + 16);
    if (rc == Z_OK) {
        rc = inflate(&stream, Z_FINISH);
        const bool valid = rc == Z_STREAM_END &&
            stream.total_out == input.size() &&
            std::equal(input.begin(), input.end(), decoded.begin());
        inflateEnd(&stream);
        if (!valid) {
            std::free(encoded);
            return false;
        }
    } else {
        std::free(encoded);
        return false;
    }

    // A gzip consumer must reject a damaged CRC footer.
    auto* bytes = static_cast<uint8_t*>(encoded);
    bytes[encodedLength - 8] ^= 0x01;
    stream = {};
    stream.next_in = bytes;
    stream.avail_in = static_cast<uInt>(encodedLength);
    stream.next_out = decoded.data();
    stream.avail_out = static_cast<uInt>(decoded.size());
    rc = inflateInit2(&stream, MAX_WBITS + 16);
    bool rejectedCorruption = false;
    if (rc == Z_OK) {
        rc = inflate(&stream, Z_FINISH);
        rejectedCorruption = rc == Z_DATA_ERROR;
        inflateEnd(&stream);
    }
    std::free(encoded);
    return rejectedCorruption;
}

int main() {
    if (!roundTrip({})) return 1;
    for (size_t size : {size_t(1), size_t(65534), size_t(65535),
                        size_t(65536), size_t(131071), size_t(1024 * 1024)}) {
        std::vector<uint8_t> input(size);
        uint32_t state = 0x9e3779b9u;
        for (auto& value : input) {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            value = static_cast<uint8_t>(state);
        }
        if (!roundTrip(input)) {
            std::fprintf(stderr, "gzip roundtrip failed for %zu bytes\n", size);
            return 2;
        }
    }
    std::puts("Brutal MASM gzip roundtrip + CRC rejection PASS");
    return 0;
}
