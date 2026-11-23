#include "deflate_brutal_qt.hpp"
#include <zlib.h>

#include <cstdint>
#include <cstring>
#include <vector>

static bool check(const brutal::Bytes& input) {
    const brutal::Bytes encoded = brutal::compress(input);
    const std::size_t blocks = (std::max)(std::size_t(1),
        input.size() / 65535 + (input.size() % 65535 != 0 ? 1 : 0));
    if (encoded.size() != input.size() + blocks * 5 + 18) return false;
    if (encoded.size() < 23 || encoded[0] != 0x1f || encoded[1] != 0x8b ||
        encoded[2] != 8 || encoded[3] != 0 || encoded[9] != 0xff) return false;
    if (brutal::decompress(encoded) != input) return false;
    if (!input.empty() && brutal::decompress(encoded, input.size() - 1).size() != 0)
        return false;

    std::vector<std::uint8_t> output(input.empty() ? 1 : input.size());
    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(encoded.data()));
    stream.avail_in = static_cast<uInt>(encoded.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK) return false;
    const int rc = inflate(&stream, Z_FINISH);
    const bool ok = rc == Z_STREAM_END && stream.total_out == input.size() &&
        (input.empty() || std::memcmp(output.data(), input.data(), input.size()) == 0);
    inflateEnd(&stream);
    return ok;
}

int main() {
    if (brutal::maxCompressedSize(0) != 23) return 1;
    if (!check({})) return 2;
    brutal::Bytes repeated(1u << 20, 0x5a);
    if (!check(repeated)) return 3;
    brutal::Bytes varied(1u << 20);
    std::uint32_t state = 0x12345678u;
    for (auto& b : varied) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        b = static_cast<std::uint8_t>(state >> 24);
    }
    if (!check(varied)) return 4;

    auto badCrc = brutal::compress(repeated);
    badCrc[badCrc.size() - 8] ^= 1;
    if (!brutal::decompress(badCrc).empty()) return 5;
    auto badLen = brutal::compress(repeated);
    const auto header = brutal::gzipHeaderSize(badLen.data(), badLen.size());
    badLen[header + 2] ^= 1;
    if (!brutal::decompress(badLen).empty()) return 6;
    return 0;
}
