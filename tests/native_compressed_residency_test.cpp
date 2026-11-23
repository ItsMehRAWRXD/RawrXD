#include "native_compressed_residency.hpp"
#include <cstdlib>
#include <iostream>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL: " #x << " line " << __LINE__ << "\\n"; return EXIT_FAILURE; } } while (false)
#include <cstdint>
#include <stdexcept>
#include <vector>

int main() {
    using namespace rawrxd::compression;
    std::vector<std::uint8_t> repeated;
    repeated.reserve(750);
    for (std::uint16_t value = 1; value <= 250; ++value)
        repeated.insert(repeated.end(), 3, static_cast<std::uint8_t>(value));
    const auto packed = encode(repeated.data(), repeated.size());
    CHECK(packed.rle);
    CHECK(packed.payload.size() < repeated.size());
    CHECK(decode(packed) == repeated);
    const std::vector<std::uint8_t> mixed{1,2,3,4,5,6,7,8};
    const auto raw = encode(mixed.data(), mixed.size());
    CHECK(!raw.rle && !raw.lz4);
    CHECK(decode(raw) == mixed);
    const std::vector<std::uint8_t> singleton{0xa5};
    CHECK(decode(encode(singleton.data(), singleton.size())) == singleton);
    std::vector<std::uint8_t> incompressible(65536);
    std::uint32_t randomState = 0x9e3779b9u;
    for (auto& value : incompressible) {
        randomState ^= randomState << 13;
        randomState ^= randomState >> 17;
        randomState ^= randomState << 5;
        value = static_cast<std::uint8_t>(randomState >> 24);
    }
    const auto packed_incompressible = encode(incompressible.data(), incompressible.size());
    CHECK(!packed_incompressible.rle && !packed_incompressible.lz4);
    CHECK(packed_incompressible.payload.size() == incompressible.size());
    CHECK(decode(packed_incompressible) == incompressible);

    // Repeated non-run structure must use the general LZ4-style codec.
    std::vector<std::uint8_t> structured(65536);
    for (std::size_t i = 0; i < structured.size(); ++i)
        structured[i] = static_cast<std::uint8_t>((i % 251u) ^ ((i / 251u) & 7u));
    const auto packed_structured = encode(structured.data(), structured.size());
    CHECK(packed_structured.lz4);
    CHECK(packed_structured.payload.size() < structured.size());
    CHECK(decode(packed_structured) == structured);
    BoundedDecodeCache cache(16);
    CHECK(cache.get(1, raw) == mixed);
    CHECK(cache.resident_bytes() == 8);
    CHECK(cache.get(2, raw) == mixed);
    CHECK(cache.resident_bytes() == 16);
    CHECK(cache.get(3, raw) == mixed);
    CHECK(cache.resident_bytes() == 16);
    CHECK(cache.get(4, packed) == repeated);
    CHECK(cache.resident_bytes() == 16);
    Block changed = raw;
    changed.generation = 1;
    changed.payload[0] = 99;
    CHECK(cache.get(3, changed) == std::vector<std::uint8_t>({99,2,3,4,5,6,7,8}));
    Block corrupt{{0, 42}, 1, true};
    Block corruptLz4{{0x00, 0x00, 0x00}, 4, false, true};
    bool rejected = false;
    try { (void)decode(corrupt); } catch (const std::runtime_error&) { rejected = true; }
    CHECK(rejected);
    rejected = false;
    try { (void)decode(corruptLz4); } catch (const std::runtime_error&) { rejected = true; }
    CHECK(rejected);
    return EXIT_SUCCESS;
}
