#include "native_compressed_residency.hpp"
#include <cstdlib>
#include <iostream>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL: " #x << " line " << __LINE__ << "\\n"; return EXIT_FAILURE; } } while (false)
#include <cstdint>
#include <stdexcept>
#include <vector>

int main() {
    using namespace rawrxd::compression;
    const std::vector<std::uint8_t> repeated(4096, 0x7f);
    const auto packed = encode(repeated.data(), repeated.size());
    CHECK(packed.rle);
    CHECK(packed.payload.size() < repeated.size());
    CHECK(decode(packed) == repeated);
    const std::vector<std::uint8_t> mixed{1,2,3,4,5,6,7,8};
    const auto raw = encode(mixed.data(), mixed.size());
    CHECK(!raw.rle);
    CHECK(decode(raw) == mixed);
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
    bool rejected = false;
    try { (void)decode(corrupt); } catch (const std::runtime_error&) { rejected = true; }
    CHECK(rejected);
    return EXIT_SUCCESS;
}
