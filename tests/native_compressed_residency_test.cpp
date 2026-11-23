#include "native_compressed_residency.hpp"
#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <vector>

int main() {
    using namespace rawrxd::compression;
    const std::vector<std::uint8_t> repeated(4096, 0x7f);
    const auto packed = encode(repeated.data(), repeated.size());
    assert(packed.rle);
    assert(packed.payload.size() < repeated.size());
    assert(decode(packed) == repeated);
    const std::vector<std::uint8_t> mixed{1,2,3,4,5,6,7,8};
    const auto raw = encode(mixed.data(), mixed.size());
    assert(!raw.rle);
    assert(decode(raw) == mixed);
    BoundedDecodeCache cache(16);
    assert(cache.get(1, raw) == mixed);
    assert(cache.resident_bytes() == 8);
    assert(cache.get(2, raw) == mixed);
    assert(cache.resident_bytes() == 16);
    assert(cache.get(3, raw) == mixed);
    assert(cache.resident_bytes() == 16);
    assert(cache.get(4, packed) == repeated);
    assert(cache.resident_bytes() == 16);
    Block corrupt{{0, 42}, 1, true};
    bool rejected = false;
    try { (void)decode(corrupt); } catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}
