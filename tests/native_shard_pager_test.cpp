#include "../src/ShardPager.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

int main() {
    using namespace deep2;
    constexpr std::size_t pageSize = 16;
    PageCache cache(2 * pageSize, pageSize);
    cache.setReader([](uint32_t shard, uint64_t page, uint8_t* out, std::size_t bytes) {
        for (std::size_t i = 0; i < bytes; ++i)
            out[i] = static_cast<uint8_t>((page * 16 + i + shard) & 255);
        return true;
    });
    uint8_t result[40] = {};
    assert(cache.readRange(3, 8, sizeof(result), result));
    for (std::size_t i = 0; i < sizeof(result); ++i)
        assert(result[i] == static_cast<uint8_t>(i + 11));
    assert(cache.residentBytes() <= 2 * pageSize);
    assert(!cache.readRange(3, UINT64_MAX - 1, 8, result));
    assert(!cache.readRange(3, 0, 1, nullptr));
    assert(cache.readRange(3, 0, 0, nullptr));

    // Different 64-bit page numbers must never alias in the cache index.
    Page* low = cache.acquire(2, 1);
    assert(low);
    Page* high = cache.acquire(2, (uint64_t{1} << 32) + 1);
    assert(high && high != low);
    cache.release(high);
    cache.release(low);

    // Moving a lease transfers page ownership exactly once.
    TensorLease first(cache, 1, 0, pageSize);
    assert(first);
    TensorLease second(std::move(first));
    assert(second && !first);
    assert(second.read(0, 1, result));
    TensorLease third;
    third = std::move(second);
    assert(third && !second);
    assert(!third.read(1, pageSize, result));
    assert(!third.read(0, 1, nullptr));
    assert(third.read(0, 0, nullptr));
    return 0;
}
