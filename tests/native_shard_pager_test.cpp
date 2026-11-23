#include "../src/ShardPager.hpp"
#include <cstdio>
#include <cstdlib>
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed: %s:%d: %s\\n", __FILE__, __LINE__, #expr); std::abort(); } } while (0)
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
    CHECK(cache.readRange(3, 8, sizeof(result), result));
    for (std::size_t i = 0; i < sizeof(result); ++i)
        CHECK(result[i] == static_cast<uint8_t>(i + 11));
    CHECK(cache.residentBytes() <= 2 * pageSize);
    CHECK(!cache.readRange(3, UINT64_MAX - 1, 8, result));
    CHECK(!cache.readRange(3, 0, 1, nullptr));
    CHECK(cache.readRange(3, 0, 0, nullptr));

    // Different 64-bit page numbers must never alias in the cache index.
    Page* low = cache.acquire(2, 1);
    CHECK(low);
    Page* high = cache.acquire(2, (uint64_t{1} << 32) + 1);
    CHECK(high && high != low);
    cache.release(high);
    cache.release(low);

    // Moving a lease transfers page ownership exactly once.
    TensorLease first(cache, 1, 0, pageSize);
    CHECK(first);
    TensorLease second(std::move(first));
    CHECK(second && !first);
    CHECK(second.read(0, 1, result));
    TensorLease third;
    third = std::move(second);
    CHECK(third && !second);
    CHECK(!third.read(1, pageSize, result));
    CHECK(!third.read(0, 1, nullptr));
    CHECK(third.read(0, 0, nullptr));
    return 0;
}
