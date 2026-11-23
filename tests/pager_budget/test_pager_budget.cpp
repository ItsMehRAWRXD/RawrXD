#include "ShardPager.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
int main() {
    constexpr std::size_t page = 4096;
    std::vector<std::uint8_t> source(page * 17);
    for (std::size_t i = 0; i < source.size(); ++i)
        source[i] = static_cast<std::uint8_t>(i * 17 + (i >> 7));
    deep2::PageCache cache(page * 2, page);
    cache.setReader([&](std::uint32_t, std::uint64_t pageNo,
                        std::uint8_t* dst, std::size_t n) {
        if (pageNo >= 17 || n != page) return false;
        std::memcpy(dst, source.data() + pageNo * page, n);
        return true;
    });
    std::vector<std::uint8_t> output(source.size());
    assert(cache.readRange(0, 0, output.size(), output.data()));
    assert(output == source);
    assert(cache.residentBytes() <= cache.capacityBytes());
    assert(cache.pageCount() <= 2);
    assert(!cache.readRange(0, UINT64_MAX - 5, 10, output.data()));
    assert(!cache.readRange(0, 0, 1, nullptr));
    {
        deep2::TensorLease lease(cache, 0, 0, page);
        assert(lease);
        deep2::TensorLease moved(std::move(lease));
        assert(moved);
        assert(!lease);
        assert(moved.direct(0, 32));
        cache.evictUnleasedAll();
        assert(cache.leaseCount() == 1);
    }
    assert(cache.leaseCount() == 0);
    cache.evictUnleasedAll();
    assert(cache.residentBytes() == 0);
    std::cout << "pager budget and lease tests passed\n";
}
