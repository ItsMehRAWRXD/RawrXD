#include "../../src/deep2/DecodedWeightTileCache.hpp"
#include <cassert>
#include <algorithm>
#include <atomic>
#include <vector>
#include <iostream>
int main() {
    std::vector<float> weights(8192);
    for (size_t i=0; i<weights.size(); ++i)
        weights[i] = float(int(i % 19) - 9);
    Deep2::TensorResidencyCache source(1 << 20);
    std::atomic<unsigned> reads{0};
    assert(source.RegisterF32FromReader("w", weights.size(), 0.0f,
        [&](size_t first, size_t count, float* dst) {
            ++reads;
            std::copy_n(weights.data()+first, count, dst);
            return true;
        }, 1024));
    Deep2::DecodedWeightTileCache tiles(source, 4096);
    auto first = tiles.Acquire("w", 100, 512);
    assert(first && std::equal(first->begin(), first->end(), weights.begin()+100));
    const auto before = source.GetStats().bytesDecoded;
    auto again = tiles.Acquire("w", 100, 512);
    assert(again == first);
    assert(source.GetStats().bytesDecoded == before);
    assert(tiles.GetStats().hits == 1);
    auto second = tiles.Acquire("w", 2048, 512);
    auto third = tiles.Acquire("w", 4096, 512);
    assert(second && third);
    assert(tiles.GetStats().residentBytes <= 4096);
    assert(tiles.GetStats().evictions >= 1);
    assert(tiles.GetStats().totalLiveDecodedBytes >= 3 * 512 * sizeof(float));
    // Existing leases remain valid after eviction and invalidation.
    assert((*first)[0] == weights[100]);
    tiles.Invalidate("w");
    assert(tiles.GetStats().residentBytes <= 4096);
    tiles.SetBudget(0);
    assert(tiles.GetStats().residentBytes == 0);
    assert(tiles.GetStats().totalLiveDecodedBytes >= 3 * 512 * sizeof(float));
    first.reset();
    again.reset();
    second.reset();
    third.reset();
    assert(tiles.GetStats().totalLiveDecodedBytes == 0);
    assert(!tiles.Acquire("missing", 0, 64));
    assert(!tiles.Acquire("w", weights.size(), 1));
    std::cout << "DECODED_TILE_REUSE=PASS\n";
}
