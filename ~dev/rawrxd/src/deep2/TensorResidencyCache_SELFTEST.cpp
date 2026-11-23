#include "TensorResidencyCache.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <thread>
#include <vector>

int main() {
    Deep2::TensorResidencyCache cache(1u << 20, 1024);
    std::vector<uint8_t> source(8192);
    for (size_t i = 0; i < source.size(); ++i)
        source[i] = static_cast<uint8_t>((i / 512) & 3u ? 0x5a : 0x11);
    assert(cache.Register("weights.layer0", source.data(), source.size()));
    assert(cache.Contains("weights.layer0"));

    auto stats = cache.GetStats();
    assert(stats.tensorCount == 1);
    assert(stats.chunkCount == 8);
    assert(stats.storedBytes < stats.logicalBytes);

    // Read a range crossing multiple independent chunks.
    std::vector<uint8_t> tile(2700, 0);
    assert(cache.ReadRange("weights.layer0", 777, tile.size(), tile.data()));
    assert(std::equal(tile.begin(), tile.end(), source.begin() + 777));

    // Invalid range and missing key must not mutate the destination.
    std::vector<uint8_t> untouched(16, 0xa5);
    assert(!cache.ReadRange("weights.layer0", source.size() - 2, 4, untouched.data()));
    assert(std::all_of(untouched.begin(), untouched.end(),
                       [](uint8_t v) { return v == 0xa5; }));
    assert(!cache.ReadRange("missing", 0, untouched.size(), untouched.data()));

    // Incompressible input is rejected rather than retained as duplicate raw data.
    std::vector<uint8_t> noisy(2048);
    uint32_t state = 0x9e3779b9u;
    for (auto& value : noisy) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        value = static_cast<uint8_t>(state);
    }
    assert(!cache.Register("noisy", noisy.data(), noisy.size()));
    assert(!cache.Contains("noisy"));

    // Concurrent readers share immutable encoded chunks safely.
    std::vector<uint8_t> a(2048), b(2048);
    std::thread t0([&] { assert(cache.ReadRange("weights.layer0", 0, a.size(), a.data())); });
    std::thread t1([&] { assert(cache.ReadRange("weights.layer0", 4096, b.size(), b.data())); });
    t0.join(); t1.join();
    assert(std::equal(a.begin(), a.end(), source.begin()));
    assert(std::equal(b.begin(), b.end(), source.begin() + 4096));

    stats = cache.GetStats();
    assert(stats.cacheHits >= 3);
    assert(stats.cacheMisses >= 1);
    assert(stats.bytesDecoded >= tile.size() + a.size() + b.size());

    cache.SetBudget(1);
    assert(!cache.Contains("weights.layer0"));
    assert(cache.GetStats().storedBytes == 0);
    assert(cache.GetStats().evictions == 1);
    return 0;
}
