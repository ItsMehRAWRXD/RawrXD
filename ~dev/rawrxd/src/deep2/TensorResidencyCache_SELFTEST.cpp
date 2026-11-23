#include "TensorResidencyCache.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <limits>
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

    // Explicit lossy FP32 -> FP16 residency: half-size storage and
    // conversion of only the requested range, including a chunk boundary.
    std::vector<float> fp32(2048);
    for (size_t i = 0; i < fp32.size(); ++i)
        fp32[i] = std::sin(static_cast<float>(i) * 0.013f) * 3.0f;
    fp32[20] = std::numeric_limits<float>::infinity();
    fp32[21] = -std::numeric_limits<float>::infinity();
    fp32[22] = std::numeric_limits<float>::quiet_NaN();
    assert(cache.RegisterF32AsF16("fp32.norm", fp32.data(), fp32.size()));
    std::vector<float> fp16Decoded(17);
    assert(cache.ReadF32Range("fp32.norm", 509, fp16Decoded.size(),
                              fp16Decoded.data()));
    for (size_t i = 0; i < fp16Decoded.size(); ++i) {
        const float expected = fp32[509 + i];
        if (std::isnan(expected)) assert(std::isnan(fp16Decoded[i]));
        else if (std::isinf(expected)) assert(fp16Decoded[i] == expected);
        else assert(std::fabs(fp16Decoded[i] - expected) < 0.002f);
    }
    const auto fpStats = cache.GetStats();
    assert(fpStats.logicalBytes >= fp32.size() * sizeof(uint16_t));
    assert(fpStats.storedBytes < fpStats.logicalBytes + source.size());

    cache.SetBudget(1);
    assert(!cache.Contains("weights.layer0"));
    assert(cache.GetStats().storedBytes == 0);
    assert(cache.GetStats().evictions == 1);
    return 0;
}
