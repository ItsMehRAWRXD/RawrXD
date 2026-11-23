#include "TensorResidencyCache.hpp"
#include <algorithm>
#include <atomic>

#include <cstdint>
#include <cstring>
#include <cmath>
#include <limits>
#include <thread>
#include <vector>

#define CHECK(expr) do { if (!(expr)) return __LINE__; } while (0)

int main() {
    Deep2::TensorResidencyCache cache(1u << 20, 1024);
    std::vector<uint8_t> source(8192);
    for (size_t i = 0; i < source.size(); ++i)
        source[i] = static_cast<uint8_t>((i / 512) & 3u ? 0x5a : 0x11);
    CHECK(cache.Register("weights.layer0", source.data(), source.size()));
    CHECK(cache.Contains("weights.layer0"));

    auto stats = cache.GetStats();
    CHECK(stats.tensorCount == 1);
    CHECK(stats.chunkCount == 8);
    CHECK(stats.storedBytes < stats.logicalBytes);

    // Read a range crossing multiple independent chunks.
    std::vector<uint8_t> tile(2700, 0);
    CHECK(cache.ReadRange("weights.layer0", 777, tile.size(), tile.data()));
    CHECK(std::equal(tile.begin(), tile.end(), source.begin() + 777));

    // Matrix-style row-at-a-time reads match the exact packed source rows.
    std::vector<uint8_t> rowTile(1024);
    for (size_t row = 0; row < 8; ++row) {
        CHECK(cache.ReadRange("weights.layer0", row * rowTile.size(),
                              rowTile.size(), rowTile.data()));
        CHECK(std::equal(rowTile.begin(), rowTile.end(),
                         source.begin() + row * rowTile.size()));
    }

    // Invalid range and missing key must not mutate the destination.
    std::vector<uint8_t> untouched(16, 0xa5);
    CHECK(!cache.ReadRange("weights.layer0", source.size() - 2, 4, untouched.data()));
    CHECK(std::all_of(untouched.begin(), untouched.end(),
                       [](uint8_t v) { return v == 0xa5; }));
    CHECK(!cache.ReadRange("missing", 0, untouched.size(), untouched.data()));

    // Incompressible input is rejected rather than retained as duplicate raw data.
    std::vector<uint8_t> noisy(2048);
    uint32_t state = 0x9e3779b9u;
    for (auto& value : noisy) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        value = static_cast<uint8_t>(state);
    }
    CHECK(!cache.Register("noisy", noisy.data(), noisy.size()));
    CHECK(!cache.Contains("noisy"));

    // Concurrent readers share immutable encoded chunks safely.
    std::vector<uint8_t> a(2048), b(2048);
    std::atomic<bool> readersOk{true};
    std::thread t0([&] {
        if (!cache.ReadRange("weights.layer0", 0, a.size(), a.data()))
            readersOk.store(false, std::memory_order_relaxed);
    });
    std::thread t1([&] {
        if (!cache.ReadRange("weights.layer0", 4096, b.size(), b.data()))
            readersOk.store(false, std::memory_order_relaxed);
    });
    t0.join(); t1.join();
    CHECK(readersOk.load(std::memory_order_relaxed));
    CHECK(std::equal(a.begin(), a.end(), source.begin()));
    CHECK(std::equal(b.begin(), b.end(), source.begin() + 4096));

    stats = cache.GetStats();
    CHECK(stats.cacheHits >= 3);
    CHECK(stats.cacheMisses >= 1);
    CHECK(stats.bytesDecoded >= tile.size() + a.size() + b.size());

    // Explicit lossy FP32 -> FP16 residency: half-size storage and
    // conversion of only the requested range, including a chunk boundary.
    std::vector<float> fp32(2048);
    for (size_t i = 0; i < fp32.size(); ++i)
        fp32[i] = std::sin(static_cast<float>(i) * 0.013f) * 3.0f;
    fp32[20] = std::numeric_limits<float>::infinity();
    fp32[21] = -std::numeric_limits<float>::infinity();
    fp32[22] = std::numeric_limits<float>::quiet_NaN();
    fp32[23] = 5.960464477539063e-8f; // smallest positive binary16 subnormal
    CHECK(cache.RegisterF32AsF16("fp32.norm", fp32.data(), fp32.size()));
    std::vector<float> fp16Decoded(17);
    CHECK(cache.ReadF32Range("fp32.norm", 509, fp16Decoded.size(),
                              fp16Decoded.data()));
    for (size_t i = 0; i < fp16Decoded.size(); ++i) {
        const float expected = fp32[509 + i];
        if (std::isnan(expected)) CHECK(std::isnan(fp16Decoded[i]));
        else if (std::isinf(expected)) CHECK(fp16Decoded[i] == expected);
        else CHECK(std::fabs(fp16Decoded[i] - expected) < 0.002f);
    }
    uint16_t rawHalf[4] = {};
    CHECK(cache.ReadF16Range("fp32.norm", 20, 4, rawHalf));
    CHECK(rawHalf[0] == 0x7c00u);
    CHECK(rawHalf[1] == 0xfc00u);
    CHECK((rawHalf[2] & 0x7c00u) == 0x7c00u && (rawHalf[2] & 0x03ffu));
    CHECK(rawHalf[3] == 0x0001u);
    float special[4] = {};
    CHECK(cache.ReadF32Range("fp32.norm", 20, 4, special));
    CHECK(std::isinf(special[0]) && special[0] > 0.0f);
    CHECK(std::isinf(special[1]) && special[1] < 0.0f);
    CHECK(std::isnan(special[2]));
    CHECK(special[3] == 5.960464477539063e-8f);
    const auto fpStats = cache.GetStats();
    CHECK(fpStats.logicalBytes == source.size() +
          fp32.size() * sizeof(uint16_t));
    CHECK(fpStats.logicalBytes == source.size() +
          (fp32.size() * sizeof(float)) / 2u);
    CHECK(fpStats.storedBytes < fpStats.logicalBytes);

    cache.SetBudget(1);
    CHECK(!cache.Contains("weights.layer0"));
    CHECK(cache.GetStats().storedBytes == 0);
    CHECK(cache.GetStats().evictions == 2);
    return 0;
}
