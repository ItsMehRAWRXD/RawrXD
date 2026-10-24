// Tests real immutable column-slice cache, including repack hysteresis
// and snapshots retained by readers while another model is loaded.
#include "../~dev/rawrxd/src/deep2/Deep2Q4KColumnSlices.hpp"
#include <atomic>
#include <cassert>
#include <cstring>
#include <thread>
#include <vector>

static void check(const std::vector<uint8_t>& raw, size_t rows, size_t cols,
                  const Deep2::Q4KColumnSlices& slices) {
    constexpr size_t QB = 144;
    const size_t rowBytes = (cols / 256) * QB;
    const size_t left = (slices.cols0 / 256) * QB;
    const size_t right = rowBytes - left;
    assert(slices.cols0 + slices.cols1 == cols);
    assert(slices.w0.size() == rows * left);
    assert(slices.w1.size() == rows * right);
    for (size_t r = 0; r < rows; ++r) {
        assert(!std::memcmp(slices.w0.data() + r * left,
                            raw.data() + r * rowBytes, left));
        assert(!std::memcmp(slices.w1.data() + r * right,
                            raw.data() + r * rowBytes + left, right));
    }
}
int main() {
    constexpr size_t rows = 64, cols = 256 * 64, rowBytes = (cols / 256) * 144;
    std::vector<uint8_t> weights(rows * rowBytes);
    for (size_t i = 0; i < weights.size(); ++i)
        weights[i] = static_cast<uint8_t>((i * 17 + 29) & 255);
    Deep2::Q4KColumnSliceCache cache;
    assert(!cache.get(nullptr, weights.size(), rows, cols, 32));
    assert(!cache.get(weights.data(), weights.size() - 1, rows, cols, 32));
    assert(!cache.get(weights.data(), weights.size(), rows, cols, 0));
    assert(!cache.get(weights.data(), weights.size(), rows, cols, 64));
    auto first = cache.get(weights.data(), weights.size(), rows, cols, 32);
    assert(first);
    check(weights, rows, cols, *first);
    assert(cache.rebuilds() == 1);
    // A one-block speed estimate shift reuses the entire packed tensor.
    auto near = cache.get(weights.data(), weights.size(), rows, cols, 33);
    assert(near == first && cache.rebuilds() == 1);
    // A genuine geometry change rebuilds, but old readers remain valid.
    auto shifted = cache.get(weights.data(), weights.size(), rows, cols, 36);
    assert(shifted && shifted != first && cache.rebuilds() == 2);
    check(weights, rows, cols, *first);
    check(weights, rows, cols, *shifted);
    assert(cache.cachedBytes() == weights.size());
    cache.clear();
    assert(cache.cachedBytes() == 0);
    check(weights, rows, cols, *first);
    check(weights, rows, cols, *shifted);

    std::atomic<unsigned> good{0};
    std::vector<std::thread> callers;
    for (unsigned t = 0; t < 8; ++t) {
        callers.emplace_back([&, t] {
            for (unsigned i = 0; i < 100; ++i) {
                const uint32_t boundary = 28 + ((i + t) % 9);
                auto snapshot = cache.get(weights.data(), weights.size(),
                                          rows, cols, boundary);
                assert(snapshot);
                check(weights, rows, cols, *snapshot);
                good.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& t : callers) t.join();
    assert(good.load() == 800);

    // Cold-start contention for the same source must pack exactly once.
    Deep2::Q4KColumnSliceCache singleFlight;
    std::atomic<unsigned> ready{0};
    std::atomic<bool> release{false};
    std::vector<std::thread> simultaneous;
    for (unsigned t = 0; t < 12; ++t) {
        simultaneous.emplace_back([&] {
            ready.fetch_add(1, std::memory_order_release);
            while (!release.load(std::memory_order_acquire))
                std::this_thread::yield();
            auto snapshot = singleFlight.get(weights.data(), weights.size(),
                                             rows, cols, 32);
            assert(snapshot);
            check(weights, rows, cols, *snapshot);
        });
    }
    while (ready.load(std::memory_order_acquire) != 12)
        std::this_thread::yield();
    release.store(true, std::memory_order_release);
    for (auto& t : simultaneous) t.join();
    assert(singleFlight.rebuilds() == 1);
    assert(singleFlight.cachedBytes() == weights.size());

    // Eviction is safe for active readers: their immutable snapshot survives
    // removal of its cache entry, and the host working set stays bounded.
    constexpr size_t largeRows = 4096;
    Deep2::Q4KColumnSliceCache bounded(largeRows * rowBytes);
    std::vector<uint8_t> largeA(largeRows * rowBytes, 0x2a);
    std::vector<uint8_t> largeB(largeRows * rowBytes, 0x4b);
    auto held = bounded.get(largeA.data(), largeA.size(), largeRows, cols, 32);
    assert(held && bounded.cachedBytes() == largeA.size());
    auto next = bounded.get(largeB.data(), largeB.size(), largeRows, cols, 32);
    assert(next);
    assert(bounded.cachedBytes() == largeB.size());
    // Evicted source is repacked if requested again.
    auto restored = bounded.get(largeA.data(), largeA.size(), largeRows, cols, 32);
    assert(restored && bounded.rebuilds() == 3);
    assert(bounded.cachedBytes() == largeA.size());
    // No retained data if the configured budget is smaller than one tensor.
    Deep2::Q4KColumnSliceCache uncached(largeA.size() - 1);
    auto transient = uncached.get(largeA.data(), largeA.size(), largeRows, cols, 32);
    assert(transient && uncached.cachedBytes() == 0);
    assert(uncached.rebuilds() == 1);
    assert(uncached.get(largeA.data(), largeA.size(), largeRows, cols, 32));
    assert(uncached.rebuilds() == 2);
    assert(held->w0.front() == 0x2a);
    assert(next->w0.front() == 0x4b);



    // Concurrent invalidation cannot publish a snapshot built for a
    // previous cache generation. Source weights remain alive throughout.
    std::atomic<bool> start{false};
    std::thread invalidator([&] {
        while (!start.load(std::memory_order_acquire)) std::this_thread::yield();
        for (unsigned i = 0; i < 100; ++i) {
            cache.clear();
            std::this_thread::yield();
        }
    });
    start.store(true, std::memory_order_release);
    for (unsigned i = 0; i < 100; ++i) {
        const auto snapshot = cache.get(weights.data(), weights.size(),
                                        rows, cols, 32);
        if (snapshot) check(weights, rows, cols, *snapshot);
    }
    invalidator.join();
    auto final = cache.get(weights.data(), weights.size(), rows, cols, 32);
    assert(final);
    check(weights, rows, cols, *final);
    return 0;
}
