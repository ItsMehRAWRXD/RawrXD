// Portable microbenchmark: cost of repeated Q4_K column slice repacking.
// Measures only CPU repack overhead, never claims an end-to-end model TPS result.
#include "../~dev/rawrxd/src/deep2/Deep2Q4KColumnSlices.hpp"
#include <chrono>
#include <cstdio>
#include <vector>

int main() {
    constexpr size_t rows = 1024, cols = 256 * 128;
    constexpr unsigned iterations = 40;
    std::vector<uint8_t> source(rows * (cols / 256) * 144, 0x65);
    Deep2::Q4KColumnSliceCache cold, reused;
    using Clock = std::chrono::steady_clock;
    const auto start = Clock::now();
    for (unsigned n = 0; n < iterations; ++n) {
        cold.clear();
        const auto slice = cold.get(source.data(), source.size(), rows,
                                    cols, 64 + (n % 2));
        if (!slice) return 1;
    }
    const auto midpoint = Clock::now();
    for (unsigned n = 0; n < iterations; ++n) {
        const auto slice = reused.get(source.data(), source.size(), rows,
                                      cols, 64 + (n % 2));
        if (!slice) return 2;
    }
    const auto finish = Clock::now();
    if (cold.rebuilds() != iterations || reused.rebuilds() != 1) return 3;
    const double repackMs =
        std::chrono::duration<double, std::milli>(midpoint - start).count();
    const double reuseMs =
        std::chrono::duration<double, std::milli>(finish - midpoint).count();
    std::printf("Q4K_REPACK_BASELINE_MS=%.3f\n", repackMs);
    std::printf("Q4K_REPACK_REUSED_MS=%.3f\n", reuseMs);
    std::printf("Q4K_REPACK_BASELINE_COUNT=%zu\n", cold.rebuilds());
    std::printf("Q4K_REPACK_REUSED_COUNT=%zu\n", reused.rebuilds());
    std::printf("Q4K_CPU_REPACK_SPEEDUP=%.3f\n",
                reuseMs > 0.0 ? repackMs / reuseMs : 0.0);
    std::puts("NOTE: CPU repacking microbenchmark; not GPU inference TPS.");
    return 0;
}
