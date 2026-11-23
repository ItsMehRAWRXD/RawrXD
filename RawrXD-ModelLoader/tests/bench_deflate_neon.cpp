#include "gzip_stored_validator.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <random>
#include <chrono>

extern "C" void* deflate_neon(const void* src, std::size_t len,
                              std::size_t* out_len);

int main() {
    using clock = std::chrono::high_resolution_clock;
    constexpr std::size_t len = 1048576;
    std::vector<std::uint8_t> source(len);
    std::mt19937 rng(42);
    for (auto& value : source) value = static_cast<std::uint8_t>(rng());

    std::size_t outputSize = 0;
    void* output = deflate_neon(source.data(), source.size(), &outputSize);
    if (!output || !rawrxd_test::validateStoredGzip(
            static_cast<const std::uint8_t*>(output), outputSize,
            source.data(), source.size())) {
        std::fprintf(stderr, "FAIL: NEON gzip stream failed roundtrip validation\\n");
        std::free(output);
        return 1;
    }
    std::free(output);

    const auto start = clock::now();
    output = deflate_neon(source.data(), source.size(), &outputSize);
    const auto stop = clock::now();
    if (!output) return 1;
    const double ms = std::chrono::duration<double, std::milli>(stop - start).count();
    const bool valid = rawrxd_test::validateStoredGzip(
        static_cast<const std::uint8_t*>(output), outputSize,
        source.data(), source.size());
    std::free(output);
    if (!valid) return 1;

    std::printf("Stored-block gzip packaging: %.3f ms\\n", ms);
    std::printf("Input: %zu bytes, output: %zu bytes, expansion: %.2f%%\\n",
        len, outputSize,
        100.0 * (static_cast<double>(outputSize) / len - 1.0));
    std::puts("NOTE: DEFLATE BTYPE=00 copies data; this is not a compression-ratio benchmark.");
    std::puts("NEON_GZIP_BENCH_ROUNDTRIP=PASS");
    return 0;
}
