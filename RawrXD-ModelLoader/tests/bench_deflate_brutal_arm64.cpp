#include "gzip_stored_validator.hpp"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <random>
#include <chrono>

extern "C" void* deflate_brutal_neon(const void*, std::size_t, std::size_t*);

int main() {
    using clock = std::chrono::high_resolution_clock;
    const std::size_t len = 1u << 20;
    std::vector<std::uint8_t> src(len);
    std::mt19937 rng(42);
    for (auto& value : src) value = static_cast<std::uint8_t>(rng());

    std::size_t outLen = 0;
    void* out = deflate_brutal_neon(src.data(), src.size(), &outLen);
    if (!out || !rawrxd_test::validateStoredGzip(
            static_cast<const std::uint8_t*>(out), outLen, src.data(), src.size())) {
        std::fprintf(stderr, "FAIL: NEON output is not a valid roundtripping gzip stream\\n");
        std::free(out);
        return 1;
    }
    std::free(out);

    const auto start = clock::now();
    out = deflate_brutal_neon(src.data(), src.size(), &outLen);
    const auto stop = clock::now();
    if (!out) return 1;
    const double ms = std::chrono::duration<double, std::milli>(stop - start).count();
    const bool valid = rawrxd_test::validateStoredGzip(
        static_cast<const std::uint8_t*>(out), outLen, src.data(), src.size());
    std::free(out);
    if (!valid) return 1;

    std::printf("Stored-block gzip packaging: %.3f ms\\n", ms);
    std::printf("Input: %zu bytes, output: %zu bytes, expansion: %.2f%%\\n",
        len, outLen, 100.0 * (static_cast<double>(outLen) / len - 1.0));
    std::puts("NOTE: DEFLATE BTYPE=00 copies data; this is not a compression-ratio benchmark.");
    std::puts("BRUTAL_NEON_GZIP_BENCH_ROUNDTRIP=PASS");
    return 0;
}
