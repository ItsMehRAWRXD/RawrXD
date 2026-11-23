#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include "brutal_gzip.h"

using namespace std::chrono;

int main() {
    const size_t len = 1048576; // 1 MB
    std::vector<char> src(len);
    std::mt19937 rng(42);
    std::generate(src.begin(), src.end(), [&](){ return (char)rng(); });

    printf("Benchmarking deflate_brutal_masm with 1MB random data...\n");
    fflush(stdout);

    // Warmup
    size_t out_len = 0;
    void* out = deflate_brutal_masm(src.data(), len, &out_len);
    if (!out) {
        printf("Allocation failed!\n");
        return 1;
    }
    printf("Warmup done. Out ptr: %p, Len: %zu\n", out, out_len);
    fflush(stdout);
    free(out);

    // Measure
    auto t0 = high_resolution_clock::now();
    out = deflate_brutal_masm(src.data(), len, &out_len);
    auto t1 = high_resolution_clock::now();
    if (!out) {
        printf("Compression allocation failed!\\n");
        return 1;
    }
    const size_t expected_len = len + 5 * ((len + 65534) / 65535) + 18;
    if (out_len != expected_len) {
        printf("Unexpected stored-gzip size: %zu (expected %zu)\\n", out_len, expected_len);
        free(out);
        return 2;
    }

    double ms_asm = duration<double, std::milli>(t1 - t0).count();
    free(out);

    printf("Brutal MASM: %.2f ms\n", ms_asm);
    printf("Target (Qt): ~50.00 ms\n");
    printf("Speedup vs Target: %.2fx\n", 50.0 / ms_asm);

    if (ms_asm <= 5.0) {
        printf("SUCCESS: Latency <= 5ms\n");
    } else {
        printf("WARNING: Latency > 5ms\n");
    }

    return 0;
}
