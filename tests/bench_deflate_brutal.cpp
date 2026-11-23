#include <cstdio>
#include <cstdlib>
#include <cstddef>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>

extern "C" void* deflate_brutal_masm(const void* src, std::size_t len,
                                    std::size_t* out_len);

using namespace std::chrono;

int main() {
    constexpr std::size_t len = 1048576;
    std::vector<unsigned char> src(len);
    std::mt19937 rng(42);
    std::generate(src.begin(), src.end(),
                  [&]() { return static_cast<unsigned char>(rng()); });

    std::puts("Benchmarking checksum-finalized MASM gzip stored-block encoder (1 MiB random input)...");
    std::size_t out_len = 0;
    void* warmup = deflate_brutal_masm(src.data(), src.size(), &out_len);
    if (!warmup) {
        std::puts("FAIL: encoder returned null");
        return 1;
    }
    std::printf("Warmup output bytes: %zu\n", out_len);
    std::free(warmup);

    constexpr int iterations = 10;
    double total_ms = 0.0;
    std::size_t last_size = 0;
    for (int i = 0; i < iterations; ++i) {
        auto begin = steady_clock::now();
        void* output = deflate_brutal_masm(src.data(), src.size(), &last_size);
        auto end = steady_clock::now();
        if (!output || last_size == 0) {
            std::free(output);
            std::puts("FAIL: encoder failed during timed iteration");
            return 2;
        }
        total_ms += duration<double, std::milli>(end - begin).count();
        std::free(output);
    }

    const double average_ms = total_ms / iterations;
    const double ratio = static_cast<double>(last_size) / src.size();
    std::printf("Average latency: %.3f ms (%d iterations)\n", average_ms, iterations);
    std::printf("Encoded bytes: %zu; output/input ratio: %.5fx\n", last_size, ratio);
    std::printf("Throughput: %.2f MiB/s\n",
        (static_cast<double>(src.size()) / (1024.0 * 1024.0)) /
        (average_ms / 1000.0));
    std::puts("Note: RFC 1951 stored blocks prioritize low latency; they do not entropy-compress random input.");
    return 0;
}
