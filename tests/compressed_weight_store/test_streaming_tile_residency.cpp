// Regression: compressed weights remain encoded across many inference-style tile reads.
// This test measures store-owned residency, not total process RSS or GPU VRAM.
#include "deep2/compression/CompressedWeightStore.hpp"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
using rawrxd::compression::CompressedWeightStore;
static bool require(bool ok, const char* what) {
    if (!ok) std::fprintf(stderr, "FAIL: %s\n", what);
    return ok;
}
int main() {
    constexpr std::size_t block = 4096, budget = 2 * block;
    constexpr std::size_t tensorBytes = 8 * 1024 * 1024;
    CompressedWeightStore store(budget, block, tensorBytes);
    std::vector<std::uint8_t> raw(tensorBytes);
    for (std::size_t i = 0; i < raw.size(); ++i)
        raw[i] = static_cast<std::uint8_t>((i / 64) % 7);
    std::string error;
    if (!require(store.addTensor("synthetic.layer.weight", raw.data(), raw.size(),
                                 &error, rawrxd::compression::GGML_TYPE_OPAQUE, true),
                 "compressed tensor admission")) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return 1;
    }
    auto stats = store.stats();
    if (!require(stats.compressed_bytes < stats.raw_bytes, "encoded payload smaller than raw")) return 2;
    if (!require(stats.cached_decoded_bytes == 0, "no eager decoded residency")) return 3;
    if (!require(stats.resident_bytes_estimate < stats.raw_bytes,
                 "encoded store and metadata smaller than original tensor")) return 4;
    std::vector<std::uint8_t> tile(777);
    std::uint64_t checks = 0;
    for (std::size_t offset = 0; offset < tensorBytes; offset += tile.size()) {
        const auto length = std::min(tile.size(), tensorBytes - offset);
        if (!require(store.readRange("synthetic.layer.weight", offset, tile.data(), length, &error),
                     "tile decode")) return 5;
        if (!require(std::equal(tile.begin(), tile.begin() + length, raw.begin() + offset),
                     "tile matches independent source")) return 6;
        ++checks;
        stats = store.stats();
        if (!require(stats.cached_decoded_bytes <= budget,
                     "decoded cache remains within budget")) return 7;
    }
    store.clearDecodedCache();
    stats = store.stats();
    if (!require(stats.cached_decoded_bytes == 0, "cache clear releases decoded blocks")) return 8;
    if (!require(stats.cache_misses > 0 && checks > 1000, "inference-style tile streaming exercised")) return 9;
    std::printf("COMPRESSED_TILE_RESIDENCY=PASS raw=%llu encoded=%llu resident_estimate=%llu tiles=%llu\n",
        static_cast<unsigned long long>(stats.raw_bytes),
        static_cast<unsigned long long>(stats.compressed_bytes),
        static_cast<unsigned long long>(stats.resident_bytes_estimate),
        static_cast<unsigned long long>(checks));
    return 0;
}
