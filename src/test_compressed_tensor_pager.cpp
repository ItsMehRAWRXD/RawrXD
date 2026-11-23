#include "CompressedTensorPager.hpp"

#include <cstdint>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <vector>

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL line " << __LINE__ << ": " #x "\n"; ++failures; } } while (0)

int main() {
    constexpr uint64_t pageSize = 64 * 1024;
    std::vector<uint8_t> source(static_cast<size_t>(pageSize * 2));
    std::fill(source.begin(), source.begin() + pageSize, uint8_t('A'));

    // Deterministic high-entropy page exercises the raw fallback.
    uint32_t state = 0x12345678u;
    for (size_t i = static_cast<size_t>(pageSize); i < source.size(); ++i) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        source[i] = static_cast<uint8_t>(state & 0xffu);
    }

    uint64_t readerCalls = 0;
    deep2::CompressedTensorPager pager(source.size(),
        [&](uint64_t offset, uint64_t count, uint8_t* out) {
            ++readerCalls;
            if (offset > source.size() || count > source.size() - offset) return false;
            std::memcpy(out, source.data() + offset, static_cast<size_t>(count));
            return true;
        }, static_cast<size_t>(pageSize), static_cast<size_t>(pageSize * 2));

    // Small subrange from a compressed page: output must match source exactly.
    std::vector<uint8_t> got(113);
    CHECK(pager.read(901, got.size(), got.data()));
    CHECK(std::memcmp(got.data(), source.data() + 901, got.size()) == 0);

    // Cross-page range: both compressed and raw page representations are read.
    std::vector<uint8_t> crossing(257);
    const uint64_t crossingOffset = pageSize - 91;
    CHECK(pager.read(crossingOffset, crossing.size(), crossing.data()));
    CHECK(std::memcmp(crossing.data(), source.data() + crossingOffset, crossing.size()) == 0);

    // Cache hits must not refetch source pages.
    const uint64_t callsAfterMisses = readerCalls;
    CHECK(pager.read(1000, 64, got.data()));
    CHECK(readerCalls == callsAfterMisses);

    const auto stats = pager.stats();
    CHECK(stats.logicalBytes == source.size());
    CHECK(stats.compressedPages >= 1);
    CHECK(stats.rawPages >= 1);
    CHECK(stats.residentBytes <= pageSize * 2);
    CHECK(!pager.read(source.size() - 1, 2, got.data()));
    CHECK(pager.read(source.size(), 0, nullptr));

    std::cout << "compressed_tensor_pager failures=" << failures
              << " encoded_resident=" << stats.residentBytes
              << " compressed_pages=" << stats.compressedPages
              << " raw_pages=" << stats.rawPages << "\n";
    return failures ? 1 : 0;
}
