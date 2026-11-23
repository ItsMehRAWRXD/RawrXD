#include "CompressedTensorPager.hpp"

#include <cstdint>
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

    std::atomic<uint64_t> readerCalls{0};
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
    const uint64_t callsAfterMisses = readerCalls.load();
    CHECK(pager.read(1000, 64, got.data()));
    CHECK(readerCalls.load() == callsAfterMisses);

    // Multiple workers may read the same/different pages concurrently. The
    // shared page lease must keep data alive even if another reader evicts it.
    pager.clear();
    std::atomic<int> concurrentFailures{0};
    std::vector<std::thread> workers;
    for (int worker = 0; worker < 8; ++worker) {
        workers.emplace_back([&, worker]() {
            std::vector<uint8_t> local(4096);
            const uint64_t offset = (worker % 2 == 0)
                ? static_cast<uint64_t>(worker * 97)
                : pageSize + static_cast<uint64_t>(worker * 113);
            for (int repeat = 0; repeat < 4; ++repeat) {
                if (!pager.read(offset, local.size(), local.data()) ||
                    std::memcmp(local.data(), source.data() + offset, local.size()) != 0) {
                    ++concurrentFailures;
                    break;
                }
            }
        });
    }
    for (auto& worker : workers) worker.join();
    CHECK(concurrentFailures.load() == 0);

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
