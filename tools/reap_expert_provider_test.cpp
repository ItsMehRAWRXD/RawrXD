// RAWRXD REAP (Streaming): CPU regression for the demand-driven expert provider.
// Verifies only requested expert ranges are read (no full-bank materialization).
#include "deep2/ReapExpertProvider.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;

static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    std::string e;
    const uint64_t B = 100, E = 4;
    std::vector<uint8_t> bank(E * B);
    for (uint64_t x = 0; x < E; ++x)
        for (uint64_t i = 0; i < B; ++i) bank[x * B + i] = static_cast<uint8_t>(x);

    std::vector<uint64_t> dims{16, E};
    std::vector<uint32_t> keep{1, 3};
    uint64_t bytesRead = 0;
    std::vector<uint32_t> order;
    bool contentOk = true;

    auto read = [&](uint64_t off, uint64_t len, uint8_t* dst) {
        bytesRead += len;
        for (uint64_t i = 0; i < len; ++i) dst[i] = bank[off + i];
        return true;
    };
    auto sink = [&](uint32_t idx, const uint8_t* d, uint64_t len) {
        order.push_back(idx);
        for (uint64_t i = 0; i < len; ++i) if (d[i] != idx) contentOk = false;
    };

    CHECK(ForEachRetainedExpert(dims, E * B, keep, /*window=*/B, read, sink, e), "provider ok");
    CHECK(order.size() == 2 && order[0] == 1 && order[1] == 3, "retained order 1,3");
    CHECK(bytesRead == 2 * B, "only 2 experts read (200), NOT full bank (400)");
    CHECK(contentOk, "each expert content matches its index");
    // Window budget exceeded -> fail closed.
    CHECK(!ForEachRetainedExpert(dims, E * B, keep, /*window=*/50, read, sink, e),
          "window budget enforced");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}