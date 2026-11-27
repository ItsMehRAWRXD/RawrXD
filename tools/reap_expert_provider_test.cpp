// RAWRXD REAP SC02: CPU regression for the AUTHORITATIVE expert provider
// (src/reap/ReapExpertProvider) — demand-driven ForEachRetained + bounded window.
#include "reap/ReapExpertProvider.hpp"
#include <cstdio>
#include <string>
#include <vector>

using namespace RawrXD::Reap;
static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    const uint64_t B = 100, E = 4;
    std::vector<uint8_t> bank(E * B);
    for (uint64_t x = 0; x < E; ++x)
        for (uint64_t i = 0; i < B; ++i) bank[x * B + i] = static_cast<uint8_t>(x);

    ExpertProvider p;
    SliceTensorDesc d;
    d.name = "ffn_up_exps";
    d.dims = {16, E};
    d.bytes = E * B;
    p.Register(0, d, bank.data());

    std::vector<uint32_t> keep{1, 3};
    std::vector<uint32_t> order;
    bool contentOk = true;
    auto sink = [&](uint32_t idx, const uint8_t* dd, uint64_t len) {
        order.push_back(idx);
        for (uint64_t i = 0; i < len; ++i) if (dd[i] != idx) contentOk = false;
    };

    CHECK(p.ForEachRetained(0, keep, /*window=*/B, sink), "foreach ok");
    CHECK(order.size() == 2 && order[0] == 1 && order[1] == 3, "retained order 1,3");
    CHECK(contentOk, "each expert content matches its index");
    CHECK(p.AcquireCount() == 1, "one demand acquisition recorded");
    // Window budget exceeded -> fail closed.
    CHECK(!p.ForEachRetained(0, keep, /*window=*/50, sink), "window budget enforced");
    // Invalid layer -> fail closed.
    CHECK(!p.ForEachRetained(9, keep, B, sink), "invalid layer rejected");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}