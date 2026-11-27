// RAWRXD REAP V03: CPU regression for the reusable in-memory expert transform.
#include "deep2/ReapExpertTransform.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;

static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    std::string e;
    // 4 experts x 100 bytes; each expert byte = its id.
    const uint64_t B = 100, E = 4;
    std::vector<uint8_t> src(E * B);
    for (uint64_t x = 0; x < E; ++x)
        for (uint64_t i = 0; i < B; ++i) src[x * B + i] = static_cast<uint8_t>(x);

    std::vector<uint64_t> dims{16, E};
    std::vector<uint32_t> keep{0, 2, 3};
    std::vector<uint8_t> dst;
    CHECK(TransformExpertTensor(dims, E * B, src.data(), keep, dst, e), "transform ok");
    CHECK(dst.size() == 3 * B, "size = 3*100");
    bool ok = true;
    for (uint64_t x = 0; x < 3; ++x)
        for (uint64_t i = 0; i < B; ++i)
            if (dst[x * B + i] != static_cast<uint8_t>(keep[x])) ok = false;
    CHECK(ok, "retained experts 0,2,3 concatenated in order (content equivalence)");
    // Fail-closed: out-of-range retained.
    std::vector<uint32_t> bad{0, 9};
    CHECK(!TransformExpertTensor(dims, E * B, src.data(), bad, dst, e), "out-of-range rejected");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}