// RAWRXD REAP V02: CPU regression for the storage-independent expert slicer.
#include "deep2/ReapExpertSlice.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;

static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    std::string e;
    ExpertSliceLayout L;
    // 4 experts, 100 bytes each => 400 total; retain {0,2,3}.
    std::vector<uint64_t> dims{16, 4};
    std::vector<uint32_t> keep{0, 2, 3};
    CHECK(ComputeExpertSliceLayout(dims, 400, keep, L, e), "compute ok");
    CHECK(L.stride == 100, "stride 100");
    CHECK(L.totalBytes == 300, "total 300 (3 retained)");
    CHECK(L.slices.size() == 3, "3 slices");
    CHECK(L.slices[0].offset == 0 && L.slices[1].offset == 200 && L.slices[2].offset == 300,
          "offsets 0/200/300 (original order preserved)");
    // Non-divisible -> fail closed.
    CHECK(!ComputeExpertSliceLayout(dims, 401, keep, L, e), "non-divisible rejected");
    // Out-of-range retained -> fail closed.
    std::vector<uint32_t> bad{0, 4};
    CHECK(!ComputeExpertSliceLayout(dims, 400, bad, L, e), "out-of-range rejected");
    // Empty dims -> fail closed.
    std::vector<uint64_t> none;
    CHECK(!ComputeExpertSliceLayout(none, 400, keep, L, e), "empty dims rejected");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}