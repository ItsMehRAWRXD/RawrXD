// s02p_pipeline_test.cpp — CPU test: cache-aware streaming (provider+residency).
#include "reap/ReapStreamingPipeline.hpp"
#include <cstdio>
#include <vector>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    SliceTensorDesc t; t.name = "blk.0.experts"; t.dims = {16, 4}; t.bytes = 4 * 16; // 4 experts, 16B
    std::vector<uint8_t> src(64);
    for (size_t i = 0; i < src.size(); ++i) src[i] = (uint8_t)(i + 1);
    StreamingPipeline p(64, 16);   // budget 64B = 4 experts
    p.Register(0, t, src.data());
    const uint8_t* b0 = nullptr; const uint8_t* b1 = nullptr;
    ck(p.Acquire(0, 0, &b0), "acquire0");
    ck(b0 && b0[0] == 1, "bytes0");
    ck(p.Acquire(0, 0, &b1), "acquire0_again");
    ck(b0 == b1, "cache_hit_same_ptr");
    ck(p.Hits() == 1 && p.Misses() == 1, "hit_miss_count");
    ck(p.ResidencyUsed() == 16, "residency16");
    std::printf("FAILS=%d\nS02P_PIPELINE=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}