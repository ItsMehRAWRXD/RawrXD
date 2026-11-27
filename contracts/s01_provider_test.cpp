// s01_provider_test.cpp — CPU test for the demand-driven expert provider.
#include "reap/ReapExpertProvider.hpp"
#include <cstdio>
#include <vector>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    SliceTensorDesc t; t.name = "blk.0.experts"; t.dims = {16, 4}; t.bytes = 4 * 16; // 4 experts, 16 B each
    std::vector<uint8_t> src(t.bytes);
    for (size_t i = 0; i < src.size(); ++i) src[i] = (uint8_t)(i + 1);
    ExpertProvider p; p.Register(0, t, src.data());
    std::vector<uint8_t> dst(64);
    ck(p.Acquire(0, 2, dst.data(), dst.size()), "acquire_expert2");
    // expert 2 offset = 2*16 = 32; bytes 32..47 => values 33..48
    ck(dst[0] == 33 && dst[15] == 48, "expert2_bytes");
    ck(p.AcquireCount() == 1, "acquire_count");
    ck(p.AcquiredBytes() == 16, "acquired_bytes");
    ck(!p.Acquire(0, 9, dst.data(), dst.size()), "reject_oob");
    ck(!p.Acquire(1, 0, dst.data(), dst.size()), "reject_missing_layer");
    std::printf("FAILS=%d\nS01_PROVIDER=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}