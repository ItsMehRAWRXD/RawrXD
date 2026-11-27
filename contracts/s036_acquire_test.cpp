// s036_acquire_test.cpp — CPU test: AcquireTransformed identity binding.
#include "reap/ReapTransformAcquire.hpp"
#include <cstdio>
#include <vector>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    SliceTensorDesc t; t.name="blk.0.experts"; t.dims={16,4}; t.bytes=64;
    std::vector<uint8_t> src(64); for (size_t i=0;i<64;++i) src[i]=(uint8_t)(i+1);
    ExpertProvider prov; prov.Register(0, t, src.data());
    std::vector<uint8_t> dst(64);
    uint64_t fp = SelectionFingerprint({{0,{2}}}, 1, 64, 1);
    auto r = AcquireTransformed(prov, 0, 2, dst.data(), dst.size(), 1, fp, true, 1);
    ck(r.ok, "acquire_ok");
    ck(dst[0] == 33, "expert2_bytes");   // offset 2*16=32 -> value 33
    ck(r.identity == CacheIdentity(((uint64_t)0<<32)|2, fp, true), "identity_bound");
    auto bad = AcquireTransformed(prov, 0, 2, dst.data(), dst.size(), 1, 0, false, 1);
    ck(!bad.ok, "invalid_selection_failclosed");
    std::printf("FAILS=%d\nS036_ACQUIRE=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}