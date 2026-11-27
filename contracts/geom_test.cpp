// geom_test.cpp — CPU test for expert-axis + quant-block geometry validation.
#include "reap/ReapExpertGeometry.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    SliceTensorDesc t; t.name = "blk.0.experts"; t.dims = {4096, 8}; t.bytes = 8 * 4096; // stride 4096, block 32
    auto r = ValidateExpertGeometry(t, 32);
    ck(r.ok, "aligned_ok");
    ck(r.stride == 4096 && r.blockBytes == 32, "stride_block");
    SliceTensorDesc mis = t; mis.bytes = 8 * 4096 + 8;   // misaligned stride
    ck(!ValidateExpertGeometry(mis, 32).ok, "reject_misaligned");
    SliceTensorDesc bad; bad.name="x"; bad.dims={8}; bad.bytes=8*4096; // expert dim not last / bytes%8==0 but stride huge... still aligned? 4096%32==0
    auto r2 = ValidateExpertGeometry(bad, 32); ck(r2.ok, "single_dim_ok");
    std::printf("FAILS=%d\nGEOM=%s\n", fails, fails ? "FAIL" : "PASS");
    return fails ? 1 : 0;
}