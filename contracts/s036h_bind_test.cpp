// s036h_bind_test.cpp — CPU test: descriptor binding validation.
#include "reap/ReapDescriptorBind.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    auto b = BindTransformed(123, 0, 32, 16, true, 64);   // offset32 + 16 <= 64
    ck(b.valid, "bind_ok");
    ck(b.range==16 && b.binding==0, "range_binding");
    ck(!BindTransformed(123,0,32,16,false,64).valid, "invalid_selection_failclosed");
    ck(!BindTransformed(123,0,60,16,true,64).valid, "out_of_range_failclosed");   // 60+16>64
    ck(!BindTransformed(123,0,0,0,true,64).valid, "zero_size_failclosed");
    std::printf("FAILS=%d\nS036H_BIND=%s\n", fails, fails?"FAIL":"PASS");
    return fails?1:0;
}