// s036i_disp_test.cpp — CPU test: dispatch request validation (fail-closed).
#include "reap/ReapDispatch.hpp"
#include <cstdio>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    auto b = BindTransformed(123, 0, 0, 16, true, 64);
    std::vector<uint32_t> map = {0, 2, 5};
    auto d = MakeDispatch(b, map, true);
    ck(d.valid, "dispatch_ok");
    ck(d.routerMapping.size()==3 && d.identity==123, "mapping_identity");
    ck(!MakeDispatch(b, map, false).valid, "invalid_selection_failclosed");
    ck(!MakeDispatch(b, {}, true).valid, "no_routing_failclosed");
    auto badb = BindTransformed(123,0,60,16,true,64);   // out of range -> invalid binding
    ck(!MakeDispatch(badb, map, true).valid, "invalid_binding_failclosed");
    std::printf("FAILS=%d\nS036I_DISP=%s\n", fails, fails?"FAIL":"PASS");
    return fails?1:0;
}