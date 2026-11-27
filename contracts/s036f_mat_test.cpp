// s036f_mat_test.cpp — CPU test: transformed-expert materialization (fail-closed).
#include "reap/ReapMaterialize.hpp"
#include <cstdio>
#include <vector>
using namespace RawrXD::Reap;
static int fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; }
int main() {
    SliceTensorDesc t; t.name="blk.0.experts"; t.dims={16,4}; t.bytes=64;
    std::vector<uint8_t> src(64); for(size_t i=0;i<64;++i) src[i]=(uint8_t)(i+1);
    ExpertProvider prov; prov.Register(0,t,src.data());
    PlacementRequest req; req.checkpointId=1; req.selectionFingerprint=SelectionFingerprint({{0,{2}}},1,64,1); req.mode=1; req.selectionValid=true;
    auto m = Materialize(prov, req, 0, 2, 16);
    ck(m.ok, "materialized");
    ck(m.bytes.size()==16 && m.bytes[0]==33, "expert2_bytes");
    PlacementRequest bad = req; bad.selectionValid = false;
    auto b = Materialize(prov, bad, 0, 2, 16);
    ck(!b.ok && b.bytes.empty(), "invalid_failclosed");
    std::printf("FAILS=%d\nS036F_MAT=%s\n", fails, fails?"FAIL":"PASS");
    return fails?1:0;
}