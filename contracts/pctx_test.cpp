// pctx_test.cpp — CPU test: request-scoped transform context (admit→acquire).
#include "reap/ReapTransformContext.hpp"
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
    Capacity cap; cap.hostRamBytes=64ULL<<30; cap.dedicatedVramBytes=32ULL<<30; cap.sharedVramBytes=16ULL<<30;
    ModelGeom g; g.nonexpertBytes=1ULL<<20; g.expertBytesTotal=4ULL<<20; g.kvBytes=1ULL<<20; g.scratchBytes=1ULL<<20; g.expertCount=4;
    TransformContext ctx(req, 8ULL<<20, 1);
    ck(ctx.PlanAdmission(cap,g), "admitted");
    std::vector<uint8_t> dst(64);
    ck(ctx.Acquire(prov,0,2,dst.data(),dst.size()), "acquire");
    ck(dst[0]==33, "expert2_bytes");
    ctx.Retirement().Cancel();
    ck(!ctx.Acquire(prov,0,2,dst.data(),dst.size()), "cancel_blocks_acquire");
    std::printf("FAILS=%d\nPCTX=%s\n", fails, fails?"FAIL":"PASS");
    return fails?1:0;
}