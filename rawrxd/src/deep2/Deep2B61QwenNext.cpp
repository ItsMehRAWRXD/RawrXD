#include "Deep2B61QwenNext.hpp"
namespace Deep2 {
ModelPerformanceContract B61QwenNextContract() noexcept {
    ModelPerformanceContract c{};
    c.envelope={FleetFamily::Qwen3Next,"qwen3-next-80b-a3b",
        80.0,3.0,48,512,10,1,2048,16,2,256,262144,
        false,false,true,false};
    c.contextBucketMax=8192;
    c.minSamples=320;
    c.minP10RawTps=40.0;
    c.minMedianRawTps=45.0;
    c.minP10RooflineFraction=.82;
    c.minMedianRooflineFraction=.86;
    c.minP10BandwidthFraction=.80;
    c.minP10ComputeFraction=.55;
    c.minMedianOverlap=.90;
    c.maxP90Skew=.05;
    c.maxP90HostSync=.02;
    c.maxP90QueueIdle=.03;
    c.minRooflineHeadroom=1.03;
    return c;
}
RuntimeModelMeta B61QwenNextContractReferenceMeta() noexcept {
    return {80.0,3.0,48,512,10,1,2048,16,2,256,262144,
            false,false,true,false};
}
}
