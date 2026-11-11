#include "Deep2B64Laguna.hpp"
namespace Deep2 {
ModelPerformanceContract B64LagunaContract() noexcept {
    ModelPerformanceContract c{};
    c.envelope={FleetFamily::LagunaS21,"laguna-s-2.1-118b-a8b",
        118.0,8.0,48,256,10,1,0,0,8,128,1048576,
        false,false,false,true};
    c.contextBucketMax=8192;
    c.minSamples=320;
    c.minP10RawTps=15.0;
    c.minMedianRawTps=18.0;
    c.minP10RooflineFraction=.78;
    c.minMedianRooflineFraction=.82;
    c.minP10BandwidthFraction=.75;
    c.minP10ComputeFraction=.45;
    c.minMedianOverlap=.88;
    c.maxP90Skew=.06;
    c.maxP90HostSync=.025;
    c.maxP90QueueIdle=.035;
    c.minRooflineHeadroom=1.03;
    return c;
}
RuntimeModelMeta B64LagunaContractReferenceMeta() noexcept {
    return {118.0,8.0,48,256,10,1,0,0,8,128,1048576,
            false,false,false,true};
}
}
