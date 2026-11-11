#include "Deep2B62Nemotron.hpp"
namespace Deep2 {
ModelPerformanceContract B62NemotronContract() noexcept {
    ModelPerformanceContract c{};
    c.envelope={FleetFamily::Nemotron35Lightning,"nemotron-3.5-lightning-30b-a3b",
        30.0,3.0,52,128,6,1,2688,0,0,0,1000000,
        false,true,false,false};
    c.contextBucketMax=8192;
    c.minSamples=320;
    c.minP10RawTps=60.0;
    c.minMedianRawTps=70.0;
    c.minP10RooflineFraction=.80;
    c.minMedianRooflineFraction=.84;
    c.minP10BandwidthFraction=.75;
    c.minP10ComputeFraction=.55;
    c.minMedianOverlap=.90;
    c.maxP90Skew=.05;
    c.maxP90HostSync=.02;
    c.maxP90QueueIdle=.03;
    c.minRooflineHeadroom=1.03;
    return c;
}
RuntimeModelMeta B62NemotronContractReferenceMeta() noexcept {
    return {30.0,3.0,52,128,6,1,2688,0,0,0,1000000,
            false,true,false,false};
}
}
