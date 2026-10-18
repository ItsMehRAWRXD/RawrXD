#include "Deep2B65DeepSeekFlash.hpp"
namespace Deep2 {
ModelPerformanceContract B65DeepSeekFlashContract() noexcept {
    ModelPerformanceContract c{};
    c.envelope={FleetFamily::DeepSeekV4Flash,"deepseek-v4-flash-284b-a13b",
        284.0,13.0,0,0,0,0,0,64,1,0,1000000,
        false,false,false,false};
    c.contextBucketMax=8192;
    c.minSamples=320;
    c.minP10RawTps=10.0;
    c.minMedianRawTps=12.0;
    c.minP10RooflineFraction=.75;
    c.minMedianRooflineFraction=.80;
    c.minP10BandwidthFraction=.72;
    c.minP10ComputeFraction=.40;
    c.minMedianOverlap=.85;
    c.maxP90Skew=.07;
    c.maxP90HostSync=.03;
    c.maxP90QueueIdle=.04;
    c.minRooflineHeadroom=1.03;
    return c;
}
RuntimeModelMeta B65DeepSeekFlashContractReferenceMeta() noexcept {
    return {284.0,13.0,0,0,0,0,0,64,1,0,1000000,
            false,false,false,false};
}
}
