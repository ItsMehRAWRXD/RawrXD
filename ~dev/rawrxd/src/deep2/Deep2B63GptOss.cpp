#include "Deep2B63GptOss.hpp"
namespace Deep2 {
ModelPerformanceContract B63GptOssContract() noexcept {
    ModelPerformanceContract c{};
    c.envelope={FleetFamily::GptOss120B,"gpt-oss-120b",
        117.0,5.1,36,128,4,0,0,0,0,0,131072,
        false,false,false,true};
    c.contextBucketMax=8192;
    c.minSamples=320;
    c.minP10RawTps=25.0;
    c.minMedianRawTps=30.0;
    c.minP10RooflineFraction=.80;
    c.minMedianRooflineFraction=.84;
    c.minP10BandwidthFraction=.75;
    c.minP10ComputeFraction=.50;
    c.minMedianOverlap=.90;
    c.maxP90Skew=.05;
    c.maxP90HostSync=.02;
    c.maxP90QueueIdle=.03;
    c.minRooflineHeadroom=1.03;
    return c;
}
RuntimeModelMeta B63GptOssContractReferenceMeta() noexcept {
    return {117.0,5.1,36,128,4,0,0,0,0,0,131072,
            false,false,false,true};
}
}
