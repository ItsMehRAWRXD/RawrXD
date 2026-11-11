#include "Deep2B68TargetCalibrator.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

static double quantile(std::vector<double> v,double q) {
    if(v.empty()) return 0.0;
    std::sort(v.begin(),v.end());
    const double pos=q*double(v.size()-1);
    const size_t lo=(size_t)std::floor(pos),hi=(size_t)std::ceil(pos);
    if(lo==hi) return v[lo];
    const double f=pos-double(lo);
    return v[lo]*(1.0-f)+v[hi]*f;
}

B68Calibration B68TargetCalibrator::calibrate(
    const B68Hardware& hw,
    const B68WorkModel& w,
    const std::vector<B67TokenTelemetry>& in,
    double safetyFraction,
    double headroom) {

    B68Calibration c{};
    c.requiredHeadroom=headroom;

    if(hw.aggregateBandwidthGBs<=0.0 || w.bytesPerToken<=0.0)
        return {false,"MEMORY_ROOFLINE_INPUT",0,0,0,0,0,0,headroom};

    c.memoryRooflineTps=
        hw.aggregateBandwidthGBs*1e9/w.bytesPerToken;

    if(hw.aggregateComputeTFLOPs>0.0 && w.flopsPerToken>0.0)
        c.computeRooflineTps=
            hw.aggregateComputeTFLOPs*1e12/w.flopsPerToken;

    c.physicalRooflineTps =
        c.computeRooflineTps>0.0 ?
        std::min(c.memoryRooflineTps,c.computeRooflineTps) :
        c.memoryRooflineTps;

    std::vector<double> tps;
    for(const auto& x:in) {
        if(!B67LiveTelemetry::validSteadySample(x)) continue;
        tps.push_back(B67LiveTelemetry::derive(x).rawTps);
    }

    if(tps.size()<64)
        return {false,"INSUFFICIENT_STEADY_SAMPLES",
                c.memoryRooflineTps,c.computeRooflineTps,c.physicalRooflineTps,
                0,0,0,headroom};

    const double p10=quantile(tps,.10);
    const double med=quantile(tps,.50);
    c.observedMedianTps=med;

    const double roofSafe=c.physicalRooflineTps/headroom;
    c.safeP10Target=std::min(p10*safetyFraction,roofSafe*safetyFraction);
    c.safeMedianTarget=std::min(med*safetyFraction,roofSafe);

    if(c.safeP10Target<=0.0 || c.safeMedianTarget<=0.0)
        return {false,"CALIBRATION_ZERO",
                c.memoryRooflineTps,c.computeRooflineTps,c.physicalRooflineTps,
                c.observedMedianTps,0,0,headroom};

    c.pass=true;
    c.failure="PASS";
    return c;
}

} // namespace Deep2
