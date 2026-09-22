#include "Deep2B67LiveTelemetry.hpp"
#include <algorithm>

namespace Deep2 {

B67Derived B67LiveTelemetry::derive(const B67TokenTelemetry& t) noexcept {
    B67Derived d{};
    if(!t.wallNs) return d;

    const double sec=double(t.wallNs)*1e-9;
    d.rawTps=1.0/sec;
    d.measuredBandwidthGBs=
        (double(t.bytesRead+t.bytesWritten)/1e9)/sec;
    d.measuredComputeTFLOPs=
        (t.flops/1e12)/sec;

    const uint64_t hi=std::max(t.gpu0Ns,t.gpu1Ns);
    const uint64_t lo=std::min(t.gpu0Ns,t.gpu1Ns);
    if(hi) {
        d.overlapFraction=
            std::min(1.0,double(t.overlapNs)/double(hi));
        d.completionSkew=double(hi-lo)/double(hi);
    }

    d.hostSyncFraction=double(t.hostSyncNs)/double(t.wallNs);
    d.queueIdleFraction=double(t.queueIdleNs)/double(t.wallNs);
    return d;
}

bool B67LiveTelemetry::validSteadySample(const B67TokenTelemetry& t) noexcept {
    return t.wallNs>0 &&
           t.gpu0Forwards>0 &&
           t.gpu1Forwards>0 &&
           t.parity &&
           t.stableOutput &&
           t.weightReloadBytes==0 &&
           t.hostMaterializations==0 &&
           t.hostTokenCopies==0 &&
           t.peerCopyBytes==0;
}

} // namespace Deep2
