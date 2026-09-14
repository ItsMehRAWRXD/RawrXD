#include "Deep2RooflineCert.hpp"
#include <sstream>

namespace Deep2::Roofline {

CertResult Certify(const std::vector<TokenMetrics>& t, const CertTargets& g, double rooflineTps) {
    CertResult r{};
    r.rooflineTps = rooflineTps;
    if (t.size() < g.minTokens) r.failures.push_back("TOKENS_LT_MIN");

    u64 wall = 0;
    double overlap = 0.0, skew = 0.0;
    bool parity = true, stable = true;
    for (const auto& x : t) {
        wall += x.tokenWallNs;
        overlap += x.overlapRatio();
        skew += x.completionSkew();
        r.totalForwards[0] += x.gpu[0].forwards;
        r.totalForwards[1] += x.gpu[1].forwards;
        r.steadyWeightReuploads += x.weightReuploads;
        r.steadyDescriptorRebuilds += x.descriptorRebuilds;
        parity = parity && x.argmaxParity;
        stable = stable && x.outputStable;
    }
    if (!t.empty()) {
        r.meanOverlapRatio = overlap / t.size();
        r.meanCompletionSkew = skew / t.size();
    }
    r.measuredTps = wall ? (static_cast<double>(t.size()) * 1.0e9 / static_cast<double>(wall)) : 0.0;
    if (rooflineTps > 0.0) r.rooflineFraction = r.measuredTps / rooflineTps;

    if (g.requireBothGpus && (!r.totalForwards[0] || !r.totalForwards[1])) r.failures.push_back("BOTH_GPUS_NOT_LIVE");
    if (g.requireParity && !parity) r.failures.push_back("ARGMAX_PARITY_FAIL");
    if (g.requireStableOutput && !stable) r.failures.push_back("OUTPUT_STABILITY_FAIL");
    if (r.steadyWeightReuploads > g.maxSteadyWeightReuploads) r.failures.push_back("WEIGHT_REUPLOAD_STEADY_STATE");
    if (r.steadyDescriptorRebuilds > g.maxSteadyDescriptorRebuilds) r.failures.push_back("DESCRIPTOR_REBUILD_STEADY_STATE");
    if (r.meanOverlapRatio < g.minOverlapRatio) r.failures.push_back("OVERLAP_LT_TARGET");
    if (r.meanCompletionSkew > g.maxCompletionSkew) r.failures.push_back("COMPLETION_SKEW_GT_TARGET");
    if (g.minMeasuredTps > 0.0 && r.measuredTps < g.minMeasuredTps) r.failures.push_back("TPS_LT_TARGET");
    if (g.minRooflineFraction > 0.0 && r.rooflineFraction < g.minRooflineFraction) r.failures.push_back("ROOFLINE_FRACTION_LT_TARGET");

    r.pass = r.failures.empty();
    return r;
}

std::string CertResult::emit() const {
    std::ostringstream o;
    o << "DEEP2_ROOFLINE_CERT=" << (pass ? "PASS" : "HOLD") << '\n';
    o << "MEASURED_TPS=" << measuredTps << '\n';
    o << "ROOFLINE_TPS=" << rooflineTps << '\n';
    o << "ROOFLINE_FRACTION=" << rooflineFraction << '\n';
    o << "MEAN_OVERLAP_RATIO=" << meanOverlapRatio << '\n';
    o << "MEAN_COMPLETION_SKEW=" << meanCompletionSkew << '\n';
    o << "GPU0_FORWARDS=" << totalForwards[0] << '\n';
    o << "GPU1_FORWARDS=" << totalForwards[1] << '\n';
    o << "STEADY_WEIGHT_REUPLOADS=" << steadyWeightReuploads << '\n';
    o << "STEADY_DESCRIPTOR_REBUILDS=" << steadyDescriptorRebuilds << '\n';
    o << "FAILURE_COUNT=" << failures.size() << '\n';
    for (const auto& f : failures) o << "FAIL=" << f << '\n';
    return o.str();
}

} // namespace Deep2::Roofline
