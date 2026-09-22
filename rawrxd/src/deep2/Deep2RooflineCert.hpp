#pragma once
#include "Deep2RooflineCommon.hpp"
#include <string>

namespace Deep2::Roofline {

struct CertResult {
    bool pass = false;
    double measuredTps = 0.0;
    double rooflineTps = 0.0;
    double rooflineFraction = 0.0;
    double meanOverlapRatio = 0.0;
    double meanCompletionSkew = 0.0;
    u64 totalForwards[2]{};
    u64 steadyWeightReuploads = 0;
    u64 steadyDescriptorRebuilds = 0;
    u64 steadyHostTrafficBytes = 0;
    double specAcceptanceRatio = 0.0;
    std::vector<std::string> failures;
    std::string emit() const;
};

CertResult Certify(const std::vector<TokenMetrics>& tokens,
                   const CertTargets& targets,
                   double rooflineTps);

} // namespace Deep2::Roofline
