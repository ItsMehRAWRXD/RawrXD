#pragma once
#include "Deep2NoDepSha256.hpp"
#include <string>
#include <unordered_map>

namespace Deep2 {

struct B74Replay {
    bool pass = false;
    const char* failure = "UNSET";
    std::unordered_map<std::string,std::string> fields;
    std::string computedSha256;
};

struct B74Regression {
    bool pass = false;
    const char* failure = "UNSET";
    double medianTpsDeltaPct = 0.0;
    double p10TpsDeltaPct = 0.0;
};

class B74ReceiptReplay {
public:
    static B74Replay parseAndVerify(const std::string& canonicalText,
                                    const std::string& expectedSha256) noexcept;
    static B74Regression compare(const B74Replay& baseline,
                                 const B74Replay& candidate,
                                 double maxMedianRegressionPct=3.0,
                                 double maxP10RegressionPct=5.0) noexcept;
};

} // namespace Deep2
