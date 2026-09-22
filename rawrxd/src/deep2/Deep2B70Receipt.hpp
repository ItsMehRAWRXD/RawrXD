#pragma once
#include "Deep2B66RuntimeMeta.hpp"
#include "Deep2B68TargetCalibrator.hpp"
#include "Deep2B69ContractRunner.hpp"
#include <cstdint>
#include <string>

namespace Deep2 {

struct B70Receipt {
    std::string canonicalText;
    std::string sha256Hex;
};

class B70ReceiptWriter {
public:
    static B70Receipt make(const B66RuntimeMeta&,
                           const B68Calibration&,
                           const B69Contract&,
                           const B69Result&);
    static bool verify(const B70Receipt&);
};

} // namespace Deep2
