#pragma once
#include "Deep2B74ReceiptReplay.hpp"
#include <string>
#include <vector>

namespace Deep2 {

struct B75FleetItem {
    std::string name;
    bool required = true;
    B74Replay receipt{};
};

struct B75Promotion {
    bool pass = false;
    const char* failure = "UNSET";
    size_t required = 0;
    size_t passed = 0;
    std::vector<std::string> failedModels;
};

class B75FleetPromotion {
public:
    static B75Promotion evaluate(const std::vector<B75FleetItem>&) noexcept;
};

} // namespace Deep2
