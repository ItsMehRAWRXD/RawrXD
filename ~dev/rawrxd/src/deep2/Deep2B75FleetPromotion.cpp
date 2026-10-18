#include "Deep2B75FleetPromotion.hpp"

namespace Deep2 {

B75Promotion B75FleetPromotion::evaluate(
    const std::vector<B75FleetItem>& items) noexcept {

    B75Promotion p{};
    for(const auto& x:items) {
        if(!x.required) continue;
        ++p.required;
        if(x.receipt.pass) ++p.passed;
        else p.failedModels.push_back(x.name);
    }
    if(!p.required) {p.failure="NO_REQUIRED_MODELS";return p;}
    if(p.passed!=p.required) {p.failure="FLEET_INCOMPLETE";return p;}
    p.pass=true;p.failure="PASS";
    return p;
}

} // namespace Deep2
