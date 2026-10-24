#include "../src/deep2/reap/ReapRouteMask.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
int main() {
    using namespace Deep2::ReapRom;
    std::vector<float> logits{2.f,1.f,3.f,0.f};
    const std::vector<uint8_t> keep{1,0,1,0};
    MaskUnretained(logits,keep,2);
    assert(std::isinf(logits[1]) && logits[1]<0);
    assert(logits[0]==2.f && logits[2]==3.f);
    const std::vector<uint32_t> accepted{0,2};
    assert(RouteIsRetained(accepted,keep));
    const std::vector<uint32_t> denied{0,1};
    assert(!RouteIsRetained(denied,keep));
    bool threw=false;
    try { auto a=logits; MaskUnretained(a,keep,3); }
    catch(const std::invalid_argument&){threw=true;}
    assert(threw);
    std::cout<<"REAP_ROUTE_MASK_SMOKE_PASS\n";
}
