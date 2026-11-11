#include "Qwen4ExpGatedResidual.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>
using namespace deep2::qwen4exp;

static bool near(float a, float b, float eps = 2e-5f) { return std::fabs(a-b) <= eps; }

template<class Fn> static bool rejects(Fn fn) {
    try { fn(); } catch (const std::invalid_argument&) { return true; }
    return false;
}

int main() {
    GRShape sh{2, 2, 1};
    std::vector<float> z4(4,0.0f), down(4,0.0f), up(4,0.0f), inject(8,0.0f);
    std::vector<float> input{1,1,3,4};
    GRWeights w{z4,down,up,inject};
    const auto out=cpu_gr_read(input,sh,w);
    const float inv = 1.0f / std::sqrt((9.0f + 16.0f)/2.0f + sh.rms_eps);
    assert(near(out.mixed[0], (1.0f + 3.0f * inv) * .25f));
    assert(near(out.mixed[1], (1.0f + 4.0f * inv) * .25f));
    assert(near(out.injection[0], 1.0f) && near(out.injection[1], 1.0f));
    const std::vector<float> block{0.25f,-0.5f};
    const auto state=cpu_gr_write(out,block,sh);
    assert(near(state[0],1.25f) && near(state[1],0.5f));
    assert(near(state[2],3.25f) && near(state[3],3.5f));
    assert(input == std::vector<float>({1,1,3,4})); // no mutation

    // Low-rank and injection gates must affect the output.
    down[0]=.1f; down[1]=.3f; down[2]=.2f; down[3]=.4f;
    up[0]=1; up[1]=2; up[2]=-1; up[3]=-2;
    inject[0]=.1f; inject[5]=.2f;
    const auto gated=cpu_gr_read(input,sh,w);
    assert(!near(gated.mixed[0],out.mixed[0]));
    assert(!near(gated.injection[0],gated.injection[1]));
    const auto gated_state=cpu_gr_write(gated,block,sh);
    assert(!near(gated_state[0],state[0]));

    // No residual-injection weight is legal only in final combine-less GR.
    GRWeights final_w{z4,down,up,{}};
    const auto final=cpu_gr_read(input,sh,final_w,false);
    assert(final.injection.empty());
    assert(rejects([&]{cpu_gr_write(final,block,sh);}));

    std::vector<float> bad_inj{0};
    GRWeights malformed{z4,down,up,bad_inj};
    assert(rejects([&]{cpu_gr_read(input,sh,malformed);}));
    assert(rejects([&]{cpu_gr_read(input,GRShape{2,3,1},w);}));
    assert(rejects([&]{cpu_gr_read(input,GRShape{2,2,1,0.0f},w);}));
    input[0]=std::numeric_limits<float>::quiet_NaN();
    assert(rejects([&]{cpu_gr_read(input,sh,w);}));
    std::cout << "Qwen4Exp GR CPU numerical-contract tests PASS (not GPU/full-model certified)\n";
}
