#include "../src/deep2/op_gdn.hpp"

#include <cmath>
#include <cstdio>
#include <vector>

int main() {
    using namespace Deep2::Qwen4Exp;
    GDNDescriptor descriptor{8, 2, 2, 1, 8};
    std::string failure;
    if (!ValidateGDNDescriptor(descriptor, failure)) {
        std::printf("GDN_GEOMETRY=FAIL reason=%s\n", failure.c_str());
        return 1;
    }

    std::vector<float> input(8), decay(8), beta(8), key(8), value(8);
    std::vector<float> state(32, 0.0f), output;
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = 0.25f + static_cast<float>(i) * 0.05f;
        decay[i] = 0.8f;
        beta[i] = 0.1f + static_cast<float>(i) * 0.01f;
        key[i] = 0.5f;
        value[i] = 1.0f + static_cast<float>(i) * 0.1f;
    }
    GDNReferenceStep(descriptor, input, decay, beta, key, value, state, output, failure);
    if (output.size() != input.size()) {
        std::printf("GDN_REFERENCE=FAIL invalid output\n");
        return 2;
    }
    const std::vector<float> first_state = state;
    GDNReferenceStep(descriptor, input, decay, beta, key, value, state, output, failure);
    bool finite = true;
    bool changed = false;
    for (size_t i = 0; i < output.size(); ++i) {
        finite = finite && std::isfinite(output[i]);
        changed = changed || state[i] != first_state[i];
    }
    std::printf("GDN_GEOMETRY=PASS\nGDN_REFERENCE_FINITE=%s\n"
                "GDN_STATE_CONTINUITY=%s\nGDN_GPU_DISPATCHES=0\n"
                "GDN_CERTIFICATION=NOT_CERTIFIED\n",
                finite ? "PASS" : "FAIL", changed ? "PASS" : "FAIL");
    return finite && changed ? 0 : 3;
}
