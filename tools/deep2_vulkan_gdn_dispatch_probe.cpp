#include "deep2/op_gdn.hpp"
#include "deep2/vulkan_compute.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool Close(const std::vector<float>& expected,
           const std::vector<float>& actual,
           float tolerance,
           double& maxAbs) {
    if (expected.size() != actual.size() || expected.empty()) return false;
    maxAbs = 0.0;
    for (size_t i = 0; i < expected.size(); ++i) {
        if (!std::isfinite(expected[i]) || !std::isfinite(actual[i])) return false;
        maxAbs = std::max(maxAbs, std::fabs(static_cast<double>(expected[i]) - actual[i]));
    }
    return maxAbs <= tolerance;
}

void Fill(std::vector<float>& values, float scale, float offset) {
    for (size_t i = 0; i < values.size(); ++i)
        values[i] = offset + scale * std::sin(static_cast<float>(i % 37));
}

} // namespace

int main() {
    using namespace Deep2;
    using namespace Deep2::Qwen4Exp;

    constexpr uint32_t keyHeads = 2;
    constexpr uint32_t valueHeads = 4;
    constexpr uint32_t headDim = 8;
    constexpr uint64_t stateKey = 0x47544E5F50524F42ull;
    GDNDescriptor descriptor{};
    descriptor.channels = valueHeads * headDim;
    descriptor.state_size = headDim;
    descriptor.groups = valueHeads;
    descriptor.key_heads = keyHeads;
    descriptor.value_heads = valueHeads;
    descriptor.head_dim = headDim;
    descriptor.tokens = 1;
    descriptor.epsilon = 1.0e-6f;
    descriptor.scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    descriptor.gate_sigmoid = 1;

    std::string failure;
    if (!ValidateGDNDescriptor(descriptor, failure)) {
        std::cerr << "GDN_CLASS_GEOMETRY=FAIL reason=" << failure << "\n";
        return 2;
    }

    const size_t qkvWidth = GDNQkvWidth(descriptor);
    const size_t outputWidth = GDNOutputWidth(descriptor);
    const size_t stateWidth = GDNQwenStateElements(descriptor);
    std::vector<float> mixed(qkvWidth), beta(valueHeads), alpha(valueHeads),
        aLog(valueHeads), dtBias(valueHeads), norm(headDim), gate(outputWidth);
    Fill(mixed, 0.002f, 0.01f);
    Fill(beta, 0.01f, -0.2f);
    Fill(alpha, 0.008f, -0.1f);
    Fill(aLog, 0.002f, -1.0f);
    Fill(dtBias, 0.003f, -0.3f);
    Fill(norm, 0.001f, 0.9f);
    Fill(gate, 0.004f, -0.1f);

    VulkanCompute gpu(0);
    if (!gpu.Initialize()) {
        std::cerr << "GDN_CLASS_VULKAN=FAIL initialize\n";
        return 3;
    }

    std::vector<float> referenceState(stateWidth, 0.0f), referenceOutput;
    if (!GDNQwenReferenceStep(
            descriptor, mixed, beta, alpha, aLog, dtBias, norm, gate,
            referenceState, referenceOutput, failure)) {
        gpu.cleanup();
        std::cerr << "GDN_CLASS_REFERENCE=FAIL reason=" << failure << "\n";
        return 4;
    }

    std::vector<float> gpuOutput;
    if (!gpu.DispatchGdn(
            mixed.data(), mixed.size(), beta.data(), beta.size(),
            alpha.data(), alpha.size(), aLog.data(), aLog.size(),
            dtBias.data(), dtBias.size(), norm.data(), norm.size(),
            gate.data(), gate.size(), keyHeads, valueHeads, headDim,
            descriptor.epsilon, descriptor.scale, true, stateKey, gpuOutput)) {
        gpu.cleanup();
        std::cerr << "GDN_CLASS_DISPATCH=FAIL\n";
        return 5;
    }

    double firstAbs = 0.0;
    const bool firstParity = Close(referenceOutput, gpuOutput, 5.0e-4f, firstAbs);
    const std::vector<float> firstReferenceState = referenceState;

    Fill(mixed, 0.0025f, 0.015f);
    Fill(gate, 0.003f, -0.08f);
    referenceOutput.clear();
    if (!GDNQwenReferenceStep(
            descriptor, mixed, beta, alpha, aLog, dtBias, norm, gate,
            referenceState, referenceOutput, failure)) {
        gpu.cleanup();
        std::cerr << "GDN_CLASS_REFERENCE_SECOND=FAIL reason=" << failure << "\n";
        return 6;
    }
    std::vector<float> secondGpuOutput;
    if (!gpu.DispatchGdn(
            mixed.data(), mixed.size(), beta.data(), beta.size(),
            alpha.data(), alpha.size(), aLog.data(), aLog.size(),
            dtBias.data(), dtBias.size(), norm.data(), norm.size(),
            gate.data(), gate.size(), keyHeads, valueHeads, headDim,
            descriptor.epsilon, descriptor.scale, true, stateKey, secondGpuOutput)) {
        gpu.cleanup();
        std::cerr << "GDN_CLASS_DISPATCH_SECOND=FAIL\n";
        return 7;
    }
    double secondAbs = 0.0;
    const bool secondParity = Close(referenceOutput, secondGpuOutput, 5.0e-4f, secondAbs);

    gpu.ResetGdnState(stateKey);
    std::vector<float> resetOutput;
    Fill(mixed, 0.002f, 0.01f);
    Fill(gate, 0.004f, -0.1f);
    std::vector<float> resetReferenceState(stateWidth, 0.0f), resetReferenceOutput;
    if (!GDNQwenReferenceStep(
            descriptor, mixed, beta, alpha, aLog, dtBias, norm, gate,
            resetReferenceState, resetReferenceOutput, failure) ||
        !gpu.DispatchGdn(
            mixed.data(), mixed.size(), beta.data(), beta.size(),
            alpha.data(), alpha.size(), aLog.data(), aLog.size(),
            dtBias.data(), dtBias.size(), norm.data(), norm.size(),
            gate.data(), gate.size(), keyHeads, valueHeads, headDim,
            descriptor.epsilon, descriptor.scale, true, stateKey, resetOutput)) {
        gpu.cleanup();
        std::cerr << "GDN_CLASS_RESET=FAIL\n";
        return 8;
    }
    double resetAbs = 0.0;
    const bool resetParity = Close(resetReferenceOutput, resetOutput, 5.0e-4f, resetAbs);
    const bool resetIndependent = Close(resetReferenceOutput, gpuOutput, 5.0e-4f, resetAbs);
    const bool all = firstParity && secondParity && resetParity && resetIndependent;

    std::cout << "GDN_CLASS_DEVICE=" << gpu.physicalInfo().name << "\n"
              << "GDN_CLASS_PIPELINE=" << (gpu.computeReady() ? "READY" : "FAIL") << "\n"
              << "GDN_CLASS_FIRST_PARITY=" << (firstParity ? "PASS" : "FAIL")
              << " max_abs=" << firstAbs << "\n"
              << "GDN_CLASS_STATE_CONTINUITY=" << (secondParity ? "PASS" : "FAIL")
              << " max_abs=" << secondAbs << "\n"
              << "GDN_CLASS_RESET_CONTINUITY=" << (resetParity ? "PASS" : "FAIL")
              << " max_abs=" << resetAbs << "\n"
              << "GDN_CLASS_RESET_INDEPENDENT=" << (resetIndependent ? "PASS" : "FAIL") << "\n"
              << "GDN_CLASS_DISPATCHES=" << gpu.get_dispatch_count() << "\n"
              << "GDN_CLASS_RESULT=" << (all ? "PASS" : "FAIL") << "\n";
    gpu.cleanup();
    return all ? 0 : 9;
}
