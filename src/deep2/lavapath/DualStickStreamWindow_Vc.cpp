/* DualStickStreamWindow_Vc.cpp — per-stick VulkanCompute bind + GPU FWD note. */
#include "DualStickStreamWindow.hpp"

namespace Deep2 {
namespace {
CPUInference::VulkanCompute* g_stickVc[2] = {nullptr, nullptr};
}

void DualStickBindVc(unsigned stick, CPUInference::VulkanCompute* vc) {
    g_stickVc[stick & 1u] = vc;
}

CPUInference::VulkanCompute* DualStickVc(unsigned stick) {
    return g_stickVc[stick & 1u];
}

void DualStickNoteExpertGpu(unsigned stick, size_t bytes) {
    DualStickExec& e = DualStickState();
    if ((stick & 1u) == 0) e.forwardCallsGpu0++;
    else e.forwardCallsGpu1++;
    e.runtimeDevices =
        (e.forwardCallsGpu0 > 0 ? 1u : 0u) + (e.forwardCallsGpu1 > 0 ? 1u : 0u);
    e.runtimeBytesWorked += bytes ? bytes : 1ull;
}

} // namespace Deep2
