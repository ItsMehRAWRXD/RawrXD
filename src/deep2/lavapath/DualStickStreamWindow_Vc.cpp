/* DualStickStreamWindow_Vc.cpp — VC bind, FWD note, expert stick residency. */
#include "DualStickStreamWindow.hpp"
#include "DualStickExpertBundle.hpp"
#include "DualStickMetaLock.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "vulkan_compute.h"
#include <cstdlib>

namespace Deep2 {
namespace {
CPUInference::VulkanCompute* g_stickVc[2] = {nullptr, nullptr};
struct ResEnt {
    int32_t layer;
    int32_t expert;
    uint32_t stick;
    uint64_t bytes;
};
enum { RES_CAP = 2048 };
ResEnt g_res[RES_CAP];
uint32_t g_resN = 0;
uint64_t g_resBytes[2] = {0, 0};

int ResFind(int layer, int expert) {
    for (uint32_t i = 0; i < g_resN; ++i)
        if (g_res[i].layer == layer && g_res[i].expert == expert)
            return (int)i;
    return -1;
}

void ApplyPinBudget(unsigned stick, CPUInference::VulkanCompute* vc) {
    if (!vc) return;
    const char* k =
        (stick & 1u) ? "DEEP2_STICK1_BUDGET_MIB" : "DEEP2_STICK0_BUDGET_MIB";
    const char* v = std::getenv(k);
    uint64_t mib = (v && *v) ? (uint64_t)std::atoi(v) : 0;
    if (!mib) {
        const char* w = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
        if (w && *w) mib = (uint64_t)std::atoi(w) / 2u;
    }
    if (mib) vc->SetPinResidentBudget((size_t)(mib << 20));
}
} // namespace

void DualStickBindVc(unsigned stick, CPUInference::VulkanCompute* vc) {
    g_stickVc[stick & 1u] = vc;
    ApplyPinBudget(stick, vc);
}

CPUInference::VulkanCompute* DualStickVc(unsigned stick) {
    return g_stickVc[stick & 1u];
}

void DualStickNoteExpertGpu(unsigned stick, size_t bytes) {
    DualStickExec& e = DualStickState();
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    if ((stick & 1u) == 0) e.forwardCallsGpu0++;
    else e.forwardCallsGpu1++;
    e.runtimeDevices =
        (e.forwardCallsGpu0 > 0 ? 1u : 0u) + (e.forwardCallsGpu1 > 0 ? 1u : 0u);
    e.runtimeBytesWorked += bytes ? bytes : 1ull;
}

int DualStickExpertStickOf(int layer, int expert) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    int i = ResFind(layer, expert);
    return i >= 0 ? (int)g_res[(uint32_t)i].stick : -1;
}

uint64_t DualStickExpertBytesOf(int layer, int expert) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    int i = ResFind(layer, expert);
    return i >= 0 ? g_res[(uint32_t)i].bytes : 0ull;
}

int DualStickExpertIsResident(int layer, int expert) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    return ResFind(layer, expert) >= 0 ? 1 : 0;
}


uint64_t DualStickStickResBytes(unsigned stick) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    return g_resBytes[stick & 1u];
}
unsigned DualStickPickStick(uint32_t expertId) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    if (!g_stickVc[1]) return expertId & 1u;
    /* #11 load-aware cold place: prefer lighter stick VRAM. */
    return (g_resBytes[0] <= g_resBytes[1]) ? 0u : 1u;
}

void DualStickNoteExpertResident(int layer, int expert, unsigned stick,
                                 uint64_t bytes) {
    stick &= 1u;
    const uint64_t b = bytes ? bytes : (1ull << 20);
    {
        std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
        int i = ResFind(layer, expert);
        if (i >= 0) {
            ResEnt& e = g_res[(uint32_t)i];
            if (g_resBytes[e.stick] >= e.bytes) g_resBytes[e.stick] -= e.bytes;
            else g_resBytes[e.stick] = 0;
            e.stick = stick;
            e.bytes = b;
            g_resBytes[stick] += b;
        } else if (g_resN < RES_CAP) {
            ResEnt& e = g_res[g_resN++];
            e.layer = layer;
            e.expert = expert;
            e.stick = stick;
            e.bytes = b;
            g_resBytes[stick] += b;
        }
    }
    MoEPlaceGlobal().MarkHot(layer, expert, stick, b);
}

void DualStickExpertResidencyReset() {
    {
        std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
        g_resN = 0;
        g_resBytes[0] = g_resBytes[1] = 0;
    }
    DualStickBundleTableReset();
}

} // namespace Deep2
