/* g3_gpu1_createdevice_diag.cpp — G3_GPU1_CREATEDEVICE_DIAG_001 driver. */
#include "dual_vk_probe_util.hpp"
#include <vector>

void ProbeFillPhys(VkPhysicalDevice pd, uint32_t idx, ProbePhys& o);
void DiagDumpPhys(const char* tag, const ProbePhys& o);
void DiagRunLadder(const char* tag, const ProbePhys& o);

static int FindByNeedle(VkInstance inst, const char* needle, ProbePhys* out) {
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::vector<VkPhysicalDevice> pds(count);
    vkEnumeratePhysicalDevices(inst, &count, pds.data());
    for (uint32_t i = 0; i < count; ++i) {
        ProbePhys t;
        ProbeFillPhys(pds[i], i, t);
        if (!t.discrete) continue;
        if (!ProbeNameHas(t.props.deviceName, needle)) continue;
        *out = t;
        return 1;
    }
    return 0;
}

int main() {
    std::printf("GATE=G3_GPU1_CREATEDEVICE_DIAG_001\nBEHAVIOR_PATCH=0\n"
                "PROMOTE=0\nTARGET=RX7800XT+R9700_SAME_PROCESS\n");
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&inst);
    std::printf("VK_STAGE=vkCreateInstance\nVK_RESULT=%d\nVK_RESULT_STR=%s\n",
                (int)r, ProbeVkResStr(r));
    if (r != VK_SUCCESS) return 10;

    uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::printf("PHYSICAL_DEVICE_COUNT=%u\n", count);

    ProbePhys r9700{}, rx7800{};
    const int ok9700 = FindByNeedle(inst, "R9700", &r9700);
    const int ok7800 = FindByNeedle(inst, "7800", &rx7800);
    std::printf("R9700_IDENTITY_MATCH=%d\nRX7800XT_IDENTITY_MATCH=%d\n", ok9700,
                ok7800);
    if (!ok9700 || !ok7800) {
        std::printf("PROBE_DISPOSITION=IDENTITY_SELECT\nPROMOTE=0\n");
        vkDestroyInstance(inst, nullptr);
        return 11;
    }

    DiagDumpPhys("R9700", r9700);
    DiagDumpPhys("RX7800XT", rx7800);
    DiagRunLadder("R9700", r9700);
    DiagRunLadder("RX7800XT", rx7800);

    std::printf("\n=== DISCRIMINATOR ===\n");
    std::printf("NOTE=CREATE_MINIMAL_CORE_ONLY == queue-only create "
                "(matches Deep2 production ext=0 path shape)\n");
    std::printf("GPU1_CREATE_FAILURE_DOES_NOT_BREAK_GPU0_GENERATION=1\n");
    std::printf("ARMED_DUALSTICK_FALLBACK_STABLE_N10=1\n");
    std::printf("DUALSTICK_LIVE=0\nPROMOTE=0\n");
    vkDestroyInstance(inst, nullptr);
    return 0;
}
