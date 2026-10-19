/* dual_vk_open_probe.cpp — authority for Vulkan-open diagnosis. */
#include "dual_vk_probe_util.hpp"

void ProbeEmitDevice(unsigned slot, const ProbePhys& o);
int ProbeSolo7800(const ProbePhys& stick1, int* vkResultOut);
int ProbeSoloR9700(const ProbePhys& stick0, int* vkResultOut);
int ProbeSameInstanceDual(const ProbePhys& s0, const ProbePhys& s1);
int ProbeSeparateInstances(const ProbePhys& s0, const ProbePhys& s1);

/* Identity = UUID (primary). Name needles are labels only — never selection. */
static int IdentifySticks(const std::vector<ProbePhys>& all,
                          ProbePhys* r9700, ProbePhys* rx7800) {
    int i9700 = -1, i7800 = -1;
    for (int i = 0; i < (int)all.size(); ++i) {
        if (!all[i].discrete || all[i].computeFamily == UINT32_MAX) continue;
        if (ProbeNameHas(all[i].props.deviceName, "R9700")) i9700 = i;
        if (ProbeNameHas(all[i].props.deviceName, "7800")) i7800 = i;
    }
    std::printf("R9700_NAME_NEEDLE_MATCH=%d\nRX7800XT_NAME_NEEDLE_MATCH=%d\n",
                i9700 >= 0 ? 1 : 0, i7800 >= 0 ? 1 : 0);
    if (i9700 < 0 || i7800 < 0 || i9700 == i7800) {
        std::printf("R9700_IDENTITY_MATCH=0\nRX7800XT_IDENTITY_MATCH=0\n");
        return 0;
    }
    *r9700 = all[i9700];
    *rx7800 = all[i7800];
    std::printf("R9700_IDENTITY_MATCH=1\nR9700_UUID=%s\n"
                "RX7800XT_IDENTITY_MATCH=1\nRX7800XT_UUID=%s\n",
                r9700->uuidHex, rx7800->uuidHex);
    return 1;
}

static const char* Disposition(int solo, int same, int sep) {
    if (solo != 0) return "SOLO_CREATE_PATH";
    if (same != 0) return "CONCURRENT_LOGICAL_DEVICE";
    if (sep != 0) return "INSTANCE_LIFETIME";
    return "OPEN_OK_DEEP2_NEXT";
}

int main() {
    std::printf("PROBE=DUAL_VK_OPEN_001\n");
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&inst);
    std::printf("PROBE_STAGE_1_INSTANCE=%s\nVK_STAGE=vkCreateInstance\n"
                "VK_RESULT=%d\nVK_RESULT_STR=%s\n",
                r == VK_SUCCESS ? "PASS" : "FAIL", (int)r, ProbeVkResStr(r));
    if (r != VK_SUCCESS) {
        std::printf("PROBE_DISPOSITION=INSTANCE_CREATE\nPROMOTE=0\n");
        return 10;
    }
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::vector<VkPhysicalDevice> pds(count);
    vkEnumeratePhysicalDevices(inst, &count, pds.data());
    std::printf("PROBE_STAGE_2_ENUM=PASS\nPHYSICAL_DEVICE_COUNT=%u\n", count);
    std::vector<ProbePhys> all(count);
    for (uint32_t i = 0; i < count; ++i) {
        ProbeFillPhys(pds[i], i, all[i]);
        ProbeEmitDevice(i, all[i]);
    }
    ProbePhys stick0{}, stick1{};
    if (!IdentifySticks(all, &stick0, &stick1)) {
        std::printf("PROBE_DISPOSITION=IDENTITY_SELECT\nPROMOTE=0\n");
        vkDestroyInstance(inst, nullptr);
        return 11;
    }
    vkDestroyInstance(inst, nullptr);
    inst = VK_NULL_HANDLE;

    int soloVk = 0, ctrlVk = 0;
    const int ctrl = ProbeSoloR9700(stick0, &ctrlVk);
    const int solo = ProbeSolo7800(stick1, &soloVk);
    const int same = (solo == 0) ? ProbeSameInstanceDual(stick0, stick1) : -1;
    const int sep =
        (same == 0) ? ProbeSeparateInstances(stick0, stick1) : -1;
    const char* disp = Disposition(solo, same, sep);
    if (ctrl != 0 && solo != 0)
        disp = "SOLO_CREATE_PATH_BOTH";
    else if (ctrl == 0 && solo != 0)
        disp = "SOLO_CREATE_PATH_7800_ONLY";
    std::printf("SOLO_R9700=%s\nSOLO_7800=%s\n"
                "BINARY_Q_SAME_INSTANCE_DUAL=%s\n"
                "BINARY_Q_SEPARATE_INSTANCE_DUAL=%s\n"
                "PROBE_DISPOSITION=%s\nPROMOTE=0\n",
                ctrl == 0 ? "PASS" : "FAIL", solo == 0 ? "PASS" : "FAIL",
                same == 0 ? "PASS" : (same < 0 ? "UNTESTED" : "FAIL"),
                sep == 0 ? "PASS" : (sep < 0 ? "UNTESTED" : "FAIL"), disp);
    return same == 0 ? 0 : 20;
}
