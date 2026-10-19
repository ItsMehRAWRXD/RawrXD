/* dual_vk_7800_ladder.cpp — driver for empty→production 7800 create ladder. */
#include "dual_vk_probe_util.hpp"
#include <vector>

void ProbeFillPhys(VkPhysicalDevice pd, uint32_t idx, ProbePhys& o);
int ProbeFindByUuid(VkInstance inst, const char* uuid, const char* luidOpt,
                    ProbePhys* filled);
VkResult LadderCreateRung(VkPhysicalDevice pd, uint32_t fam, int rung,
                          VkDevice* out);

static int Find7800(VkInstance inst, ProbePhys* out) {
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(inst, &count, nullptr);
    std::vector<VkPhysicalDevice> pds(count);
    vkEnumeratePhysicalDevices(inst, &count, pds.data());
    for (uint32_t i = 0; i < count; ++i) {
        ProbePhys t;
        ProbeFillPhys(pds[i], i, t);
        if (!t.discrete) continue;
        if (!ProbeNameHas(t.props.deviceName, "7800")) continue;
        *out = t;
        return 1;
    }
    return 0;
}

int main() {
    std::printf("PROBE=DUAL_VK_7800_LADDER_001\nBEHAVIOR_CHANGE=0\n");
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = ProbeMakeInstance(&inst);
    std::printf("VK_STAGE=vkCreateInstance\nVK_RESULT=%d\n", (int)r);
    if (r != VK_SUCCESS) return 10;
    ProbePhys stick{};
    if (!Find7800(inst, &stick)) {
        std::printf("RX7800XT_IDENTITY_MATCH=0\nPROMOTE=0\n");
        vkDestroyInstance(inst, nullptr);
        return 11;
    }
    std::printf("RX7800XT_IDENTITY_MATCH=1\nDEVICE_UUID=%s\nDEVICE_NAME=%s\n"
                "DEVICE_ID=0x%04X\nCOMPUTE_FAMILY=%u\n",
                stick.uuidHex, stick.props.deviceName, stick.props.deviceID,
                stick.computeFamily);

    static const char* ids[] = {"7800_CREATE_A0", "7800_CREATE_A1",
                                "7800_CREATE_A2", "7800_CREATE_A3",
                                "7800_CREATE_A4", "7800_CREATE_A5"};
    static const char* deltas[] = {
        "queue_only features=null pNext=null ext=0",
        "+ zeroed core VkPhysicalDeviceFeatures",
        "+ Features2 pNext chain",
        "+ required device extensions if advertised",
        "+ optional device extensions if advertised",
        "production-shaped: <=2 queues + zeroed features + ext=0"};
    int firstFail = -1;
    for (int i = 0; i < 6; ++i) {
        ProbePhys live{};
        const char* luid =
            stick.idProps.deviceLUIDValid ? stick.luidHex : nullptr;
        if (!ProbeFindByUuid(inst, stick.uuidHex, luid, &live)) {
            std::printf("%s=FAIL\nVK_STAGE=reEnumerateIdentify\nVK_RESULT=-1\n"
                        "DELTA=%s\n",
                        ids[i], deltas[i]);
            if (firstFail < 0) firstFail = i;
            continue;
        }
        VkDevice dev = VK_NULL_HANDLE;
        r = LadderCreateRung(live.pd, live.computeFamily, i, &dev);
        std::printf("%s=%s\n%s_VK_RESULT=%d\nDELTA=%s\n", ids[i],
                    r == VK_SUCCESS ? "PASS" : "FAIL", ids[i], (int)r,
                    deltas[i]);
        if (r != VK_SUCCESS && firstFail < 0) firstFail = i;
        if (dev) vkDestroyDevice(dev, nullptr);
    }
    const char* disp = (firstFail == 0) ? "DRIVER_OR_DEVICE_STATE"
                       : (firstFail > 0)  ? "FIRST_FAILING_RUNG"
                                          : "ALL_RUNGS_PASS";
    std::printf("FIRST_FAIL_RUNG=%d\nPROBE_DISPOSITION=%s\nPROMOTE=0\n",
                firstFail, disp);
    vkDestroyInstance(inst, nullptr);
    return firstFail < 0 ? 0 : (firstFail == 0 ? 20 : 21);
}
