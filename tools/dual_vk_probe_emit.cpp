/* dual_vk_probe_emit.cpp — fill + DEVICE_N receipt (≤99). */
#include "dual_vk_probe_util.hpp"

void ProbeFillPhys(VkPhysicalDevice pd, uint32_t idx, ProbePhys& o) {
    o = ProbePhys{};
    o.pd = pd;
    o.enumIndex = idx;
    o.idProps.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES;
    VkPhysicalDevicePCIBusInfoPropertiesEXT pci{};
    pci.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PCI_BUS_INFO_PROPERTIES_EXT;
    o.idProps.pNext = &pci;
    VkPhysicalDeviceProperties2 p2{};
    p2.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
    p2.pNext = &o.idProps;
    vkGetPhysicalDeviceProperties2(pd, &p2);
    o.props = p2.properties;
    ProbeFmtUuid(o.uuidHex, sizeof(o.uuidHex), o.idProps.deviceUUID);
    if (o.idProps.deviceLUIDValid) {
        for (int i = 0; i < 8; ++i)
            std::snprintf(o.luidHex + i * 2, 3, "%02X", o.idProps.deviceLUID[i]);
    } else {
        std::snprintf(o.luidHex, sizeof(o.luidHex), "-");
    }
    o.pciDomain = pci.pciDomain;
    o.pciBus = pci.pciBus;
    o.pciDevice = pci.pciDevice;
    o.pciFunction = pci.pciFunction;
    o.pciAvail = (pci.pciDomain | pci.pciBus | pci.pciDevice | pci.pciFunction) ? 1 : 0;
    uint32_t n = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(pd, &n, nullptr);
    std::vector<VkQueueFamilyProperties> q(n);
    vkGetPhysicalDeviceQueueFamilyProperties(pd, &n, q.data());
    for (uint32_t i = 0; i < n; ++i) {
        if (q[i].queueFlags & VK_QUEUE_COMPUTE_BIT) {
            o.computeFamily = i;
            o.queueCount = q[i].queueCount;
            break;
        }
    }
    o.discrete = (o.props.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU);
    VkPhysicalDeviceMemoryProperties mem{};
    vkGetPhysicalDeviceMemoryProperties(pd, &mem);
    for (uint32_t h = 0; h < mem.memoryHeapCount; ++h) {
        if ((mem.memoryHeaps[h].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) &&
            mem.memoryHeaps[h].size > o.vramBytes)
            o.vramBytes = mem.memoryHeaps[h].size;
    }
}

void ProbeEmitDevice(unsigned slot, const ProbePhys& o) {
    char pciBuf[64];
    if (o.pciAvail)
        std::snprintf(pciBuf, sizeof(pciBuf), "%u:%u:%u.%u", o.pciDomain,
                      o.pciBus, o.pciDevice, o.pciFunction);
    else
        std::snprintf(pciBuf, sizeof(pciBuf), "UNAVAIL");
    std::printf(
        "DEVICE_%u_NAME=%s\nDEVICE_%u_VENDOR_ID=0x%04X\n"
        "DEVICE_%u_DEVICE_ID=0x%04X\nDEVICE_%u_UUID=%s\n"
        "DEVICE_%u_LUID_VALID=%u\nDEVICE_%u_LUID=%s\n"
        "DEVICE_%u_PCI=%s\nDEVICE_%u_DISCRETE=%d\n"
        "DEVICE_%u_VRAM_BYTES=%llu\nDEVICE_%u_COMPUTE_FAMILY=%u\n"
        "DEVICE_%u_COMPUTE_QUEUE_COUNT=%u\n",
        slot, o.props.deviceName, slot, o.props.vendorID, slot, o.props.deviceID,
        slot, o.uuidHex, slot, (unsigned)o.idProps.deviceLUIDValid, slot,
        o.idProps.deviceLUIDValid ? o.luidHex : "-", slot, pciBuf, slot,
        o.discrete, slot, (unsigned long long)o.vramBytes, slot,
        o.computeFamily, slot, o.queueCount);
}
