// Real Vulkan topology and allocation telemetry for Deep2 reverse engineering.
//
// This tool deliberately does not invent virtual addresses or pretend that a
// descriptor was allocated. Vulkan does not expose physical device addresses
// through this diagnostic API. It reports actual physical-device memory heaps,
// compute queues, and the current live allocation count (zero unless a caller
// explicitly instruments a Vulkan allocation site).

#include <vulkan/vulkan.h>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

struct DeviceRecord {
    std::string name;
    uint32_t vendor = 0, device = 0;
    VkDeviceSize local_heap = 0;
    uint32_t compute_queues = 0;
    uint32_t queue_families = 0;
};

int main(int argc, char** argv) {
    const std::string out = argc > 1 ? argv[1] : "evidence/qwen4exp_live_vulkan_topology_20261020.md";
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "RawrXD Deep2 Dynamic Vulkan Telemetry";
    app.applicationVersion = 1;
    app.pEngineName = "RawrXD Deep2";
    app.engineVersion = 1;
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ci{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    ci.pApplicationInfo = &app;
    VkInstance instance = VK_NULL_HANDLE;
    VkResult rc = vkCreateInstance(&ci, nullptr, &instance);
    if (rc != VK_SUCCESS) {
        std::cerr << "VULKAN_INSTANCE_FAIL=" << rc << "\n";
        return 2;
    }
    uint32_t n = 0;
    rc = vkEnumeratePhysicalDevices(instance, &n, nullptr);
    if (rc != VK_SUCCESS || n == 0) {
        std::cerr << "VULKAN_DEVICE_ENUM_FAIL=" << rc << " COUNT=" << n << "\n";
        vkDestroyInstance(instance, nullptr);
        return 3;
    }
    std::vector<VkPhysicalDevice> devices(n);
    vkEnumeratePhysicalDevices(instance, &n, devices.data());
    std::vector<DeviceRecord> records;
    for (VkPhysicalDevice pd : devices) {
        VkPhysicalDeviceProperties props{};
        VkPhysicalDeviceMemoryProperties mem{};
        vkGetPhysicalDeviceProperties(pd, &props);
        vkGetPhysicalDeviceMemoryProperties(pd, &mem);
        uint32_t qn = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, nullptr);
        std::vector<VkQueueFamilyProperties> qs(qn);
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, qs.data());
        DeviceRecord r;
        r.name = props.deviceName;
        r.vendor = props.vendorID; r.device = props.deviceID; r.queue_families = qn;
        for (const auto& h : mem.memoryHeaps)
            if (h.flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) r.local_heap += h.size;
        for (const auto& q : qs)
            if (q.queueFlags & VK_QUEUE_COMPUTE_BIT) r.compute_queues += q.queueCount;
        records.push_back(std::move(r));
    }
    std::ofstream report(out);
    if (!report) { vkDestroyInstance(instance, nullptr); return 4; }
    report << "# Deep2 live Vulkan topology telemetry\n\n";
    report << "This receipt contains physical-device queries only. No fabricated LVA,\n"
           << "buffer allocation, descriptor binding, or operator execution is reported.\n\n";
    report << "Device count: " << records.size() << "\n\n";
    report << "| Device | Vendor | Device ID | Device-local heap | Compute queues | Queue families |\n"
           << "|---|---:|---:|---:|---:|---:|\n";
    for (const auto& r : records) {
        report << "| " << r.name << " | 0x" << std::hex << r.vendor << " | 0x" << r.device << std::dec
               << " | " << r.local_heap << " bytes | " << r.compute_queues << " | " << r.queue_families << " |\n";
    }
    report << "\nLive allocations observed: 0 (no allocation hook was installed)\n"
           << "Operator execution: NOT_RUN\nCertification: NOT_CERTIFIED\n";
    std::cout << "VULKAN_TOPOLOGY_DEVICES=" << records.size() << "\n"
              << "LIVE_ALLOCATIONS=0\nREPORT=" << out << "\n";
    vkDestroyInstance(instance, nullptr);
    return 0;
}
