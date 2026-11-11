// Physical Vulkan pipeline wiring probe for the Qwen4Exp lowering artifacts.
// It creates real descriptor layouts, shader modules, pipeline layouts, and
// compute pipelines on an AMD device. It does not claim inference execution:
// no model buffers are allocated and no command buffer is submitted.

#include <vulkan/vulkan.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static std::vector<uint32_t> ReadSpv(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f || (f.tellg() % 4) != 0) return {};
    const size_t bytes = static_cast<size_t>(f.tellg()); f.seekg(0);
    std::vector<uint32_t> code(bytes / 4); f.read(reinterpret_cast<char*>(code.data()), bytes);
    return code;
}

static bool MakePipeline(VkDevice dev, const std::vector<uint32_t>& code, uint32_t bindings,
                         uint32_t push_bytes, VkPipeline& pipeline, VkPipelineLayout& layout,
                         VkDescriptorSetLayout& descriptors) {
    std::vector<VkDescriptorSetLayoutBinding> bs(bindings);
    for (uint32_t i = 0; i < bindings; ++i) {
        bs[i].binding = i; bs[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bs[i].descriptorCount = 1; bs[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo d{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
    d.bindingCount = bindings; d.pBindings = bs.data();
    if (vkCreateDescriptorSetLayout(dev, &d, nullptr, &descriptors) != VK_SUCCESS) return false;
    VkPushConstantRange pc{VK_SHADER_STAGE_COMPUTE_BIT, 0, push_bytes};
    VkPipelineLayoutCreateInfo l{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
    l.setLayoutCount = 1; l.pSetLayouts = &descriptors; l.pushConstantRangeCount = 1; l.pPushConstantRanges = &pc;
    if (vkCreatePipelineLayout(dev, &l, nullptr, &layout) != VK_SUCCESS) return false;
    VkShaderModuleCreateInfo sm{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
    sm.codeSize = code.size() * sizeof(uint32_t); sm.pCode = code.data();
    VkShaderModule module = VK_NULL_HANDLE;
    if (vkCreateShaderModule(dev, &sm, nullptr, &module) != VK_SUCCESS) return false;
    VkPipelineShaderStageCreateInfo stage{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO};
    stage.stage = VK_SHADER_STAGE_COMPUTE_BIT; stage.module = module; stage.pName = "main";
    VkComputePipelineCreateInfo cp{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
    cp.stage = stage; cp.layout = layout;
    const VkResult result = vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cp, nullptr, &pipeline);
    vkDestroyShaderModule(dev, module, nullptr);
    return result == VK_SUCCESS;
}

int main(int argc, char** argv) {
    const std::string ple = argc > 1 ? argv[1] : "src/deep2/shaders/deep2_qwen4exp_ple.spv";
    const std::string hc = argc > 2 ? argv[2] : "src/deep2/shaders/deep2_qwen4exp_hc_combine.spv";
    const std::string gdn = argc > 3 ? argv[3] : "src/deep2/shaders/deep2_qwen4exp_gdn.spv";
    const auto ple_code = ReadSpv(ple), hc_code = ReadSpv(hc), gdn_code = ReadSpv(gdn);
    if (ple_code.empty() || hc_code.empty() || gdn_code.empty()) { std::cerr << "SPIRV_READ_FAIL\n"; return 2; }
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO}; app.pApplicationName = "RawrXD Qwen4Exp Pipeline Probe"; app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ic{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO}; ic.pApplicationInfo = &app;
    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(&ic, nullptr, &instance) != VK_SUCCESS) return 3;
    uint32_t count = 0; vkEnumeratePhysicalDevices(instance, &count, nullptr);
    std::vector<VkPhysicalDevice> pds(count); vkEnumeratePhysicalDevices(instance, &count, pds.data());
    VkPhysicalDevice physical = VK_NULL_HANDLE; uint32_t qfamily = UINT32_MAX; VkPhysicalDeviceProperties props{};
    for (auto pd : pds) {
        VkPhysicalDeviceProperties p{}; vkGetPhysicalDeviceProperties(pd, &p); if (p.vendorID != 0x1002) continue;
        uint32_t qn = 0; vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, nullptr); std::vector<VkQueueFamilyProperties> qs(qn);
        vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, qs.data());
        for (uint32_t i = 0; i < qn; ++i) if ((qs[i].queueFlags & VK_QUEUE_COMPUTE_BIT) != 0) { physical = pd; qfamily = i; props = p; break; }
        if (physical) break;
    }
    if (!physical) { std::cerr << "AMD_COMPUTE_DEVICE_NOT_FOUND\n"; vkDestroyInstance(instance, nullptr); return 4; }
    float priority = 1.0f; VkDeviceQueueCreateInfo q{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO}; q.queueFamilyIndex = qfamily; q.queueCount = 1; q.pQueuePriorities = &priority;
    VkDeviceCreateInfo dc{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO}; dc.queueCreateInfoCount = 1; dc.pQueueCreateInfos = &q;
    VkDevice dev = VK_NULL_HANDLE; if (vkCreateDevice(physical, &dc, nullptr, &dev) != VK_SUCCESS) { vkDestroyInstance(instance, nullptr); return 5; }
    VkPipeline ple_pipe = VK_NULL_HANDLE, hc_pipe = VK_NULL_HANDLE, gdn_pipe = VK_NULL_HANDLE;
    VkPipelineLayout ple_layout = VK_NULL_HANDLE, hc_layout = VK_NULL_HANDLE, gdn_layout = VK_NULL_HANDLE;
    VkDescriptorSetLayout ple_desc = VK_NULL_HANDLE, hc_desc = VK_NULL_HANDLE, gdn_desc = VK_NULL_HANDLE;
    const bool ple_ok = MakePipeline(dev, ple_code, 5, 16, ple_pipe, ple_layout, ple_desc);
    const bool hc_ok = MakePipeline(dev, hc_code, 6, 20, hc_pipe, hc_layout, hc_desc);
    const bool gdn_ok = MakePipeline(dev, gdn_code, 7, 16, gdn_pipe, gdn_layout, gdn_desc);
    std::cout << "DEVICE=" << props.deviceName << " QUEUE_FAMILY=" << qfamily << "\n"
              << "PLE_PIPELINE=" << (ple_ok ? "PASS" : "FAIL")
              << " HC_PIPELINE=" << (hc_ok ? "PASS" : "FAIL")
              << " GDN_PIPELINE=" << (gdn_ok ? "PASS" : "FAIL") << "\n"
              << "DISPATCHES=0 EXECUTION=NOT_RUN\n";
    if (ple_pipe) vkDestroyPipeline(dev, ple_pipe, nullptr); if (hc_pipe) vkDestroyPipeline(dev, hc_pipe, nullptr);
    if (gdn_pipe) vkDestroyPipeline(dev, gdn_pipe, nullptr);
    if (ple_layout) vkDestroyPipelineLayout(dev, ple_layout, nullptr); if (hc_layout) vkDestroyPipelineLayout(dev, hc_layout, nullptr);
    if (gdn_layout) vkDestroyPipelineLayout(dev, gdn_layout, nullptr);
    if (ple_desc) vkDestroyDescriptorSetLayout(dev, ple_desc, nullptr); if (hc_desc) vkDestroyDescriptorSetLayout(dev, hc_desc, nullptr);
    if (gdn_desc) vkDestroyDescriptorSetLayout(dev, gdn_desc, nullptr);
    vkDestroyDevice(dev, nullptr); vkDestroyInstance(instance, nullptr);
    return ple_ok && hc_ok && gdn_ok ? 0 : 6;
}
