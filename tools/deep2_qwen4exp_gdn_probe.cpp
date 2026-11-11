#include "../src/deep2/op_gdn.hpp"

#include <vulkan/vulkan.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

std::vector<uint32_t> ReadSpv(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    const std::streamoff end = file.tellg();
    if (end <= 0 || (end % 4) != 0) return {};
    file.seekg(0, std::ios::beg);
    std::vector<uint32_t> code(static_cast<size_t>(end) / 4);
    file.read(reinterpret_cast<char*>(code.data()), end);
    return file ? code : std::vector<uint32_t>{};
}

uint32_t FindMemoryType(const VkPhysicalDeviceMemoryProperties& properties,
                        uint32_t type_bits,
                        VkMemoryPropertyFlags required,
                        VkMemoryPropertyFlags preferred) {
    uint32_t fallback = UINT32_MAX;
    for (uint32_t i = 0; i < properties.memoryTypeCount; ++i) {
        if ((type_bits & (1u << i)) == 0) continue;
        const auto flags = properties.memoryTypes[i].propertyFlags;
        if ((flags & required) != required) continue;
        if ((flags & preferred) == preferred) return i;
        if (fallback == UINT32_MAX) fallback = i;
    }
    return fallback;
}

struct HostBuffer {
    VkDevice device = VK_NULL_HANDLE;
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize size = 0;
    bool coherent = false;

    bool Upload(const void* data, size_t bytes) const {
        void* mapped = nullptr;
        if (vkMapMemory(device, memory, 0, bytes, 0, &mapped) != VK_SUCCESS) return false;
        std::memcpy(mapped, data, bytes);
        if (!coherent) {
            VkMappedMemoryRange range{VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE};
            range.memory = memory;
            range.offset = 0;
            range.size = VK_WHOLE_SIZE;
            if (vkFlushMappedMemoryRanges(device, 1, &range) != VK_SUCCESS) {
                vkUnmapMemory(device, memory);
                return false;
            }
        }
        vkUnmapMemory(device, memory);
        return true;
    }

    bool Download(void* data, size_t bytes) const {
        if (!coherent) {
            VkMappedMemoryRange range{VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE};
            range.memory = memory;
            range.offset = 0;
            range.size = VK_WHOLE_SIZE;
            if (vkInvalidateMappedMemoryRanges(device, 1, &range) != VK_SUCCESS) return false;
        }
        void* mapped = nullptr;
        if (vkMapMemory(device, memory, 0, bytes, 0, &mapped) != VK_SUCCESS) return false;
        std::memcpy(data, mapped, bytes);
        vkUnmapMemory(device, memory);
        return true;
    }

    void Destroy() {
        if (buffer) vkDestroyBuffer(device, buffer, nullptr);
        if (memory) vkFreeMemory(device, memory, nullptr);
        buffer = VK_NULL_HANDLE;
        memory = VK_NULL_HANDLE;
    }
};

bool CreateHostBuffer(VkPhysicalDevice physical,
                      VkDevice device,
                      const VkPhysicalDeviceMemoryProperties& memory_properties,
                      size_t bytes,
                      HostBuffer& result) {
    result.device = device;
    VkBufferCreateInfo buffer_info{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
    buffer_info.size = bytes;
    buffer_info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
    buffer_info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkCreateBuffer(device, &buffer_info, nullptr, &result.buffer) != VK_SUCCESS) return false;

    VkMemoryRequirements requirements{};
    vkGetBufferMemoryRequirements(device, result.buffer, &requirements);
    const uint32_t preferred_index = FindMemoryType(
        memory_properties, requirements.memoryTypeBits,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
        VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
    if (preferred_index == UINT32_MAX) {
        result.Destroy();
        return false;
    }
    VkMemoryAllocateInfo allocate_info{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
    allocate_info.allocationSize = requirements.size;
    allocate_info.memoryTypeIndex = preferred_index;
    if (vkAllocateMemory(device, &allocate_info, nullptr, &result.memory) != VK_SUCCESS) {
        result.Destroy();
        return false;
    }
    if (vkBindBufferMemory(device, result.buffer, result.memory, 0) != VK_SUCCESS) {
        result.Destroy();
        return false;
    }
    result.size = bytes;
    result.coherent = (memory_properties.memoryTypes[preferred_index].propertyFlags &
                       VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
    (void)physical;
    return true;
}

struct GdnPush {
    uint32_t tokens;
    uint32_t key_heads;
    uint32_t value_heads;
    uint32_t head_dim;
    float epsilon;
    float scale;
    uint32_t gate_sigmoid;
    uint32_t reserved;
};
static_assert(sizeof(GdnPush) == 32);

bool CloseVectors(const std::vector<float>& expected,
                  const std::vector<float>& actual,
                  float tolerance,
                  double& max_abs,
                  double& max_relative,
                  double& cosine) {
    if (expected.size() != actual.size() || expected.empty()) return false;
    max_abs = 0.0;
    max_relative = 0.0;
    double dot = 0.0;
    double expected_norm = 0.0;
    double actual_norm = 0.0;
    for (size_t i = 0; i < expected.size(); ++i) {
        if (!std::isfinite(expected[i]) || !std::isfinite(actual[i])) return false;
        const double lhs = expected[i];
        const double rhs = actual[i];
        max_abs = std::max(max_abs, std::fabs(lhs - rhs));
        max_relative = std::max(max_relative, std::fabs(lhs - rhs) /
                                            std::max(1.0e-6, std::fabs(lhs)));
        dot += lhs * rhs;
        expected_norm += lhs * lhs;
        actual_norm += rhs * rhs;
    }
    cosine = dot / std::sqrt(expected_norm * actual_norm);
    return max_abs <= tolerance;
}

} // namespace

int main(int argc, char** argv) {
    using namespace Deep2::Qwen4Exp;

    const std::string shader_path = argc > 1
        ? argv[1] : "src/deep2/shaders/deep2_qwen4exp_gdn.spv";
    const auto shader_code = ReadSpv(shader_path);
    if (shader_code.empty()) {
        std::cerr << "GDN_SHADER_READ=FAIL path=" << shader_path << "\n";
        return 2;
    }

    constexpr uint32_t tokens = 3;
    GDNDescriptor descriptor{};
    descriptor.key_heads = 16;
    descriptor.value_heads = 48;
    descriptor.head_dim = 128;
    descriptor.conv_kernel = 4;
    descriptor.tokens = tokens;
    descriptor.qkv_stride = GDNQkvWidth(descriptor);
    descriptor.gate_stride = GDNOutputWidth(descriptor);
    descriptor.epsilon = 1.0e-6f;
    descriptor.scale = 1.0f / std::sqrt(128.0f);
    descriptor.gate_sigmoid = true;

    std::string failure;
    if (!ValidateGDNDescriptor(descriptor, failure)) {
        std::cerr << "GDN_GEOMETRY=FAIL reason=" << failure << "\n";
        return 3;
    }
    const size_t qkv_width = GDNQkvWidth(descriptor);
    const size_t output_width = GDNOutputWidth(descriptor);
    const size_t scalar_width = descriptor.value_heads;
    const size_t state_width = static_cast<size_t>(GDNStateElements(descriptor));
    std::vector<float> qkv(static_cast<size_t>(tokens) * qkv_width);
    std::vector<float> beta(static_cast<size_t>(tokens) * scalar_width);
    std::vector<float> alpha(static_cast<size_t>(tokens) * scalar_width);
    std::vector<float> gate(static_cast<size_t>(tokens) * output_width);
    std::vector<float> a_log(scalar_width), dt_bias(scalar_width), norm(descriptor.head_dim);
    for (size_t i = 0; i < qkv.size(); ++i)
        qkv[i] = 0.005f * std::sin(static_cast<float>(i % 97));
    for (size_t i = 0; i < beta.size(); ++i) {
        beta[i] = -0.3f + 0.01f * static_cast<float>(i % 23);
        alpha[i] = -0.2f + 0.008f * static_cast<float>(i % 19);
    }
    for (size_t i = 0; i < gate.size(); ++i)
        gate[i] = -0.1f + 0.004f * static_cast<float>(i % 31);
    for (size_t i = 0; i < scalar_width; ++i) {
        a_log[i] = -1.0f + 0.002f * static_cast<float>(i % 17);
        dt_bias[i] = -0.4f + 0.003f * static_cast<float>(i % 13);
    }
    for (size_t i = 0; i < norm.size(); ++i)
        norm[i] = 0.9f + 0.001f * static_cast<float>(i % 29);

    std::vector<float> cpu_state(state_width, 0.0f), cpu_output;
    if (!GDNReferenceDecode(descriptor, qkv, beta, alpha, gate, a_log, dt_bias,
                            norm, cpu_state, cpu_output, failure)) {
        std::cerr << "GDN_REFERENCE=FAIL reason=" << failure << "\n";
        return 4;
    }

    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "RawrXD Qwen4Exp GDN Probe";
    app.applicationVersion = 1;
    app.pEngineName = "RawrXD Deep2";
    app.engineVersion = 1;
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo instance_info{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    instance_info.pApplicationInfo = &app;
    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(&instance_info, nullptr, &instance) != VK_SUCCESS) {
        std::cerr << "GDN_VULKAN=FAIL instance\n";
        return 5;
    }

    uint32_t physical_count = 0;
    vkEnumeratePhysicalDevices(instance, &physical_count, nullptr);
    std::vector<VkPhysicalDevice> physical_devices(physical_count);
    if (physical_count == 0 || vkEnumeratePhysicalDevices(
            instance, &physical_count, physical_devices.data()) != VK_SUCCESS) {
        vkDestroyInstance(instance, nullptr);
        std::cerr << "GDN_VULKAN=FAIL no_device\n";
        return 6;
    }

    VkPhysicalDevice physical = VK_NULL_HANDLE;
    uint32_t queue_family = UINT32_MAX;
    VkPhysicalDeviceProperties properties{};
    for (VkPhysicalDevice candidate : physical_devices) {
        VkPhysicalDeviceProperties candidate_properties{};
        vkGetPhysicalDeviceProperties(candidate, &candidate_properties);
        if (candidate_properties.vendorID != 0x1002) continue;
        uint32_t family_count = 0;
        vkGetPhysicalDeviceQueueFamilyProperties(candidate, &family_count, nullptr);
        std::vector<VkQueueFamilyProperties> families(family_count);
        vkGetPhysicalDeviceQueueFamilyProperties(candidate, &family_count, families.data());
        for (uint32_t family = 0; family < family_count; ++family) {
            if ((families[family].queueFlags & VK_QUEUE_COMPUTE_BIT) != 0) {
                physical = candidate;
                queue_family = family;
                properties = candidate_properties;
                break;
            }
        }
        if (physical) break;
    }
    if (!physical) {
        vkDestroyInstance(instance, nullptr);
        std::cerr << "GDN_VULKAN=FAIL amd_compute_device_not_found\n";
        return 7;
    }

    float priority = 1.0f;
    VkDeviceQueueCreateInfo queue_info{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
    queue_info.queueFamilyIndex = queue_family;
    queue_info.queueCount = 1;
    queue_info.pQueuePriorities = &priority;
    VkDeviceCreateInfo device_info{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
    device_info.queueCreateInfoCount = 1;
    device_info.pQueueCreateInfos = &queue_info;
    VkDevice device = VK_NULL_HANDLE;
    if (vkCreateDevice(physical, &device_info, nullptr, &device) != VK_SUCCESS) {
        vkDestroyInstance(instance, nullptr);
        std::cerr << "GDN_VULKAN=FAIL device_create\n";
        return 8;
    }

    VkPhysicalDeviceMemoryProperties memory_properties{};
    vkGetPhysicalDeviceMemoryProperties(physical, &memory_properties);
    std::vector<HostBuffer> buffers(9);
    const std::vector<size_t> buffer_sizes = {
        qkv.size() * sizeof(float), beta.size() * sizeof(float),
        alpha.size() * sizeof(float), a_log.size() * sizeof(float),
        dt_bias.size() * sizeof(float), norm.size() * sizeof(float),
        gate.size() * sizeof(float), state_width * sizeof(float),
        cpu_output.size() * sizeof(float)};
    bool setup_ok = true;
    for (size_t i = 0; i < buffers.size() && setup_ok; ++i)
        setup_ok = CreateHostBuffer(physical, device, memory_properties, buffer_sizes[i], buffers[i]);
    std::vector<float> gpu_state(state_width, 0.0f), gpu_output(cpu_output.size(), 0.0f);
    const std::vector<const void*> uploads = {
        qkv.data(), beta.data(), alpha.data(), a_log.data(), dt_bias.data(),
        norm.data(), gate.data(), gpu_state.data(), gpu_output.data()};
    for (size_t i = 0; i < buffers.size() && setup_ok; ++i)
        setup_ok = buffers[i].Upload(uploads[i], buffer_sizes[i]);
    if (!setup_ok) {
        for (auto& buffer : buffers) buffer.Destroy();
        vkDestroyDevice(device, nullptr);
        vkDestroyInstance(instance, nullptr);
        std::cerr << "GDN_VULKAN=FAIL host_buffer_setup\n";
        return 9;
    }

    VkDescriptorSetLayoutBinding bindings[9]{};
    for (uint32_t i = 0; i < 9; ++i) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    VkDescriptorSetLayoutCreateInfo descriptor_info{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
    descriptor_info.bindingCount = 9;
    descriptor_info.pBindings = bindings;
    VkDescriptorSetLayout descriptor_layout = VK_NULL_HANDLE;
    VkPipelineLayout pipeline_layout = VK_NULL_HANDLE;
    VkShaderModule shader_module = VK_NULL_HANDLE;
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;
    VkDescriptorSet descriptor_set = VK_NULL_HANDLE;
    bool pipeline_ok = vkCreateDescriptorSetLayout(
        device, &descriptor_info, nullptr, &descriptor_layout) == VK_SUCCESS;
    GdnPush push{tokens, descriptor.key_heads, descriptor.value_heads, descriptor.head_dim,
                 descriptor.epsilon, descriptor.scale, descriptor.gate_sigmoid ? 1u : 0u, 0u};
    if (pipeline_ok) {
        VkPushConstantRange push_range{VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof(GdnPush)};
        VkPipelineLayoutCreateInfo layout_info{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
        layout_info.setLayoutCount = 1;
        layout_info.pSetLayouts = &descriptor_layout;
        layout_info.pushConstantRangeCount = 1;
        layout_info.pPushConstantRanges = &push_range;
        pipeline_ok = vkCreatePipelineLayout(device, &layout_info, nullptr, &pipeline_layout) == VK_SUCCESS;
    }
    if (pipeline_ok) {
        VkShaderModuleCreateInfo shader_info{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        shader_info.codeSize = shader_code.size() * sizeof(uint32_t);
        shader_info.pCode = shader_code.data();
        pipeline_ok = vkCreateShaderModule(device, &shader_info, nullptr, &shader_module) == VK_SUCCESS;
    }
    if (pipeline_ok) {
        VkPipelineShaderStageCreateInfo stage{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO};
        stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        stage.module = shader_module;
        stage.pName = "main";
        VkComputePipelineCreateInfo compute_info{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
        compute_info.stage = stage;
        compute_info.layout = pipeline_layout;
        pipeline_ok = vkCreateComputePipelines(
            device, VK_NULL_HANDLE, 1, &compute_info, nullptr, &pipeline) == VK_SUCCESS;
    }
    if (pipeline_ok) {
        VkDescriptorPoolSize pool_size{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 9};
        VkDescriptorPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO};
        pool_info.maxSets = 1;
        pool_info.poolSizeCount = 1;
        pool_info.pPoolSizes = &pool_size;
        pipeline_ok = vkCreateDescriptorPool(device, &pool_info, nullptr, &descriptor_pool) == VK_SUCCESS;
    }
    if (pipeline_ok) {
        VkDescriptorSetAllocateInfo allocate_info{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO};
        allocate_info.descriptorPool = descriptor_pool;
        allocate_info.descriptorSetCount = 1;
        allocate_info.pSetLayouts = &descriptor_layout;
        pipeline_ok = vkAllocateDescriptorSets(device, &allocate_info, &descriptor_set) == VK_SUCCESS;
    }
    if (pipeline_ok) {
        VkDescriptorBufferInfo infos[9]{};
        VkWriteDescriptorSet writes[9]{};
        for (uint32_t i = 0; i < 9; ++i) {
            infos[i].buffer = buffers[i].buffer;
            infos[i].offset = 0;
            infos[i].range = VK_WHOLE_SIZE;
            writes[i] = {VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, nullptr, descriptor_set,
                         i, 0, 1, VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, nullptr, &infos[i], nullptr};
        }
        vkUpdateDescriptorSets(device, 9, writes, 0, nullptr);
    }

    VkCommandPool command_pool = VK_NULL_HANDLE;
    VkCommandBuffer command_buffer = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    bool dispatch_ok = pipeline_ok;
    if (dispatch_ok) {
        VkCommandPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
        pool_info.queueFamilyIndex = queue_family;
        dispatch_ok = vkCreateCommandPool(device, &pool_info, nullptr, &command_pool) == VK_SUCCESS;
    }
    if (dispatch_ok) {
        VkCommandBufferAllocateInfo allocate_info{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        allocate_info.commandPool = command_pool;
        allocate_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        allocate_info.commandBufferCount = 1;
        dispatch_ok = vkAllocateCommandBuffers(device, &allocate_info, &command_buffer) == VK_SUCCESS;
    }
    if (dispatch_ok) {
        VkCommandBufferBeginInfo begin_info{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        dispatch_ok = vkBeginCommandBuffer(command_buffer, &begin_info) == VK_SUCCESS;
        if (dispatch_ok) {
            vkCmdBindPipeline(command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
            vkCmdBindDescriptorSets(command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE,
                                    pipeline_layout, 0, 1, &descriptor_set, 0, nullptr);
            vkCmdPushConstants(command_buffer, pipeline_layout, VK_SHADER_STAGE_COMPUTE_BIT,
                               0, sizeof(GdnPush), &push);
            vkCmdDispatch(command_buffer, descriptor.value_heads, 1, 1);
            dispatch_ok = vkEndCommandBuffer(command_buffer) == VK_SUCCESS;
        }
    }
    if (dispatch_ok) {
        VkFenceCreateInfo fence_info{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
        dispatch_ok = vkCreateFence(device, &fence_info, nullptr, &fence) == VK_SUCCESS;
    }
    VkQueue queue = VK_NULL_HANDLE;
    if (dispatch_ok) {
        vkGetDeviceQueue(device, queue_family, 0, &queue);
        VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO};
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &command_buffer;
        const VkResult submit_result = vkQueueSubmit(queue, 1, &submit, fence);
        dispatch_ok = submit_result == VK_SUCCESS;
        if (dispatch_ok) dispatch_ok = vkWaitForFences(device, 1, &fence, VK_TRUE, 30ull * 1000ull * 1000ull * 1000ull) == VK_SUCCESS;
    }
    if (dispatch_ok) {
        dispatch_ok = buffers[7].Download(gpu_state.data(), buffer_sizes[7]) &&
                      buffers[8].Download(gpu_output.data(), buffer_sizes[8]);
    }

    double output_abs = std::numeric_limits<double>::infinity();
    double output_rel = std::numeric_limits<double>::infinity();
    double output_cos = 0.0;
    double state_abs = std::numeric_limits<double>::infinity();
    double state_rel = std::numeric_limits<double>::infinity();
    double state_cos = 0.0;
    const bool output_parity = dispatch_ok && CloseVectors(
        cpu_output, gpu_output, 5.0e-4f, output_abs, output_rel, output_cos);
    const bool state_parity = dispatch_ok && CloseVectors(
        cpu_state, gpu_state, 5.0e-4f, state_abs, state_rel, state_cos);

    std::cout << "GDN_DEVICE=" << properties.deviceName << " QUEUE_FAMILY=" << queue_family << "\n"
              << "GDN_GEOMETRY=PASS key_heads=" << descriptor.key_heads
              << " value_heads=" << descriptor.value_heads
              << " head_dim=" << descriptor.head_dim << "\n"
              << "GDN_PIPELINE=" << (pipeline_ok ? "PASS" : "FAIL") << "\n"
              << "GDN_DISPATCHES=" << (dispatch_ok ? 1 : 0)
              << " GDN_EXECUTION=" << (dispatch_ok ? "PASS" : "FAIL") << "\n"
              << "GDN_OUTPUT_PARITY=" << (output_parity ? "PASS" : "FAIL")
              << " max_abs=" << output_abs << " max_rel=" << output_rel
              << " cosine=" << output_cos << "\n"
              << "GDN_STATE_PARITY=" << (state_parity ? "PASS" : "FAIL")
              << " max_abs=" << state_abs << " max_rel=" << state_rel
              << " cosine=" << state_cos << "\n"
              << "GDN_INDEPENDENT_PARITY="
              << (output_parity && state_parity ? "PASS" : "FAIL") << "\n"
              << "QWEN4EXP_FULL_MODEL=NOT_CERTIFIED\n";

    if (fence) vkDestroyFence(device, fence, nullptr);
    if (command_pool) vkDestroyCommandPool(device, command_pool, nullptr);
    if (descriptor_pool) vkDestroyDescriptorPool(device, descriptor_pool, nullptr);
    if (pipeline) vkDestroyPipeline(device, pipeline, nullptr);
    if (shader_module) vkDestroyShaderModule(device, shader_module, nullptr);
    if (pipeline_layout) vkDestroyPipelineLayout(device, pipeline_layout, nullptr);
    if (descriptor_layout) vkDestroyDescriptorSetLayout(device, descriptor_layout, nullptr);
    for (auto& buffer : buffers) buffer.Destroy();
    vkDestroyDevice(device, nullptr);
    vkDestroyInstance(instance, nullptr);
    return pipeline_ok && dispatch_ok && output_parity && state_parity ? 0 : 10;
}
