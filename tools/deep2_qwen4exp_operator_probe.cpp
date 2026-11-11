#include "../src/deep2/op_hyperconnection.hpp"
#include "../src/deep2/op_ple.hpp"
#include "../src/deep2/op_qsa.hpp"
#include "../src/deep2/op_sparse_moe.hpp"

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
    bool coherent = false;

    bool Upload(const void* data, size_t bytes) const {
        void* mapped = nullptr;
        if (vkMapMemory(device, memory, 0, bytes, 0, &mapped) != VK_SUCCESS) return false;
        std::memcpy(mapped, data, bytes);
        if (!coherent) {
            VkMappedMemoryRange range{VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE};
            range.memory = memory;
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

class VulkanProbe {
public:
    bool Initialize(std::string& failure) {
        VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
        app.pApplicationName = "RawrXD Qwen4Exp operator probe";
        app.applicationVersion = 1;
        app.pEngineName = "RawrXD Deep2";
        app.engineVersion = 1;
        app.apiVersion = VK_API_VERSION_1_1;
        VkInstanceCreateInfo instance_info{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
        instance_info.pApplicationInfo = &app;
        if (vkCreateInstance(&instance_info, nullptr, &instance_) != VK_SUCCESS) {
            failure = "vkCreateInstance failed";
            return false;
        }
        uint32_t count = 0;
        if (vkEnumeratePhysicalDevices(instance_, &count, nullptr) != VK_SUCCESS || count == 0) {
            failure = "no Vulkan physical devices";
            return false;
        }
        std::vector<VkPhysicalDevice> devices(count);
        if (vkEnumeratePhysicalDevices(instance_, &count, devices.data()) != VK_SUCCESS) {
            failure = "physical device enumeration failed";
            return false;
        }
        for (VkPhysicalDevice candidate : devices) {
            VkPhysicalDeviceProperties properties{};
            vkGetPhysicalDeviceProperties(candidate, &properties);
            if (properties.vendorID != 0x1002) continue;
            uint32_t family_count = 0;
            vkGetPhysicalDeviceQueueFamilyProperties(candidate, &family_count, nullptr);
            std::vector<VkQueueFamilyProperties> families(family_count);
            vkGetPhysicalDeviceQueueFamilyProperties(candidate, &family_count, families.data());
            for (uint32_t family = 0; family < family_count; ++family) {
                if ((families[family].queueFlags & VK_QUEUE_COMPUTE_BIT) == 0) continue;
                physical_ = candidate;
                queue_family_ = family;
                device_name_ = properties.deviceName;
                break;
            }
            if (physical_) break;
        }
        if (!physical_) {
            failure = "AMD compute device not found";
            return false;
        }
        float priority = 1.0f;
        VkDeviceQueueCreateInfo queue_info{VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO};
        queue_info.queueFamilyIndex = queue_family_;
        queue_info.queueCount = 1;
        queue_info.pQueuePriorities = &priority;
        VkDeviceCreateInfo device_info{VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO};
        device_info.queueCreateInfoCount = 1;
        device_info.pQueueCreateInfos = &queue_info;
        if (vkCreateDevice(physical_, &device_info, nullptr, &device_) != VK_SUCCESS) {
            failure = "vkCreateDevice failed";
            return false;
        }
        vkGetDeviceQueue(device_, queue_family_, 0, &queue_);
        vkGetPhysicalDeviceMemoryProperties(physical_, &memory_properties_);
        VkCommandPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
        pool_info.queueFamilyIndex = queue_family_;
        if (vkCreateCommandPool(device_, &pool_info, nullptr, &command_pool_) != VK_SUCCESS) {
            failure = "vkCreateCommandPool failed";
            return false;
        }
        return true;
    }

    ~VulkanProbe() {
        if (device_) vkDeviceWaitIdle(device_);
        if (command_pool_) vkDestroyCommandPool(device_, command_pool_, nullptr);
        if (device_) vkDestroyDevice(device_, nullptr);
        if (instance_) vkDestroyInstance(instance_, nullptr);
    }

    bool CreateBuffer(size_t bytes, HostBuffer& result, std::string& failure) const {
        if (bytes == 0) {
            failure = "zero-sized storage buffer";
            return false;
        }
        result.device = device_;
        VkBufferCreateInfo info{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
        info.size = bytes;
        info.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT;
        info.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (vkCreateBuffer(device_, &info, nullptr, &result.buffer) != VK_SUCCESS) {
            failure = "vkCreateBuffer failed";
            return false;
        }
        VkMemoryRequirements requirements{};
        vkGetBufferMemoryRequirements(device_, result.buffer, &requirements);
        const uint32_t memory_type = FindMemoryType(
            memory_properties_, requirements.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
            VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if (memory_type == UINT32_MAX) {
            result.Destroy();
            failure = "host-visible memory type unavailable";
            return false;
        }
        VkMemoryAllocateInfo allocation{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
        allocation.allocationSize = requirements.size;
        allocation.memoryTypeIndex = memory_type;
        if (vkAllocateMemory(device_, &allocation, nullptr, &result.memory) != VK_SUCCESS ||
            vkBindBufferMemory(device_, result.buffer, result.memory, 0) != VK_SUCCESS) {
            result.Destroy();
            failure = "storage buffer memory allocation failed";
            return false;
        }
        result.coherent = (memory_properties_.memoryTypes[memory_type].propertyFlags &
                           VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
        return true;
    }

    bool Dispatch(const std::string& shader_path,
                  uint32_t binding_count,
                  const void* push_data,
                  uint32_t push_size,
                  const std::vector<HostBuffer*>& buffers,
                  uint32_t groups_x,
                  std::string& failure) const {
        if (binding_count != buffers.size() || groups_x == 0) {
            failure = "dispatch descriptor/count geometry mismatch";
            return false;
        }
        const auto code = ReadSpv(shader_path);
        if (code.empty()) {
            failure = "SPIR-V read failed: " + shader_path;
            return false;
        }
        std::vector<VkDescriptorSetLayoutBinding> bindings(binding_count);
        for (uint32_t i = 0; i < binding_count; ++i) {
            bindings[i].binding = i;
            bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            bindings[i].descriptorCount = 1;
            bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
        }
        VkDescriptorSetLayoutCreateInfo descriptor_info{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO};
        descriptor_info.bindingCount = binding_count;
        descriptor_info.pBindings = bindings.data();
        VkDescriptorSetLayout descriptor_layout = VK_NULL_HANDLE;
        VkPipelineLayout pipeline_layout = VK_NULL_HANDLE;
        VkShaderModule shader_module = VK_NULL_HANDLE;
        VkPipeline pipeline = VK_NULL_HANDLE;
        VkDescriptorPool descriptor_pool = VK_NULL_HANDLE;
        VkDescriptorSet descriptor_set = VK_NULL_HANDLE;
        VkCommandBuffer command_buffer = VK_NULL_HANDLE;
        VkFence fence = VK_NULL_HANDLE;
        auto cleanup = [&] {
            if (fence) vkDestroyFence(device_, fence, nullptr);
            if (command_buffer) vkFreeCommandBuffers(device_, command_pool_, 1, &command_buffer);
            if (descriptor_pool) vkDestroyDescriptorPool(device_, descriptor_pool, nullptr);
            if (pipeline) vkDestroyPipeline(device_, pipeline, nullptr);
            if (shader_module) vkDestroyShaderModule(device_, shader_module, nullptr);
            if (pipeline_layout) vkDestroyPipelineLayout(device_, pipeline_layout, nullptr);
            if (descriptor_layout) vkDestroyDescriptorSetLayout(device_, descriptor_layout, nullptr);
        };
        if (vkCreateDescriptorSetLayout(device_, &descriptor_info, nullptr, &descriptor_layout) != VK_SUCCESS) {
            failure = "descriptor layout creation failed";
            cleanup();
            return false;
        }
        VkPushConstantRange push_range{VK_SHADER_STAGE_COMPUTE_BIT, 0, push_size};
        VkPipelineLayoutCreateInfo layout_info{VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO};
        layout_info.setLayoutCount = 1;
        layout_info.pSetLayouts = &descriptor_layout;
        layout_info.pushConstantRangeCount = push_size ? 1u : 0u;
        layout_info.pPushConstantRanges = push_size ? &push_range : nullptr;
        if (vkCreatePipelineLayout(device_, &layout_info, nullptr, &pipeline_layout) != VK_SUCCESS) {
            failure = "pipeline layout creation failed";
            cleanup();
            return false;
        }
        VkShaderModuleCreateInfo shader_info{VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO};
        shader_info.codeSize = code.size() * sizeof(uint32_t);
        shader_info.pCode = code.data();
        if (vkCreateShaderModule(device_, &shader_info, nullptr, &shader_module) != VK_SUCCESS) {
            failure = "shader module creation failed";
            cleanup();
            return false;
        }
        VkPipelineShaderStageCreateInfo stage{VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO};
        stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
        stage.module = shader_module;
        stage.pName = "main";
        VkComputePipelineCreateInfo compute{VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO};
        compute.stage = stage;
        compute.layout = pipeline_layout;
        if (vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &compute, nullptr, &pipeline) != VK_SUCCESS) {
            failure = "compute pipeline creation failed";
            cleanup();
            return false;
        }
        VkDescriptorPoolSize pool_size{VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, binding_count};
        VkDescriptorPoolCreateInfo pool_info{VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO};
        pool_info.maxSets = 1;
        pool_info.poolSizeCount = 1;
        pool_info.pPoolSizes = &pool_size;
        if (vkCreateDescriptorPool(device_, &pool_info, nullptr, &descriptor_pool) != VK_SUCCESS) {
            failure = "descriptor pool creation failed";
            cleanup();
            return false;
        }
        VkDescriptorSetAllocateInfo set_info{VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO};
        set_info.descriptorPool = descriptor_pool;
        set_info.descriptorSetCount = 1;
        set_info.pSetLayouts = &descriptor_layout;
        if (vkAllocateDescriptorSets(device_, &set_info, &descriptor_set) != VK_SUCCESS) {
            failure = "descriptor set allocation failed";
            cleanup();
            return false;
        }
        std::vector<VkDescriptorBufferInfo> infos(binding_count);
        std::vector<VkWriteDescriptorSet> writes(binding_count);
        for (uint32_t i = 0; i < binding_count; ++i) {
            infos[i].buffer = buffers[i]->buffer;
            infos[i].offset = 0;
            infos[i].range = VK_WHOLE_SIZE;
            writes[i] = VkWriteDescriptorSet{VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET};
            writes[i].dstSet = descriptor_set;
            writes[i].dstBinding = i;
            writes[i].descriptorCount = 1;
            writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
            writes[i].pBufferInfo = &infos[i];
        }
        vkUpdateDescriptorSets(device_, binding_count, writes.data(), 0, nullptr);
        VkCommandBufferAllocateInfo command_info{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        command_info.commandPool = command_pool_;
        command_info.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        command_info.commandBufferCount = 1;
        if (vkAllocateCommandBuffers(device_, &command_info, &command_buffer) != VK_SUCCESS) {
            failure = "command buffer allocation failed";
            cleanup();
            return false;
        }
        VkCommandBufferBeginInfo begin{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        if (vkBeginCommandBuffer(command_buffer, &begin) != VK_SUCCESS) {
            failure = "command buffer begin failed";
            cleanup();
            return false;
        }
        vkCmdBindPipeline(command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
        vkCmdBindDescriptorSets(command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE,
                                pipeline_layout, 0, 1, &descriptor_set, 0, nullptr);
        if (push_size) vkCmdPushConstants(command_buffer, pipeline_layout,
                                          VK_SHADER_STAGE_COMPUTE_BIT, 0, push_size, push_data);
        vkCmdDispatch(command_buffer, groups_x, 1, 1);
        if (vkEndCommandBuffer(command_buffer) != VK_SUCCESS) {
            failure = "command buffer end failed";
            cleanup();
            return false;
        }
        VkFenceCreateInfo fence_info{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
        if (vkCreateFence(device_, &fence_info, nullptr, &fence) != VK_SUCCESS) {
            failure = "fence creation failed";
            cleanup();
            return false;
        }
        VkSubmitInfo submit{VK_STRUCTURE_TYPE_SUBMIT_INFO};
        submit.commandBufferCount = 1;
        submit.pCommandBuffers = &command_buffer;
        if (vkQueueSubmit(queue_, 1, &submit, fence) != VK_SUCCESS ||
            vkWaitForFences(device_, 1, &fence, VK_TRUE, 30'000'000'000ull) != VK_SUCCESS) {
            failure = "GPU submission or fence wait failed";
            cleanup();
            return false;
        }
        cleanup();
        return true;
    }

    const std::string& DeviceName() const { return device_name_; }

private:
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue queue_ = VK_NULL_HANDLE;
    VkCommandPool command_pool_ = VK_NULL_HANDLE;
    uint32_t queue_family_ = UINT32_MAX;
    VkPhysicalDeviceMemoryProperties memory_properties_{};
    std::string device_name_;
};

bool Close(const std::vector<float>& expected, const std::vector<float>& actual,
           float tolerance, double& max_abs, double& cosine) {
    if (expected.size() != actual.size() || expected.empty()) return false;
    max_abs = 0.0;
    double dot = 0.0;
    double lhs_norm = 0.0;
    double rhs_norm = 0.0;
    for (size_t i = 0; i < expected.size(); ++i) {
        if (!std::isfinite(expected[i]) || !std::isfinite(actual[i])) return false;
        max_abs = std::max(max_abs, std::fabs(static_cast<double>(expected[i]) - actual[i]));
        dot += static_cast<double>(expected[i]) * actual[i];
        lhs_norm += static_cast<double>(expected[i]) * expected[i];
        rhs_norm += static_cast<double>(actual[i]) * actual[i];
    }
    cosine = dot / std::sqrt(lhs_norm * rhs_norm);
    return max_abs <= tolerance;
}

template <typename T>
bool Upload(VulkanProbe& vk, const std::vector<T>& values, HostBuffer& buffer, std::string& failure) {
    return vk.CreateBuffer(values.size() * sizeof(T), buffer, failure) &&
           buffer.Upload(values.data(), values.size() * sizeof(T));
}

} // namespace

int main(int argc, char** argv) {
    const std::string root = argc > 1 ? argv[1] : "src/deep2/shaders/";
    const std::string ple_shader = root + "deep2_qwen4exp_ple.spv";
    const std::string hc_shader = root + "deep2_qwen4exp_hc_combine.spv";
    const std::string qsa_shader = root + "deep2_qwen4exp_qsa_score.spv";
    const std::string moe_shader = root + "deep2_qwen4exp_moe_router.spv";
    std::string failure;
    VulkanProbe vk;
    if (!vk.Initialize(failure)) {
        std::cerr << "QWEN4EXP_OPERATOR_GPU=BLOCKED reason=" << failure << "\n";
        return 2;
    }
    std::cout << "QWEN4EXP_OPERATOR_DEVICE=" << vk.DeviceName() << "\n";

    using namespace Deep2::Qwen4Exp;
    bool all_pass = true;

    {
        PLEDescriptor descriptor{5, 8, 4, 3};
        const size_t state_length = PLEStateLength(descriptor);
        std::vector<float> input(static_cast<size_t>(descriptor.tokens) * descriptor.channels);
        std::vector<float> weights(static_cast<size_t>(descriptor.kernel) * descriptor.channels);
        std::vector<float> cpu_state(static_cast<size_t>(descriptor.channels) * state_length, 0.0f);
        std::vector<float> gpu_state = cpu_state;
        std::vector<float> cpu_output, gpu_output(input.size(), 0.0f);
        for (size_t i = 0; i < input.size(); ++i) input[i] = 0.02f * std::sin(static_cast<float>(i + 1));
        for (size_t i = 0; i < weights.size(); ++i) weights[i] = 0.1f + 0.01f * static_cast<float>(i % 7);
        if (!PLEReferenceDecode(descriptor, input, weights, cpu_state, cpu_output, failure)) {
            std::cerr << "PLE_REFERENCE=FAIL reason=" << failure << "\n";
            return 3;
        }
        HostBuffer x, w, state, y, state_out;
        bool ok = Upload(vk, input, x, failure) && Upload(vk, weights, w, failure) &&
                  Upload(vk, gpu_state, state, failure) && Upload(vk, gpu_output, y, failure) &&
                  Upload(vk, gpu_state, state_out, failure);
        struct Push { uint32_t tokens, channels, kernel, dilation; } push{
            descriptor.tokens, descriptor.channels, descriptor.kernel, descriptor.dilation};
        std::vector<HostBuffer*> buffers{&x, &w, &state, &y, &state_out};
        ok = ok && vk.Dispatch(ple_shader, 5, &push, sizeof(push), buffers, 1, failure);
        ok = ok && y.Download(gpu_output.data(), gpu_output.size() * sizeof(float));
        ok = ok && state_out.Download(gpu_state.data(), gpu_state.size() * sizeof(float));
        double output_abs = 0.0, output_cos = 0.0, state_abs = 0.0, state_cos = 0.0;
        const bool pass = ok && Close(cpu_output, gpu_output, 1.0e-5f, output_abs, output_cos) &&
                          Close(cpu_state, gpu_state, 1.0e-5f, state_abs, state_cos);
        all_pass = all_pass && pass;
        std::cout << "PLE_GPU_DISPATCH=" << (pass ? "PASS" : "FAIL")
                  << " max_abs=" << std::max(output_abs, state_abs)
                  << " cosine=" << std::min(output_cos, state_cos) << "\n";
        x.Destroy(); w.Destroy(); state.Destroy(); y.Destroy(); state_out.Destroy();
    }

    {
        HyperconnectionDescriptor descriptor{2, 8, 4, 1.0e-5f, false};
        const size_t width = static_cast<size_t>(HyperconnectionWidth(descriptor));
        std::vector<float> residual(static_cast<size_t>(descriptor.tokens) * width);
        std::vector<float> block(static_cast<size_t>(descriptor.tokens) * descriptor.hidden);
        std::vector<float> injection(static_cast<size_t>(descriptor.tokens) * descriptor.streams);
        std::vector<float> norm(descriptor.hidden), cpu_combined, cpu_normalized;
        std::vector<float> gpu_combined(residual.size()), gpu_normalized(residual.size());
        for (size_t i = 0; i < residual.size(); ++i) residual[i] = 0.01f * std::sin(static_cast<float>(i + 2));
        for (size_t i = 0; i < block.size(); ++i) block[i] = 0.02f * std::cos(static_cast<float>(i + 1));
        for (size_t i = 0; i < injection.size(); ++i) injection[i] = -0.2f + 0.04f * static_cast<float>(i);
        for (size_t i = 0; i < norm.size(); ++i) norm[i] = 0.8f + 0.01f * static_cast<float>(i);
        if (!HyperconnectionCombineNorm(descriptor, residual, block, injection, norm,
                                         cpu_combined, cpu_normalized, failure)) {
            std::cerr << "HC_REFERENCE=FAIL reason=" << failure << "\n";
            return 4;
        }
        HostBuffer r, b, i, n, c, o;
        bool ok = Upload(vk, residual, r, failure) && Upload(vk, block, b, failure) &&
                  Upload(vk, injection, i, failure) && Upload(vk, norm, n, failure) &&
                  Upload(vk, gpu_combined, c, failure) && Upload(vk, gpu_normalized, o, failure);
        struct Push { uint32_t tokens, head_dim, hc_count, reserved; float epsilon; } push{
            descriptor.tokens, descriptor.hidden, descriptor.streams, 0, descriptor.epsilon};
        std::vector<HostBuffer*> buffers{&r, &b, &i, &n, &c, &o};
        ok = ok && vk.Dispatch(hc_shader, 6, &push, sizeof(push), buffers, 1, failure);
        ok = ok && c.Download(gpu_combined.data(), gpu_combined.size() * sizeof(float));
        ok = ok && o.Download(gpu_normalized.data(), gpu_normalized.size() * sizeof(float));
        double combined_abs = 0.0, combined_cos = 0.0, normalized_abs = 0.0, normalized_cos = 0.0;
        const bool pass = ok && Close(cpu_combined, gpu_combined, 2.0e-5f, combined_abs, combined_cos) &&
                          Close(cpu_normalized, gpu_normalized, 2.0e-5f, normalized_abs, normalized_cos);
        all_pass = all_pass && pass;
        std::cout << "HC_GPU_DISPATCH=" << (pass ? "PASS" : "FAIL")
                  << " max_abs=" << std::max(combined_abs, normalized_abs)
                  << " cosine=" << std::min(combined_cos, normalized_cos) << "\n";
        r.Destroy(); b.Destroy(); i.Destroy(); n.Destroy(); c.Destroy(); o.Destroy();
    }

    {
        QSADescriptor descriptor{};
        const uint32_t rows = 2, pages = 2, max_pages = 2, requests = 1;
        std::vector<float> query(static_cast<size_t>(rows) * descriptor.index_heads * descriptor.key_dim);
        std::vector<float> key_cache(static_cast<size_t>(pages) * descriptor.page_size * descriptor.key_dim);
        std::vector<int32_t> page_table{0, 1}, request{0, 0}, position{7, 11}, lengths{12};
        std::vector<float> cpu_logits;
        std::vector<uint32_t> cpu_visible;
        for (size_t i = 0; i < query.size(); ++i)
            query[i] = 0.001f * static_cast<float>(static_cast<int>(i % 31) - 15);
        for (size_t i = 0; i < key_cache.size(); ++i)
            key_cache[i] = 0.002f * static_cast<float>(static_cast<int>(i % 17) - 8);
        if (!QSAScoreReference(descriptor, query, rows, key_cache, pages, page_table,
                               max_pages, request, position, lengths, cpu_logits, cpu_visible, failure)) {
            std::cerr << "QSA_REFERENCE=FAIL reason=" << failure << "\n";
            return 5;
        }
        std::vector<float> gpu_logits(cpu_logits.size(), 0.0f);
        std::vector<uint32_t> gpu_visible(rows, 0);
        HostBuffer q, k, p, rq, po, le, l, v;
        bool ok = Upload(vk, query, q, failure) && Upload(vk, key_cache, k, failure) &&
                  Upload(vk, page_table, p, failure) && Upload(vk, request, rq, failure) &&
                  Upload(vk, position, po, failure) && Upload(vk, lengths, le, failure) &&
                  Upload(vk, gpu_logits, l, failure) && Upload(vk, gpu_visible, v, failure);
        struct Push { uint32_t rows, heads, key_dim, page_size, ratio, max_pages, requests, reserved; } push{
            rows, descriptor.index_heads, descriptor.key_dim, descriptor.page_size,
            descriptor.compress_ratio, max_pages, requests, 0};
        std::vector<HostBuffer*> buffers{&q, &k, &p, &rq, &po, &le, &l, &v};
        ok = ok && vk.Dispatch(qsa_shader, 8, &push, sizeof(push), buffers, 1, failure);
        ok = ok && l.Download(gpu_logits.data(), gpu_logits.size() * sizeof(float));
        ok = ok && v.Download(gpu_visible.data(), gpu_visible.size() * sizeof(uint32_t));
        bool pass = ok && gpu_visible == cpu_visible;
        double max_abs = 0.0, cosine = 0.0;
        for (size_t idx = 0; idx < cpu_logits.size(); ++idx) {
            if (std::isfinite(cpu_logits[idx]) && std::isfinite(gpu_logits[idx])) {
                max_abs = std::max(max_abs, std::fabs(static_cast<double>(cpu_logits[idx]) - gpu_logits[idx]));
            } else if (std::isfinite(cpu_logits[idx]) != std::isfinite(gpu_logits[idx])) {
                pass = false;
            }
        }
        std::vector<float> cpu_finite, gpu_finite;
        for (size_t idx = 0; idx < cpu_logits.size(); ++idx) {
            if (std::isfinite(cpu_logits[idx])) {
                cpu_finite.push_back(cpu_logits[idx]);
                gpu_finite.push_back(gpu_logits[idx]);
            }
        }
        if (!cpu_finite.empty()) pass = pass && Close(cpu_finite, gpu_finite, 2.0e-5f, max_abs, cosine);
        all_pass = all_pass && pass;
        std::cout << "QSA_GPU_DISPATCH=" << (pass ? "PASS" : "FAIL")
                  << " max_abs=" << max_abs << " cosine=" << cosine << "\n";
        q.Destroy(); k.Destroy(); p.Destroy(); rq.Destroy(); po.Destroy(); le.Destroy(); l.Destroy(); v.Destroy();
    }

    {
        SparseMoEDescriptor descriptor{};
        std::vector<float> hidden(descriptor.hidden), router(static_cast<size_t>(descriptor.hidden) * descriptor.experts);
        for (size_t i = 0; i < hidden.size(); ++i)
            hidden[i] = 0.001f * static_cast<float>(static_cast<int>(i % 23) - 11);
        for (size_t i = 0; i < router.size(); ++i)
            router[i] = 0.0001f * static_cast<float>(static_cast<int>(i % 19) - 9);
        std::vector<uint32_t> ids;
        std::vector<float> weights;
        if (!SparseMoERouteReference(descriptor, hidden, router, ids, weights, failure)) {
            std::cerr << "MOE_REFERENCE=FAIL reason=" << failure << "\n";
            return 6;
        }
        std::vector<float> cpu_logits(descriptor.experts, 0.0f), gpu_logits(cpu_logits.size(), 0.0f);
        for (uint32_t expert = 0; expert < descriptor.experts; ++expert) {
            double value = 0.0;
            for (uint32_t i = 0; i < descriptor.hidden; ++i)
                value += static_cast<double>(hidden[i]) * router[static_cast<size_t>(i) * descriptor.experts + expert];
            cpu_logits[expert] = static_cast<float>(value);
        }
        HostBuffer h, r, l;
        bool ok = Upload(vk, hidden, h, failure) && Upload(vk, router, r, failure) &&
                  Upload(vk, gpu_logits, l, failure);
        struct Push { uint32_t hidden_width, experts, top_k, reserved; } push{
            descriptor.hidden, descriptor.experts, descriptor.top_k, 0};
        std::vector<HostBuffer*> buffers{&h, &r, &l};
        ok = ok && vk.Dispatch(moe_shader, 3, &push, sizeof(push), buffers, 8, failure);
        ok = ok && l.Download(gpu_logits.data(), gpu_logits.size() * sizeof(float));
        double max_abs = 0.0, cosine = 0.0;
        const bool pass = ok && Close(cpu_logits, gpu_logits, 5.0e-4f, max_abs, cosine);
        all_pass = all_pass && pass;
        std::cout << "MOE_ROUTER_GPU_DISPATCH=" << (pass ? "PASS" : "FAIL")
                  << " max_abs=" << max_abs << " cosine=" << cosine
                  << " selected=" << ids.size() << "\n";
        h.Destroy(); r.Destroy(); l.Destroy();
    }

    std::cout << "QWEN4EXP_OPERATOR_GPU=" << (all_pass ? "PASS" : "FAIL") << "\n";
    std::cout << "QWEN4EXP_EXPERT_GEMM=FAIL_CLOSED_UNDEQUANTIZED\n";
    std::cout << "QWEN4EXP_FULL_MODEL=NOT_CERTIFIED\n";
    return all_pass ? 0 : 7;
}
