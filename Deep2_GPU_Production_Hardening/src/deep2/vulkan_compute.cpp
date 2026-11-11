// ============================================================================
// vulkan_compute.cpp — Deep2 GPU Production Hardening (P0-A, P0-B, P1)
// Implements:
//   - Real GPU timestamp queries (gpu_ms, host_wait_ms, submit_cpu_ms)
//   - Batched command buffer submissions (BeginBatch/EndBatch)
//   - Pipeline cache for bind-phase optimization
//   - Total device-local weight allocation tracking
// ============================================================================

#include "vulkan_compute.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <iostream>

namespace Deep2 {

// ============================================================================
// Batch Submission Implementation (P0-B)
// ============================================================================

bool VulkanCompute::BeginBatch(GpuWorkKind kind, uint64_t epoch) {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);

    if (batchActive_) {
        // Nested batch not supported; end current first
        EndBatch(nullptr);
    }

    VkCommandBuffer cmd = VK_NULL_HANDLE;
    VkQueryPool query = VK_NULL_HANDLE;

    if (!beginCommand(cmd, query, true)) {
        return false;
    }

    batch_ = {};
    batch_.cmd = cmd;
    batch_.query = query;
    batch_.kind = kind;
    batch_.epoch = epoch;
    batch_.active = true;
    batchDispatchCount_ = 0;

    return true;
}

bool VulkanCompute::EndBatch(GpuWorkInterval* interval) {
    std::lock_guard<std::recursive_mutex> lock(apiMu_);

    if (!batchActive_ || !batch_.cmd) {
        return false;
    }

    VkCommandBuffer cmd = batch_.cmd;
    VkQueryPool query = batch_.query;

    // Write bottom timestamp
    if (query) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, query, 1);
    }
    if (vkEndCommandBuffer(cmd) != VK_SUCCESS) {
        return false;
    }

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    if (vkCreateFence(device_, &fi, nullptr, &fence) != VK_SUCCESS) {
        if (query) vkDestroyQueryPool(device_, query, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
        batch_ = {};
        return false;
    }
    batch_.fence = fence;

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;

    const uint64_t hostSubmitNs = nowNs();
    batch_.hostSubmitNs = hostSubmitNs;

    auto submit_start = std::chrono::high_resolution_clock::now();
    VkResult submit = vkQueueSubmit(queue_, 1, &si, fence);
    double submit_cpu_ms = std::chrono::duration<double, std::milli>(
        std::chrono::high_resolution_clock::now() - submit_start).count();

    if (submit != VK_SUCCESS) {
        vkDestroyFence(device_, fence, nullptr);
        if (query) vkDestroyQueryPool(device_, query, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
        batch_ = {};
        return false;
    }

    gpu_counters_.submits += 1;
    gpu_counters_.submit_cpu_ms += submit_cpu_ms;

    VkResult wait = vkWaitForFences(device_, 1, &fence, VK_TRUE, UINT64_MAX);
    const uint64_t hostCompleteNs = nowNs();

    if (wait == VK_SUCCESS) {
        gpu_counters_.waits += 1;

        GpuWorkInterval wi{};
        if (finalizeInterval(query, hostSubmitNs, hostCompleteNs,
                             batch_.epoch, batch_.bytes, batch_.kind, wi)) {
            // Accumulate real GPU time
            if (wi.calibrated && wi.gpuEndNs >= wi.gpuStartNs) {
                double gpu_ns = static_cast<double>(wi.gpuEndNs - wi.gpuStartNs);
                gpu_counters_.gpu_ms += gpu_ns / 1e6;
            }
            double host_wait_ns = static_cast<double>(hostCompleteNs - hostSubmitNs);
            gpu_counters_.host_wait_ms += host_wait_ns / 1e6;

            // Legacy aliases
            gpu_counters_.kernel_ms = gpu_counters_.host_wait_ms + gpu_counters_.submit_cpu_ms;
            gpu_counters_.wait_ms = gpu_counters_.host_wait_ms;
            gpu_counters_.submit_ms = gpu_counters_.submit_cpu_ms;

            recordInterval(wi);
            if (interval) *interval = wi;
        }
    }

    vkDestroyFence(device_, fence, nullptr);
    if (query) vkDestroyQueryPool(device_, query, nullptr);
    vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);

    batch_ = {};
    batchActive_ = false;
    return wait == VK_SUCCESS;
}

bool VulkanCompute::DispatchOpsBatched(DeviceBuf& a, DeviceBuf& b, DeviceBuf& c, DeviceBuf& d,
                                       const OpsPush& push, uint32_t groupsX) {
    if (!batchActive_ || !batch_.cmd) return false;

    // Record barrier if this is not the first dispatch and previous was quant
    if (batchDispatchCount_ > 0) {
        recordComputeBarrier(batch_.cmd);
    }

    // Bind pipeline and descriptor
    vkCmdBindPipeline(batch_.cmd, VK_PIPELINE_BIND_POINT_COMPUTE, opsPipeline_);
    VkDescriptorSet set = getOpsDescriptor(a, b, c, d);
    vkCmdBindDescriptorSets(batch_.cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            opsPipelineLayout_, 0, 1, &set, 0, nullptr);

    // Record dispatch
    vkCmdDispatch(batch_.cmd, groupsX, 1, 1);

    batch_.bytes += (a.size + b.size + c.size + d.size);
    batchDispatchCount_++;
    increment_dispatch_count();

    return true;
}

bool VulkanCompute::DispatchQuantBatched(DeviceBuf& weights, DeviceBuf& input, DeviceBuf& output,
                                         const QPush& push) {
    if (!batchActive_ || !batch_.cmd) return false;

    if (batchDispatchCount_ > 0) {
        recordComputeBarrier(batch_.cmd);
    }

    vkCmdBindPipeline(batch_.cmd, VK_PIPELINE_BIND_POINT_COMPUTE, qPipeline_);
    VkDescriptorSet set = getQuantDescriptor(weights, input, output);
    vkCmdBindDescriptorSets(batch_.cmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            qPipelineLayout_, 0, 1, &set, 0, nullptr);

    vkCmdDispatch(batch_.cmd, (push.rows + 255) / 256, 1, 1);

    batch_.bytes += weights.size + input.size + output.size;
    batchDispatchCount_++;
    increment_dispatch_count();

    return true;
}

// ============================================================================
// Pipeline Cache (P1)
// ============================================================================

bool VulkanCompute::createPipelineCache() {
    VkPipelineCacheCreateInfo pci{};
    pci.sType = VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO;
    pci.flags = 0;
    pci.initialDataSize = 0;
    pci.pInitialData = nullptr;

    VkResult res = vkCreatePipelineCache(device_, &pci, nullptr, &pipelineCache_);
    if (res != VK_SUCCESS) {
        pipelineCache_ = VK_NULL_HANDLE;
        return false;
    }
    return true;
}

void VulkanCompute::destroyPipelineCache() {
    if (pipelineCache_) {
        vkDestroyPipelineCache(device_, pipelineCache_, nullptr);
        pipelineCache_ = VK_NULL_HANDLE;
    }
}

// ============================================================================
// Updated Pipeline Creation (uses cache)
// ============================================================================

bool VulkanCompute::createPipelineFromFile(const std::string& file,
                                           VkDescriptorSetLayout layout,
                                           uint32_t pushBytes,
                                           VkPipelineLayout& pipelineLayout,
                                           VkPipeline& pipeline) {
    // ... existing pipeline layout creation ...

    VkPipelineShaderStageCreateInfo stage{};
    stage.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage.stage = VK_SHADER_STAGE_COMPUTE_BIT;
    stage.module = shaderModule;
    stage.pName = "main";

    VkComputePipelineCreateInfo pci{};
    pci.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pci.stage = stage;
    pci.layout = pipelineLayout;
    pci.flags = VK_PIPELINE_CREATE_ALLOW_DERIVATIVES_BIT;

    // Use pipeline cache if available
    VkResult res = vkCreateComputePipelines(device_, pipelineCache_, 1, &pci, nullptr, &pipeline);

    if (res != VK_SUCCESS) {
        // Fallback without cache
        res = vkCreateComputePipelines(device_, VK_NULL_HANDLE, 1, &pci, nullptr, &pipeline);
    }

    return res == VK_SUCCESS;
}

// ============================================================================
// Counter Updates at Allocation Sites (P1)
// ============================================================================

bool VulkanCompute::createBuffer(VkDeviceSize bytes, VkBufferUsageFlags usage,
                                 VkMemoryPropertyFlags required,
                                 DeviceBuf& out) {
    // ... existing buffer creation ...

    VkMemoryRequirements mr;
    vkGetBufferMemoryRequirements(device_, buffer, &mr);

    // Track DEVICE_LOCAL allocations for total residency
    if ((required & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) != 0) {
        gpu_counters_.total_device_weight_bytes += mr.size;
        if (gpu_counters_.total_device_weight_bytes > gpu_counters_.total_device_weight_peak) {
            gpu_counters_.total_device_weight_peak = gpu_counters_.total_device_weight_bytes;
        }
    }

    // ... existing memory allocation and binding ...
    gpu_counters_.buffer_allocations++;

    return true;
}

void VulkanCompute::destroyBuffer(DeviceBuf& b) {
    if (b.buffer) {
        // Subtract from total if DEVICE_LOCAL
        if (b.memory && (b.memoryFlags & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT)) {
            if (gpu_counters_.total_device_weight_bytes >= b.size) {
                gpu_counters_.total_device_weight_bytes -= b.size;
            }
        }
        vkDestroyBuffer(device_, b.buffer, nullptr);
        b.buffer = VK_NULL_HANDLE;
    }
    if (b.memory) {
        vkFreeMemory(device_, b.memory, nullptr);
        b.memory = VK_NULL_HANDLE;
    }
    b.size = 0;
    b.id = 0;
}

// ============================================================================
// Timestamp Query Pool (P0-A)
// ============================================================================

bool VulkanCompute::beginCommand(VkCommandBuffer& cmd, VkQueryPool& query, bool timestamped) {
    VkCommandBufferAllocateInfo ai{};
    ai.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO;
    ai.commandPool = commandPool_;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = 1;
    if (vkAllocateCommandBuffers(device_, &ai, &cmd) != VK_SUCCESS) {
        return false;
    }

    if (timestamped && timestampValidBits_ > 0) {
        VkQueryPoolCreateInfo qci{};
        qci.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        qci.queryType = VK_QUERY_TYPE_TIMESTAMP;
        qci.queryCount = 2;
        qci.pipelineStatistics = 0;
        if (vkCreateQueryPool(device_, &qci, nullptr, &query) != VK_SUCCESS) {
            query = VK_NULL_HANDLE;
        }
    }

    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    if (vkBeginCommandBuffer(cmd, &bi) != VK_SUCCESS) {
        if (query) vkDestroyQueryPool(device_, query, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
        cmd = VK_NULL_HANDLE;
        query = VK_NULL_HANDLE;
        return false;
    }

    if (query) {
        vkCmdResetQueryPool(cmd, query, 0, 2);
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, query, 0);
    }
    return true;
}

bool VulkanCompute::finalizeInterval(VkQueryPool query, uint64_t hostSubmitNs,
                                     uint64_t hostCompleteNs, uint64_t epoch,
                                     uint64_t bytes, GpuWorkKind kind,
                                     GpuWorkInterval& out) {
    out = {};
    out.epoch = epoch;
    out.hostSubmitNs = hostSubmitNs;
    out.hostCompleteNs = hostCompleteNs;
    out.bytes = bytes;
    out.deviceOrdinal = requestedOrdinal_;
    out.kind = kind;

    if (!query) return true;

    uint64_t q[2]{};
    VkResult vr = vkGetQueryPoolResults(
        device_, query, 0, 2, sizeof(q), q, sizeof(uint64_t),
        VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT);
    if (vr != VK_SUCCESS) return true;

    uint64_t s = 0, e = 0;
    if (calibrateTick(q[0], s) && calibrateTick(q[1], e) && e >= s) {
        out.gpuStartNs = s;
        out.gpuEndNs = e;
        out.calibrated = true;
    }
    return true;
}

// ============================================================================
// Updated endSubmitWait with real GPU timing (P0-A)
// ============================================================================

bool VulkanCompute::endSubmitWait(VkCommandBuffer cmd, VkQueryPool query,
                                  GpuWorkKind kind, uint64_t bytes, uint64_t epoch,
                                  GpuWorkInterval* interval) {
    if (!cmd) return false;

    if (query) {
        vkCmdWriteTimestamp(cmd, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, query, 1);
    }
    if (vkEndCommandBuffer(cmd) != VK_SUCCESS) return false;

    VkFenceCreateInfo fi{};
    fi.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
    VkFence fence = VK_NULL_HANDLE;
    if (vkCreateFence(device_, &fi, nullptr, &fence) != VK_SUCCESS) {
        if (query) vkDestroyQueryPool(device_, query, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
        return false;
    }

    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;

    const uint64_t hostSubmitNs = nowNs();

    auto submit_start = std::chrono::high_resolution_clock::now();
    VkResult submit = vkQueueSubmit(queue_, 1, &si, fence);
    double submit_cpu_ms = std::chrono::duration<double, std::milli>(
        std::chrono::high_resolution_clock::now() - submit_start).count();

    if (submit != VK_SUCCESS) {
        vkDestroyFence(device_, fence, nullptr);
        if (query) vkDestroyQueryPool(device_, query, nullptr);
        vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
        return false;
    }

    gpu_counters_.submits += 1;
    gpu_counters_.submit_cpu_ms += submit_cpu_ms;

    VkResult wait = vkWaitForFences(device_, 1, &fence, VK_TRUE, UINT64_MAX);
    const uint64_t hostCompleteNs = nowNs();

    if (wait == VK_SUCCESS) {
        gpu_counters_.waits += 1;

        GpuWorkInterval wi{};
        if (finalizeInterval(query, hostSubmitNs, hostCompleteNs, epoch, bytes, kind, wi)) {
            if (wi.calibrated && wi.gpuEndNs >= wi.gpuStartNs) {
                double gpu_ns = static_cast<double>(wi.gpuEndNs - wi.gpuStartNs);
                gpu_counters_.gpu_ms += gpu_ns / 1e6;
            }
            double host_wait_ns = static_cast<double>(hostCompleteNs - hostSubmitNs);
            gpu_counters_.host_wait_ms += host_wait_ns / 1e6;

            gpu_counters_.kernel_ms = gpu_counters_.host_wait_ms + gpu_counters_.submit_cpu_ms;
            gpu_counters_.wait_ms = gpu_counters_.host_wait_ms;
            gpu_counters_.submit_ms = gpu_counters_.submit_cpu_ms;

            recordInterval(wi);
            if (interval) *interval = wi;
        }
    }

    vkDestroyFence(device_, fence, nullptr);
    if (query) vkDestroyQueryPool(device_, query, nullptr);
    vkFreeCommandBuffers(device_, commandPool_, 1, &cmd);
    return wait == VK_SUCCESS;
}

// ============================================================================
// Material upload with GPU timing
// ============================================================================

bool VulkanCompute::SubmitMaterialUploadAsync(const void* src, size_t bytes,
                                              uint64_t epoch, MaterialTicket& ticket) {
    // ... existing implementation ...
    // Ensure it calls endSubmitWait with proper timing
    return endSubmitWait(ticket.cmd, ticket.query, GpuWorkKind::ModelTransfer,
                         bytes, epoch, nullptr);
}

bool VulkanCompute::WaitMaterialUpload(MaterialTicket& ticket, GpuWorkInterval* interval) {
    // ... existing implementation using finalizeInterval ...
    return true;
}

// ============================================================================
// Pipeline cache init in device creation
// ============================================================================

bool VulkanCompute::createDevice() {
    // ... existing device creation ...

    // Create pipeline cache
    if (!createPipelineCache()) {
        // Non-fatal, continue without cache
    }

    return true;
}

void VulkanCompute::cleanup() {
    destroyPipelineCache();
    // ... existing cleanup ...
}

} // namespace Deep2