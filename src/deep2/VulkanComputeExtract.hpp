// VulkanComputeExtract.hpp — LIFE-06: extract a live ExecutionDeviceRecord from
// an actual Vulkan execution owner (CPUInference/Deep2::VulkanCompute as
// returned by Deep2Engine::getVulkanComputeSlot(i)). Non-owning: the slot keeps
// the device alive for the whole request (LIFE-07).
#pragma once
#include "VulkanExecutionReconcile.hpp"

namespace rawrxd {
namespace dualgpu {

template <typename SlotT>
inline ExecutionDeviceRecord RecordFromVulkanSlot(const SlotT* s) {
    ExecutionDeviceRecord r;
    if (!s) return r;
    r.dev         = s->DeviceHandle();
    r.initialized = s->initialized() && s->computeReady();
    const auto& pi = s->physicalInfo();
    r.deviceLUID  = pi.luidValid ? pi.luid : 0;
    r.deviceLost  = !r.initialized; // conservative: uninitialized == unusable
    if (auto pd = s->PhysicalHandle()) {
        const vkbudget::DeviceMemoryBudget b = vkbudget::QueryDeviceMemoryBudget(pd);
        if (b.provenanceIsBudget) r.measuredCapBytes = b.availableHeadroomBytes;
    }
    return r;
}

} // namespace dualgpu
} // namespace rawrxd