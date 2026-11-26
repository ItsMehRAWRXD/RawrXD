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
    // LIFE-06A/06B: populate physical-device, logical-device, queue and family.
    r.phys        = s->PhysicalHandle();
    r.dev         = s->DeviceHandle();
    r.queue       = s->ComputeQueue();
    r.qfam        = s->ComputeQueueFamily();
    r.initialized = s->initialized() && s->computeReady() && r.queue != VK_NULL_HANDLE;
    const auto& pi = s->physicalInfo();
    r.deviceLUID  = pi.luidValid ? pi.luid : 0;
    // LIFE-11A/11B: real synchronized runtime device-loss state.
    r.deviceLost  = s->DeviceLost();
    // LIFE-06C: preserve explicit budget provenance; a valid 0 is distinct
    // from an unavailable measurement (budgetKnown).
    if (r.phys) {
        const vkbudget::DeviceMemoryBudget b = vkbudget::QueryDeviceMemoryBudget(r.phys);
        if (b.provenanceIsBudget) {
            r.measuredCapBytes = b.availableHeadroomBytes;
            r.budgetKnown = true;
        }
    }
    return r;
}

} // namespace dualgpu
} // namespace rawrxd