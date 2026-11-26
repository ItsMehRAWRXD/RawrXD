// Compile check: extract a record from the engine's real slot type
// (CPUInference::VulkanCompute, as returned by getVulkanComputeSlot).
#include "vulkan_compute_cpu_ns.hpp"
#include "vulkan_compute.h"
#include "VulkanComputeExtract.hpp"

int main() {
    CPUInference::VulkanCompute* slot = nullptr;
    auto r = rawrxd::dualgpu::RecordFromCpuSlot(slot);
    return (r.dev == VK_NULL_HANDLE && r.phys == VK_NULL_HANDLE) ? 0 : 1;
}