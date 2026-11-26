// Compile check: extract a record from the real VulkanCompute owner (LIFE-06).
#include "vulkan_compute.h"
#include "VulkanComputeExtract.hpp"

int main() {
    Deep2::VulkanCompute* slot = nullptr;
    auto r = rawrxd::dualgpu::RecordFromVulkanSlot(slot);
    return (r.dev == VK_NULL_HANDLE) ? 0 : 1;
}