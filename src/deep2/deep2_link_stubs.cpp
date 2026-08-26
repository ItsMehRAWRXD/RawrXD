// ============================================================================
// deep2_link_stubs.cpp — Honest stubs for symbols NOT provided by real TUs
// ============================================================================

#include "vulkan_compute.h"
#include <vector>
#include <cstring>

namespace CPUInference {

// VulkanCompute stubs
VulkanCompute::VulkanCompute() {}
VulkanCompute::~VulkanCompute() {}
bool VulkanCompute::Initialize() { return false; }
bool VulkanCompute::DispatchGEMV(const float*, const float*, float*, unsigned int, unsigned int) {
    return false;
}

} // namespace CPUInference
