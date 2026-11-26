// Compile check for VulkanMemoryBudget.hpp (K2-L04 / MB-01..07).
// This validates that the provider compiles against the real Vulkan headers;
// it does not run hardware (no VkPhysicalDevice is created here).
#include "VulkanMemoryBudget.hpp"

int main() {
    // Reference the API so the compiler fully instantiates the templates/inline
    // bodies. Runtime hardware acceptance is separate (MB-12).
    rawrxd::vkbudget::DeviceMemoryBudget b{};
    bool ext = rawrxd::vkbudget::HasMemoryBudgetExtension(VK_NULL_HANDLE);
    (void)ext;
    uint64_t safe = rawrxd::vkbudget::SafeBudgetBytes(b, 0.8);
    (void)safe;
    return 0;
}