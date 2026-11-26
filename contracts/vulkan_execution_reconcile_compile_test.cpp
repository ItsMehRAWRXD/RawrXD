// Compile check for VulkanExecutionReconcile.hpp (OWN-02..09).
// Validates the reconcile logic compiles against real Vulkan + device-manager
// headers. Does not run hardware (no VkPhysicalDevice is created here).
#include "VulkanExecutionReconcile.hpp"

int main() {
    rawrxd::dualgpu::ExecutionDeviceRecord r{};
    (void)r;
    uint64_t luid = rawrxd::dualgpu::QueryDeviceLUID(VK_NULL_HANDLE, nullptr);
    (void)luid;
    Deep2::DeviceManagerSnapshot snap{};
    std::vector<rawrxd::dualgpu::DualGpuDevice> out;
    bool ok = rawrxd::dualgpu::ReconcileForAdmission({}, snap, out);
    (void)ok;
    return 0;
}