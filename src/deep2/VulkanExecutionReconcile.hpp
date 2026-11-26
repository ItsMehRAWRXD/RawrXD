// VulkanExecutionReconcile.hpp — OWN-02..09
//
// Binds locked-profile admission to the ACTUAL Vulkan execution devices owned
// by GGMLBackend (rawrxd::VulkanContext) and Deep2::GpuDmaSession, rather than
// to whatever adapters the host inventory happens to list first. It:
//   * consumes lifetime-safe, non-owning handles from the execution owner
//     (OWN-02/03),
//   * cross-checks the Vulkan deviceLUID against the Deep2 device-manager LUID
//     (OWN-04),
//   * normalizes lane order R9700 -> 0, RX 7800 XT -> 1 (OWN-05),
//   * queries the Vulkan current budget via VK_EXT_memory_budget (OWN-06),
//   * reconciles Vulkan vs DXGI budget provenance (OWN-07),
//   * propagates device-loss / initialized state into health (OWN-09).
//
// The caller (engine, after device init and before model execution) fills the
// ExecutionDeviceRecord vector from the initialized owners and calls
// ReconcileForAdmission to produce the admission device list.
#pragma once
#include "DualGpuAdmissionTelemetry.hpp"
#include "VulkanMemoryBudget.hpp"
#include "Deep2DeviceManager.hpp"
#include <vulkan/vulkan.h>
#include <vector>
#include <cstdint>
#include <algorithm>

namespace rawrxd {
namespace dualgpu {

// Non-owning snapshot of one execution device. Lifetime is the owner's
// (VulkanContext / GpuDmaSession); do not destroy through this struct.
struct ExecutionDeviceRecord {
    VkPhysicalDevice phys      = VK_NULL_HANDLE;
    VkDevice         dev       = VK_NULL_HANDLE;
    VkQueue          queue     = VK_NULL_HANDLE;
    uint32_t         qfam      = 0;
    uint64_t         deviceLUID = 0;   // from vkGetPhysicalDeviceProperties2
    uint64_t         measuredCapBytes = 0; // owner-provided current budget
    bool             budgetKnown = false;  // true => measuredCapBytes is authoritative (incl. valid 0)
    bool             initialized = false; // logical device + compute queue ready
    bool             deviceLost  = false; // runtime device-loss state
};

// OWN-04: query the Vulkan device-local LUID (8 bytes, little-endian).
inline uint64_t QueryDeviceLUID(VkPhysicalDevice pd,
                                PFN_vkGetPhysicalDeviceProperties2 fn) {
    if (!pd || !fn) return 0;
    VkPhysicalDeviceIDProperties idp{};
    idp.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES;
    VkPhysicalDeviceProperties2 p{};
    p.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
    p.pNext = &idp;
    fn(pd, &p);
    if (!idp.deviceLUIDValid) return 0; // reject invalid Vulkan LUID
    uint64_t luid = 0;
    for (int i = 0; i < 8; ++i)
        luid |= static_cast<uint64_t>(idp.deviceLUID[i]) << (8 * i);
    return luid;
}

// Convenience: build a record from raw handles (caller supplies the LUID it
// obtained from QueryDeviceLUID using the owner's function pointers).
inline ExecutionDeviceRecord MakeRecord(VkPhysicalDevice phys, VkDevice dev,
                                        VkQueue queue, uint32_t qfam,
                                        uint64_t deviceLUID, bool initialized,
                                        bool deviceLost) {
    ExecutionDeviceRecord r;
    r.phys = phys; r.dev = dev; r.queue = queue; r.qfam = qfam;
    r.deviceLUID = deviceLUID; r.initialized = initialized;
    r.deviceLost = deviceLost;
    return r;
}

// OWN-04..09: reconcile execution devices with the device manager and produce
// the admission list. Returns false (fail closed) if fewer than two healthy,
// initialized, budget-known execution devices can be reconciled.
inline bool ReconcileForAdmission(const std::vector<ExecutionDeviceRecord>& exec,
                                  const Deep2::DeviceManagerSnapshot& dmgr,
                                  std::vector<DualGpuDevice>& out) {
    out.clear();
    for (const auto& e : exec) {
        // OWN-09 + handle validation: require initialized, non-null logical
        // device and compute queue, and no device loss.
        if (!e.initialized || e.deviceLost || !e.phys || !e.dev || !e.queue) continue;
        // OWN-04: match to a device-manager entry by exact LUID.
        const Deep2::DeviceIdentity* match = nullptr;
        if (e.deviceLUID != 0) {
            for (unsigned i = 0; i < dmgr.deviceCount && i < 8; ++i) {
                if (dmgr.devices[i].luid == e.deviceLUID) { match = &dmgr.devices[i]; break; }
            }
        }
        DualGpuDevice d;
        d.stableId = match ? match->stableId : "";
        d.name     = match ? match->name     : "";
        d.vendorId = match ? match->vendorId : 0;
        d.deviceId = match ? match->deviceId : 0;
        // OWN-06/07: prefer the owner-provided current budget (authoritative,
        // incl. a valid 0); else the Vulkan EXT budget; else the manager's
        // measured free VRAM. Never capacity. Unknown -> 0 -> fail closed.
        uint64_t budget = 0;
        if (e.budgetKnown) {
            budget = e.measuredCapBytes;
        } else {
            const vkbudget::DeviceMemoryBudget b = vkbudget::QueryDeviceMemoryBudget(e.phys);
            if (b.provenanceIsBudget) budget = b.availableHeadroomBytes;
            else if (match && match->availableVramKnown) budget = match->availableVram;
        }
        d.measuredCapBytes = budget;
        d.identityExact = (match != nullptr) && (e.deviceLUID != 0);
        // OWN-09: reconcile Vulkan runtime health with device-manager PnP health.
        d.healthy       = e.initialized && !e.deviceLost && (match && match->healthy);
        out.push_back(d);
    }
    // OWN-05: normalize lane order R9700 -> 0, RX 7800 XT -> 1, others last.
    auto laneOf = [](const DualGpuDevice& d) -> int {
        if (ContainsCaseInsensitive(d.name, "R9700")) return 0;
        if (ContainsCaseInsensitive(d.name, "7800"))  return 1;
        return 2;
    };
    std::stable_sort(out.begin(), out.end(),
        [&](const DualGpuDevice& a, const DualGpuDevice& b) {
            return laneOf(a) < laneOf(b);
        });
    // Final authority is AdmitLockedProfile (exact-two, identity, budget,
    // health), not a raw record count — invalid records are rejected here.
    return AdmitLockedProfile(out).admitted;
}

} // namespace dualgpu
} // namespace rawrxd