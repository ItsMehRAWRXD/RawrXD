// ============================================================================
// AdapterIdentity.hpp — DEEP2_ADAPTER_IDENTITY_001
//
// Exact DXGI <-> Vulkan adapter correlation.  Vendor/device-only matching is
// ambiguous when two identical adapters are present, so it must NOT authorize
// strict residency admission.  Only an exact 8-byte LUID match is authoritative.
//
// Dependency-free and unit-testable: it operates on plain fields (AdapterRef),
// not on Vulkan handles, so the same decision table is exercised by production
// (Deep2Engine_ModelFit) and by the acceptance test.
// ============================================================================
#ifndef RAWRXD_DEEP2_ADAPTER_IDENTITY_HPP
#define RAWRXD_DEEP2_ADAPTER_IDENTITY_HPP

#include <cstdint>
#include <vector>

namespace Deep2 {

// One Vulkan physical adapter, reduced to identity + capability fields.
struct AdapterRef {
    uint64_t luid = 0;
    bool luidValid = false;
    uint32_t vendorId = 0;
    uint32_t deviceId = 0;
    bool compute = false;
    bool discrete = false;
    uint64_t deviceLocalBytes = 0;
};

struct AdapterMatch {
    bool exact = false;          // matched by full 8-byte LUID
    bool ambiguous = false;      // only vendor/device matched (or nothing)
    bool compute = false;
    bool discrete = false;
    uint64_t deviceLocalBytes = 0;
};

// Correlate a DXGI adapter (luid, vendor, device) to a Vulkan adapter.
//  - exact LUID match  -> authoritative (exact=true)
//  - otherwise         -> ambiguous vendor/device best-effort (ambiguous=true),
//                         which callers must treat as NON-strict for admission.
inline AdapterMatch matchAdapter(uint64_t dxgiLuid,
                                 uint32_t vendorId,
                                 uint32_t deviceId,
                                 const std::vector<AdapterRef>& vk) {
    AdapterMatch m{};
    if (dxgiLuid) {
        for (const auto& v : vk) {
            if (v.luidValid && v.luid == dxgiLuid) {
                m.exact = true;
                m.compute = v.compute;
                m.discrete = v.discrete;
                m.deviceLocalBytes = v.deviceLocalBytes;
                return m;
            }
        }
    }
    // Ambiguous fallback: never exact, never strict.
    for (const auto& v : vk) {
        if (v.vendorId == vendorId && v.deviceId == deviceId) {
            m.compute = m.compute || v.compute;
            m.discrete = m.discrete || v.discrete;
            break;
        }
    }
    m.ambiguous = true;
    return m;
}

} // namespace Deep2

#endif // RAWRXD_DEEP2_ADAPTER_IDENTITY_HPP