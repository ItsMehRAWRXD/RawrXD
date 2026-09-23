// Stub header: license_enforcement.h
// Minimal declarations to satisfy #include references.
#pragma once
#include "enterprise_license.h"
#include <cstdint>

namespace RawrXD::Enforce {

enum class SubsystemID : uint32_t {
    DualEngine = 0,
    Quantization,
    Inference,
    MultiGPULoadBalance,
    COUNT
};

class LicenseEnforcer {
public:
    static LicenseEnforcer& Instance() {
        static LicenseEnforcer s;
        return s;
    }

    // Overload 1: (SubsystemID, FeatureID, uint32_t version)
    bool allow(SubsystemID /*subsystem*/,
               RawrXD::License::FeatureID /*feature*/,
               uint32_t /*version*/ = 0) const {
        return true;
    }

    // Overload 2: (FeatureID, const char* context) used by native_speed_layer etc.
    bool allow(RawrXD::License::FeatureID /*feature*/,
               const char* /*context*/ = nullptr) const {
        return true;
    }

    // Overload 3: (SubsystemID, FeatureID, const char* context) used by local_ai_core etc.
    bool allow(SubsystemID /*subsystem*/,
               RawrXD::License::FeatureID /*feature*/,
               const char* /*context*/) const {
        return true;
    }

    bool Validate() const { return true; }
    bool IsEnterpriseLicensed() const { return true; }
};

} // namespace RawrXD::Enforce
