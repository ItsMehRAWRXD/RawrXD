// Stub header: license_enforcement.h
// Minimal declarations to satisfy #include references.
#pragma once

namespace RawrXD::Enterprise {

class LicenseEnforcement {
public:
    static LicenseEnforcement& Instance();
    bool Validate() const { return true; }
    bool IsEnterpriseLicensed() const { return true; }
};

} // namespace RawrXD::Enterprise
