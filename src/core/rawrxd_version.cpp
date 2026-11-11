// ============================================================================
// RawrXD Version System Implementation
// ============================================================================

#include "../../include/rawrxd_version.hpp"
#include <cstdio>

namespace RawrXD {

// Thread-local buffer for version string
static thread_local char versionBuffer[32];

const char* GetVersionString() {
    snprintf(versionBuffer, sizeof(versionBuffer), "%d.%d.%d.%d",
             RAWRXD_VERSION_MAJOR, RAWRXD_VERSION_MINOR,
             RAWRXD_VERSION_PATCH, RAWRXD_VERSION_BUILD);
    return versionBuffer;
}

} // namespace RawrXD

// C API Implementation
extern "C" {

const char* RawrXD_GetVersionString() {
    return RawrXD::GetVersionString();
}

void RawrXD_GetVersionNumbers(uint32_t* major, uint32_t* minor, 
                              uint32_t* patch, uint32_t* build) {
    if (major) *major = RAWRXD_VERSION_MAJOR;
    if (minor) *minor = RAWRXD_VERSION_MINOR;
    if (patch) *patch = RAWRXD_VERSION_PATCH;
    if (build) *build = RAWRXD_VERSION_BUILD;
}

int RawrXD_IsVersionCompatible(uint32_t major1, uint32_t minor1,
                                uint32_t major2, uint32_t minor2) {
    // Major version must match, minor can differ
    return (major1 == major2) ? 1 : 0;
}

} // extern "C"

// Export for Windows DLL
#pragma comment(linker, "/EXPORT:RawrXD_GetVersionString")
#pragma comment(linker, "/EXPORT:RawrXD_GetVersionNumbers")
#pragma comment(linker, "/EXPORT:RawrXD_IsVersionCompatible")
