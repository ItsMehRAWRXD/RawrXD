#include "Version.hpp"

namespace RawrXD {

// Build-time populated values (defaults for development builds)
#ifndef RAWRXD_GIT_COMMIT
#define RAWRXD_GIT_COMMIT "unknown"
#endif

#ifndef RAWRXD_BUILD_TIMESTAMP
#define RAWRXD_BUILD_TIMESTAMP __DATE__ " " __TIME__
#endif

namespace {
    // Static version info instance
    const VersionInfo s_versionInfo = {
        RAWRXD_VERSION_MAJOR,
        RAWRXD_VERSION_MINOR,
        RAWRXD_VERSION_PATCH,
        RAWRXD_VERSION_BUILD,
        RAWRXD_PROTOCOL_VERSION,
        RAWRXD_VERSION_FULL,
        RAWRXD_VERSION_CODENAME,
        RAWRXD_GIT_COMMIT,
        RAWRXD_BUILD_TIMESTAMP
    };
}

const VersionInfo& GetVersionInfo() noexcept {
    return s_versionInfo;
}

} // namespace RawrXD
