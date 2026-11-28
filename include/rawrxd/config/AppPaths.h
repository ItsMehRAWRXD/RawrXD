#pragma once

#include <string>

namespace rawrxd::config {

// Portable application path resolution (M-CFG-02 / M-CFG-07).
// Resolution order:
//   applicationRoot : RAWRXD_HOME -> executable directory
//   configDir       : RAWRXD_CONFIG_DIR -> %LOCALAPPDATA%/RawrXD/config
//   cacheDir        : RAWRXD_CACHE_DIR  -> %LOCALAPPDATA%/RawrXD/cache
//   logDir          : RAWRXD_LOG_DIR    -> %LOCALAPPDATA%/RawrXD/logs
//   modelDir        : RAWRXD_MODELS_DIR -> <root>/models
// No drive letters are hardcoded.
struct AppPaths {
    std::string executableDir;
    std::string applicationRoot;
    std::string configDir;
    std::string cacheDir;
    std::string logDir;
    std::string modelDir;

    static AppPaths resolve();

    std::string configFile() const;
    std::string registryFile() const;
    std::string logFile() const;
};

} // namespace rawrxd::config