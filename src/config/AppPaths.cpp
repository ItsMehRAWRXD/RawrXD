#include "rawrxd/config/AppPaths.h"

#include <cstdlib>
#include <filesystem>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace rawrxd::config {
namespace {

std::string envOrEmpty(const char* name) {
#if defined(_WIN32)
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) == 0 && value) {
        std::string result(value);
        std::free(value);
        return result;
    }
#else
    const char* value = std::getenv(name);
    if (value) return std::string(value);
#endif
    return {};
}

std::string computeExecutableDir() {
#if defined(_WIN32)
    char buffer[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(nullptr, buffer, static_cast<DWORD>(sizeof(buffer)));
    if (n == 0 || n >= sizeof(buffer)) return {};
    fs::path p(buffer);
    return p.parent_path().string();
#else
    char buffer[4096] = {};
    ssize_t n = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (n <= 0) return {};
    fs::path p(std::string(buffer, static_cast<size_t>(n)));
    return p.parent_path().string();
#endif
}

std::string localAppData() {
#if defined(_WIN32)
    return envOrEmpty("LOCALAPPDATA");
#else
    const std::string home = envOrEmpty("HOME");
    if (!home.empty()) return home + "/.local/share";
    return {};
#endif
}

std::string join(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    return (fs::path(a) / b).string();
}

} // namespace

AppPaths AppPaths::resolve() {
    AppPaths p;
    p.executableDir = computeExecutableDir();

    const std::string home = envOrEmpty("RAWRXD_HOME");
    p.applicationRoot = !home.empty() ? home : p.executableDir;

    const std::string base = localAppData();
    p.configDir = envOrEmpty("RAWRXD_CONFIG_DIR");
    if (p.configDir.empty()) p.configDir = join(base, "RawrXD/config");
    p.cacheDir = envOrEmpty("RAWRXD_CACHE_DIR");
    if (p.cacheDir.empty()) p.cacheDir = join(base, "RawrXD/cache");
    p.logDir = envOrEmpty("RAWRXD_LOG_DIR");
    if (p.logDir.empty()) p.logDir = join(base, "RawrXD/logs");

    p.modelDir = envOrEmpty("RAWRXD_MODELS_DIR");
    if (p.modelDir.empty()) {
        // Portable model discovery: walk up from the application root looking for a
        // "models" directory (handles bin/ and build-tree layouts), matching the
        // IDE's discovery. Fall back to applicationRoot/models.
        std::error_code ec;
        fs::path probe = fs::path(p.applicationRoot).lexically_normal();
        for (int depth = 0; depth < 4 && p.modelDir.empty(); ++depth) {
            const fs::path candidate = probe / "models";
            if (fs::is_directory(candidate, ec) && !ec) p.modelDir = candidate.string();
            if (!probe.has_parent_path() || probe.parent_path() == probe) break;
            probe = probe.parent_path();
        }
        if (p.modelDir.empty()) p.modelDir = join(p.applicationRoot, "models");
    }
    return p;
}

std::string AppPaths::configFile() const { return join(configDir, "rawrxd.config.json"); }
std::string AppPaths::registryFile() const { return join(modelDir, "registry.json"); }
std::string AppPaths::logFile() const { return join(logDir, "rawrxd.log"); }

} // namespace rawrxd::config