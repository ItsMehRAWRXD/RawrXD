// ============================================================================
// ExtensionLoader.hpp — Stub module loader
// No real usage found in auto_feature_registry.cpp; declared to satisfy includes.
// ============================================================================
#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace Extensions {

class ExtensionLoader {
public:
    static ExtensionLoader& instance();

    bool LoadExtension(const std::string& path);
    bool UnloadExtension(const std::string& path);
    std::vector<std::string> GetLoadedExtensions() const;

private:
    ExtensionLoader() = default;
    std::vector<std::string> loaded_;
};

} // namespace Extensions
} // namespace RawrXD
