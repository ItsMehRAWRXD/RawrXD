// ExtensionEngine_bridge.h - Extension Engine Bridge Stub
// Architecture: C++20, Win32, no Qt, no exceptions
// Battle-hardened stub for build compatibility
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace ExtensionEngine {

// ============================================================================
// Extension Engine Configuration
// ============================================================================

struct ExtensionConfig
{
    std::string extensionPath;
    std::string manifestPath;
    bool enableHotReload = true;
    bool enableSandbox = true;
};

// ============================================================================
// Extension Info
// ============================================================================

struct ExtensionInfo
{
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string mainPath;
    bool enabled = true;
};

// ============================================================================
// Extension Engine Bridge (Stub)
// ============================================================================

class ExtensionEngineBridge
{
public:
    ExtensionEngineBridge() = default;
    ~ExtensionEngineBridge() = default;

    // Initialize extension engine (stub)
    bool initialize(const ExtensionConfig& config)
    {
        (void)config;
        return true;
    }

    // Load extension (stub)
    bool loadExtension(const std::string& extensionPath)
    {
        (void)extensionPath;
        return true;
    }

    // Unload extension (stub)
    bool unloadExtension(const std::string& extensionId)
    {
        (void)extensionId;
        return true;
    }

    // Get loaded extensions (stub)
    std::vector<ExtensionInfo> getLoadedExtensions() const
    {
        return {};
    }

    // Enable extension (stub)
    bool enableExtension(const std::string& extensionId)
    {
        (void)extensionId;
        return true;
    }

    // Disable extension (stub)
    bool disableExtension(const std::string& extensionId)
    {
        (void)extensionId;
        return true;
    }

    // Check if initialized (stub)
    bool isInitialized() const
    {
        return false;
    }
};

} // namespace ExtensionEngine
} // namespace RawrXD

// ============================================================================
// Global Instance (Stub)
// ============================================================================

inline RawrXD::ExtensionEngine::ExtensionEngineBridge& GetExtensionEngineBridge()
{
    static RawrXD::ExtensionEngine::ExtensionEngineBridge instance;
    return instance;
}

// ============================================================================
// Convenience Functions (Stubs) - in RawrXD::Extensions namespace
// ============================================================================

namespace RawrXD {
namespace Extensions {

inline bool InitializeExtensionEngine(HWND hwnd = nullptr, bool enableLsp = true)
{
    (void)hwnd;
    (void)enableLsp;
    return true;
}

inline bool PollExtensionEngineLsp()
{
    return true;
}

inline void ShutdownExtensionEngine()
{
}

inline bool LoadExtension(const std::string& extensionPath)
{
    (void)extensionPath;
    return true;
}

inline bool UnloadExtension(const std::string& extensionId)
{
    (void)extensionId;
    return true;
}

} // namespace Extensions
} // namespace RawrXD

// ============================================================================
// END OF FILE
// ============================================================================