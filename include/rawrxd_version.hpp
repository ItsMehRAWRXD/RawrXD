#pragma once
#include <cstdint>
#include <string>

// RawrXD Unified Version System
// Single source of truth for IDE, CLI, and GUI versions

#define RAWRXD_VERSION_MAJOR 1
#define RAWRXD_VERSION_MINOR 0
#define RAWRXD_VERSION_PATCH 0
#define RAWRXD_VERSION_BUILD 0

// Version string components
#define RAWRXD_VERSION_STRING "1.0.0"
#define RAWRXD_VERSION_FULL "1.0.0.0"

// Component type identifiers for shared memory
namespace RawrXD {
    enum class ComponentType : uint32_t {
        Unknown = 0,
        IDE = 1,        // Win32IDE
        CLI = 2,        // rawrxd-cli
        GUI = 3,        // Future Qt/GTK GUI
        Server = 4,     // rawrxd_http_server
        Monitor = 5     // Production monitor
    };
    
    // Version structure for shared memory
    struct VersionInfo {
        uint32_t major;
        uint32_t minor;
        uint32_t patch;
        uint32_t build;
        ComponentType component;
        uint64_t timestamp;      // Unix timestamp of build
        char gitHash[16];          // Short git commit hash
        
        VersionInfo() 
            : major(RAWRXD_VERSION_MAJOR)
            , minor(RAWRXD_VERSION_MINOR)
            , patch(RAWRXD_VERSION_PATCH)
            , build(RAWRXD_VERSION_BUILD)
            , component(ComponentType::Unknown)
            , timestamp(0) {
            gitHash[0] = '\0';
        }
        
        // Compare versions for compatibility
        bool IsCompatibleWith(const VersionInfo& other) const {
            // Major version must match for compatibility
            // Minor/Patch can differ (backward compatible)
            return major == other.major;
        }
        
        // Get version as string
        std::string ToString() const {
            return std::to_string(major) + "." + 
                   std::to_string(minor) + "." + 
                   std::to_string(patch);
        }
        
        // Get full version with build
        std::string ToFullString() const {
            return std::to_string(major) + "." + 
                   std::to_string(minor) + "." + 
                   std::to_string(patch) + "." +
                   std::to_string(build);
        }
    };
    
    // Get current version info
    inline VersionInfo GetCurrentVersion(ComponentType comp = ComponentType::Unknown) {
        VersionInfo info;
        info.component = comp;
        // TODO: Populate timestamp and git hash at build time
        return info;
    }
}

// C API for MASM/bridge integration
extern "C" {
    // Get version string (thread-local buffer)
    const char* RawrXD_GetVersionString();
    
    // Get version numbers
    void RawrXD_GetVersionNumbers(uint32_t* major, uint32_t* minor, uint32_t* patch, uint32_t* build);
    
    // Check if versions are compatible
    int RawrXD_IsVersionCompatible(uint32_t major1, uint32_t minor1, 
                                    uint32_t major2, uint32_t minor2);
}
