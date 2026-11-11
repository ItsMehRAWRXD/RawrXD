#pragma once
#include <cstdint>
#include <string_view>

// RawrXD Unified Version System
// Single source of truth for all IDE/CLI/GUI/Headless components

#define RAWRXD_VERSION_MAJOR 1
#define RAWRXD_VERSION_MINOR 1
#define RAWRXD_VERSION_PATCH 0
#define RAWRXD_VERSION_BUILD 0

// Version string components
#define RAWRXD_VERSION_STRING "1.1.0"
#define RAWRXD_VERSION_FULL "1.1.0-alpha"
#define RAWRXD_VERSION_CODENAME "Courageous Rodent"

// Semantic version as packed integer (0xAABBCCDD = Major.Minor.Patch.Build)
#define RAWRXD_VERSION_PACKED ((RAWRXD_VERSION_MAJOR << 24) | \
                               (RAWRXD_VERSION_MINOR << 16) | \
                               (RAWRXD_VERSION_PATCH << 8)  | \
                               RAWRXD_VERSION_BUILD)

// Compatibility version for shared memory/protocol checks
// Increment when breaking changes occur
#define RAWRXD_PROTOCOL_VERSION 1

namespace RawrXD {

// Version information structure (for runtime queries)
struct VersionInfo {
    uint8_t major;
    uint8_t minor;
    uint8_t patch;
    uint8_t build;
    uint32_t protocol;
    const char* string;
    const char* codename;
    const char* gitCommit;      // Populated at build time
    const char* buildTimestamp; // Populated at build time
};

// Compile-time version accessors
constexpr uint32_t GetVersionPacked() noexcept {
    return RAWRXD_VERSION_PACKED;
}

constexpr std::string_view GetVersionString() noexcept {
    return RAWRXD_VERSION_STRING;
}

constexpr std::string_view GetVersionCodename() noexcept {
    return RAWRXD_VERSION_CODENAME;
}

constexpr uint32_t GetProtocolVersion() noexcept {
    return RAWRXD_PROTOCOL_VERSION;
}

// Runtime version info (includes build-time metadata)
const VersionInfo& GetVersionInfo() noexcept;

// Version comparison helpers
constexpr bool IsVersionAtLeast(uint8_t major, uint8_t minor, uint8_t patch) noexcept {
    return GetVersionPacked() >= ((major << 24) | (minor << 16) | (patch << 8));
}

// Check protocol compatibility
constexpr bool IsProtocolCompatible(uint32_t otherProtocol) noexcept {
    return otherProtocol == RAWRXD_PROTOCOL_VERSION;
}

} // namespace RawrXD
