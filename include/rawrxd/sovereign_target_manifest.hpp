//==============================================================================
// RawrXD sovereign_target_manifest.hpp
//
// Neutral TargetManifest schema driving CMake / compiler flags for cross-platform
// builds. This is a data structure only — not a loader, not syscalls, not a
// linker.
//
// Fields:
//   os         : windows | linux | macos | android | ios
//   arch       : x86_64 | arm64
//   objectFormat: pe | elf | macho (usually implied by OS + toolchain)
//   linker     : msvc | lld | ld64 | ndk
//   runtime    : native-apis | libc | framework-apis
//   llvmTriple : optional LLVM target triple (e.g. aarch64-apple-darwin)
//==============================================================================

#ifndef RAWRXD_SOVEREIGN_TARGET_MANIFEST_HPP
#define RAWRXD_SOVEREIGN_TARGET_MANIFEST_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace rawrxd::sovereign {

// Supported operating systems
enum class TargetOs : uint8_t {
    Unknown = 0,
    Windows,
    Linux,
    MacOS,
    Android,
    iOS,
};

// Supported architectures
enum class TargetArch : uint8_t {
    Unknown = 0,
    x86_64,
    Arm64,
};

// Supported object formats
enum class ObjectFormat : uint8_t {
    Unknown = 0,
    PE,
    ELF,
    MachO,
};

// Supported linkers
enum class LinkerKind : uint8_t {
    Unknown = 0,
    MSVC,
    LLD,
    LD64,
    NDK,
};

// Supported runtime environments
enum class RuntimeKind : uint8_t {
    Unknown = 0,
    NativeAPIs,
    LibC,
    FrameworkAPIs,
};

// TargetManifest — neutral schema describing how to build for one target OS/arch.
struct TargetManifest {
    TargetOs      os            = TargetOs::Unknown;
    TargetArch    arch          = TargetArch::Unknown;
    ObjectFormat  objectFormat  = ObjectFormat::Unknown;
    LinkerKind    linker        = LinkerKind::Unknown;
    RuntimeKind   runtime       = RuntimeKind::Unknown;
    std::optional<std::string> llvmTriple;   // e.g. "aarch64-apple-darwin"
    std::vector<std::string>  defines;       // C preprocessor definitions
    std::vector<std::string>  includePaths;  // Additional include paths
    std::vector<std::string>  libPaths;      // Additional library paths
    std::vector<std::string>  libs;          // Libraries to link
    std::vector<std::string>  cxxFlags;      // Extra compiler flags
    std::vector<std::string>  linkFlags;     // Extra linker flags
};

// Convert enum values to/from strings for diagnostics and serialization.
inline const char* target_os_name(TargetOs os) {
    switch (os) {
        case TargetOs::Unknown:   return "unknown";
        case TargetOs::Windows:   return "windows";
        case TargetOs::Linux:     return "linux";
        case TargetOs::MacOS:     return "macos";
        case TargetOs::Android:   return "android";
        case TargetOs::iOS:       return "ios";
    }
    return "unknown";
}

inline const char* target_arch_name(TargetArch arch) {
    switch (arch) {
        case TargetArch::Unknown: return "unknown";
        case TargetArch::x86_64:  return "x86_64";
        case TargetArch::Arm64:   return "arm64";
    }
    return "unknown";
}

inline const char* object_format_name(ObjectFormat fmt) {
    switch (fmt) {
        case ObjectFormat::Unknown: return "unknown";
        case ObjectFormat::PE:      return "pe";
        case ObjectFormat::ELF:     return "elf";
        case ObjectFormat::MachO:   return "macho";
    }
    return "unknown";
}

inline const char* linker_kind_name(LinkerKind kind) {
    switch (kind) {
        case LinkerKind::Unknown: return "unknown";
        case LinkerKind::MSVC:    return "msvc";
        case LinkerKind::LLD:     return "lld";
        case LinkerKind::LD64:    return "ld64";
        case LinkerKind::NDK:     return "ndk";
    }
    return "unknown";
}

inline const char* runtime_kind_name(RuntimeKind kind) {
    switch (kind) {
        case RuntimeKind::Unknown:    return "unknown";
        case RuntimeKind::NativeAPIs: return "native-apis";
        case RuntimeKind::LibC:       return "libc";
        case RuntimeKind::FrameworkAPIs: return "framework-apis";
    }
    return "unknown";
}

// Default manifest for host Windows x86_64 build (MSVC toolchain).
inline TargetManifest default_windows_x64_manifest() {
    TargetManifest m;
    m.os           = TargetOs::Windows;
    m.arch         = TargetArch::x86_64;
    m.objectFormat = ObjectFormat::PE;
    m.linker       = LinkerKind::MSVC;
    m.runtime      = RuntimeKind::NativeAPIs;
    m.llvmTriple   = std::nullopt;
    m.defines      = {"WIN32", "_WIN64", "NDEBUG"};
    return m;
}

// Default manifest for Linux x86_64 build (LLD/linker).
inline TargetManifest default_linux_x64_manifest() {
    TargetManifest m;
    m.os           = TargetOs::Linux;
    m.arch         = TargetArch::x86_64;
    m.objectFormat = ObjectFormat::ELF;
    m.linker       = LinkerKind::LLD;
    m.runtime      = RuntimeKind::LibC;
    m.llvmTriple   = std::nullopt;
    return m;
}

// Default manifest for macOS x86_64 build (ld64).
inline TargetManifest default_macos_x64_manifest() {
    TargetManifest m;
    m.os           = TargetOs::MacOS;
    m.arch         = TargetArch::x86_64;
    m.objectFormat = ObjectFormat::MachO;
    m.linker       = LinkerKind::LD64;
    m.runtime      = RuntimeKind::FrameworkAPIs;
    m.llvmTriple   = std::nullopt;
    return m;
}

// Default manifest for macOS arm64 build (ld64).
inline TargetManifest default_macos_arm64_manifest() {
    TargetManifest m = default_macos_x64_manifest();
    m.arch         = TargetArch::Arm64;
    m.llvmTriple   = "aarch64-apple-darwin";
    return m;
}

// Default manifest for Android arm64 (NDK).
inline TargetManifest default_android_arm64_manifest() {
    TargetManifest m;
    m.os           = TargetOs::Android;
    m.arch         = TargetArch::Arm64;
    m.objectFormat = ObjectFormat::ELF;
    m.linker       = LinkerKind::NDK;
    m.runtime      = RuntimeKind::LibC;
    m.llvmTriple   = "aarch64-linux-android";
    return m;
}

// Default manifest for iOS arm64 (ld64 + codesign).
inline TargetManifest default_ios_arm64_manifest() {
    TargetManifest m;
    m.os           = TargetOs::iOS;
    m.arch         = TargetArch::Arm64;
    m.objectFormat = ObjectFormat::MachO;
    m.linker       = LinkerKind::LD64;
    m.runtime      = RuntimeKind::FrameworkAPIs;
    m.llvmTriple   = "aarch64-apple-ios";
    return m;
}

// Serialize manifest to a human-readable diagnostic string.
inline std::string manifest_to_string(const TargetManifest& m) {
    std::string s;
    s += "TargetManifest{";
    s += "os=";
    s += target_os_name(m.os);
    s += ", arch=";
    s += target_arch_name(m.arch);
    s += ", objectFormat=";
    s += object_format_name(m.objectFormat);
    s += ", linker=";
    s += linker_kind_name(m.linker);
    s += ", runtime=";
    s += runtime_kind_name(m.runtime);
    if (m.llvmTriple) {
        s += ", llvmTriple=";
        s += *m.llvmTriple;
    }
    s += "}";
    return s;
}

} // namespace rawrxd::sovereign

#endif // RAWRXD_SOVEREIGN_TARGET_MANIFEST_HPP
