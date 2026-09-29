// ============================================================================
// Artifact.hpp — Platform-neutral build artifact
// Produced by the build pipeline, consumed by platform emitters.
// ============================================================================
#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace rawrxd::runtime {

enum class ArtifactFormat : uint8_t {
    Native = 0,
    PE,        // Windows .exe/.dll
    ELF,       // Linux
    MachO,     // macOS
    Wasm,      // WebAssembly
    Firmware   // Bare-metal image
};

inline const char* formatName(ArtifactFormat f) noexcept {
    switch (f) {
        case ArtifactFormat::Native:    return "Native";
        case ArtifactFormat::PE:        return "PE";
        case ArtifactFormat::ELF:       return "ELF";
        case ArtifactFormat::MachO:     return "Mach-O";
        case ArtifactFormat::Wasm:      return "Wasm";
        case ArtifactFormat::Firmware:  return "Firmware";
    }
    return "?";
}

enum class ArtifactType : uint8_t {
    Executable = 0,
    SharedLibrary,
    StaticLibrary,
    ObjectFile,
    Archive,
    Resource,
    Manifest
};

struct Section {
    std::string name;
    std::vector<uint8_t> data;
    uint64_t virtualAddress = 0;
    uint64_t virtualSize = 0;
    uint32_t flags = 0;
};

struct SymbolEntry {
    std::string name;
    uint64_t value = 0;
    uint64_t size = 0;
    uint32_t sectionIndex = 0;
    bool isExported = false;
    bool isImported = false;
};

struct RelocationEntry {
    uint64_t offset = 0;
    uint32_t symbolIndex = 0;
    uint16_t type = 0;
};

struct Artifact {
    ArtifactFormat format = ArtifactFormat::Native;
    ArtifactType type = ArtifactType::Executable;
    std::string targetOS;
    std::string architecture;        // e.g. "x86_64", "arm64"
    std::string abi;                 // e.g. "win64", "sysv", "aapcs"

    std::vector<Section> sections;
    std::vector<SymbolEntry> symbols;
    std::vector<RelocationEntry> relocations;
    std::vector<uint8_t> resources;
    std::vector<uint8_t> receipts;   // certification receipts embedded in artifact

    // Metadata
    std::string buildCommit;
    std::string buildTimestamp;
    std::string buildConfig;
    bool sourceDirty = false;
};

} // namespace rawrxd::runtime