// =============================================================================
// binary_loaders.h — R1 ELF/Mach-O/PE loaders (TOP50 R1), dependency-free.
// =============================================================================
// Format detection by magic + header parsing (entry point, architecture,
// sections/segments) with strict bounds checks. PE parsing complements the
// existing RE path; ELF and Mach-O are new.
// =============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::re {

enum class BinaryFormat { Unknown, Elf32, Elf64, MachO32, MachO64, Pe };

struct SectionInfo {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
};

struct BinaryInfo {
    BinaryFormat format = BinaryFormat::Unknown;
    std::string arch;
    uint64_t entry = 0;
    std::vector<SectionInfo> sections;
};

class BinaryLoader {
public:
    // Detect + parse. Returns false on unknown format or malformed headers.
    bool Load(const std::string& path, BinaryInfo& out) const;

    static const char* FormatName(BinaryFormat f);
    static std::string ToJson(const BinaryInfo& info);
};

}  // namespace rawrxd::re