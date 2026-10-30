//==============================================================================
// RawrXD sovereign_lab_blob_io.cpp
//
// File-based blob I/O helpers for loading raw machine code and extracting
// executable sections from COFF (.obj) and ELF64 (.o) object files.
//------------------------------------------------------------------------------

#include "sovereign_lab_blob_io.hpp"

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

namespace rawrxd::sovereign {

//------------------------------------------------------------------------------
// Little-endian read helpers
//------------------------------------------------------------------------------
static uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

static uint64_t rd64(const uint8_t* p) {
    return static_cast<uint64_t>(rd32(p)) |
           (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

//------------------------------------------------------------------------------
// readWholeFile
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> readWholeFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) return std::nullopt;

    auto fileSize = f.tellg();
    if (fileSize < 0) return std::nullopt;

    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(fileSize));
    if (!f.read(reinterpret_cast<char*>(buf.data()), fileSize)) {
        return std::nullopt;
    }
    return buf;
}

//------------------------------------------------------------------------------
// tryExtractCoffSection
//
// Parses a PE/COFF object file (.obj) and extracts a named section's raw data.
// Layout: [COFF Header (20)][Section Headers (40 each)][Raw Data][Relocs][Symbol Table][String Table]
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> tryExtractCoffSection(
    const std::string& objPath,
    const std::string& sectionName) {

    auto fileData = readWholeFile(objPath);
    if (!fileData) return std::nullopt;
    const auto& data = *fileData;
    if (data.size() < 20) return std::nullopt;

    // COFF header (20 bytes)
    uint16_t machine   = rd16(data.data());
    uint16_t numSec    = rd16(data.data() + 2);
    uint32_t symOff    = rd32(data.data() + 8);
    uint32_t numSym    = rd32(data.data() + 12);
    uint16_t optHdrSz  = rd16(data.data() + 16);

    // Validate machine type
    if (machine != 0x8664 && machine != 0x014C && machine != 0x0000) {
        return std::nullopt;
    }

    size_t secTableOff = 20 + optHdrSz;

    // String table offset: after symbol table
    uint32_t strTabOff = symOff + static_cast<uint32_t>(numSym * 18);

    for (uint16_t i = 0; i < numSec; ++i) {
        size_t shOff = secTableOff + static_cast<size_t>(i) * 40;
        if (shOff + 40 > data.size()) return std::nullopt;

        char secName[9] = {0};
        memcpy(secName, data.data() + shOff, 8);

        // Handle /N string table references for long section names
        if (secName[0] == '/') {
            uint32_t strOff = static_cast<uint32_t>(strtoul(secName + 1, nullptr, 10));
            if (strOff + 4 <= strTabOff && strTabOff + 4 <= data.size()) {
                // String table is at symOff + numSym*18, first 4 bytes = size
                uint32_t strTabBase = symOff + numSym * 18;
                if (strTabBase + 4 <= data.size()) {
                    uint32_t strTabSize = rd32(data.data() + strTabBase);
                    if (4 + strOff < strTabSize) {
                        const char* str = reinterpret_cast<const char*>(data.data() + strTabBase + 4 + strOff);
                        size_t len = strlen(str);
                        if (len < 8) {
                            memcpy(secName, str, len);
                            secName[len] = '\0';
                        }
                    }
                }
            }
        }

        if (std::string(secName) != sectionName) continue;

        uint32_t rawSize = rd32(data.data() + shOff + 16);
        uint32_t rawOff  = rd32(data.data() + shOff + 20);

        // BSS sections have no raw data
        uint32_t chars = rd32(data.data() + shOff + 36);
        if (chars & 0x00000080) {  // SCN_CNT_UNINITIALIZED
            return std::vector<uint8_t>(); // empty but valid
        }

        if (rawSize == 0 || rawOff == 0) return std::vector<uint8_t>();
        if (rawOff + rawSize > data.size()) return std::nullopt;

        std::vector<uint8_t> sectionData(data.begin() + rawOff,
                                          data.begin() + rawOff + rawSize);
        return sectionData;
    }

    return std::nullopt; // section not found
}

//------------------------------------------------------------------------------
// ELF64 constants for blob IO
//------------------------------------------------------------------------------
static constexpr uint32_t ELF64_SHT_NULL = 0;
static constexpr uint32_t ELF64_SHT_PROGBITS = 1;
static constexpr uint32_t ELF64_SHT_SYMTAB = 2;
static constexpr uint32_t ELF64_SHT_STRTAB = 3;

//------------------------------------------------------------------------------
// tryExtractElf64ProgBitsSection
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> tryExtractElf64ProgBitsSection(
    const std::string& objPath,
    const std::string& sectionName) {
    return tryExtractElf64SectionByType(objPath, ELF64_SHT_PROGBITS);
}

//------------------------------------------------------------------------------
// tryExtractElf64SectionByType
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> tryExtractElf64SectionByType(
    const std::string& objPath,
    uint32_t sectionType) {

    auto fileData = readWholeFile(objPath);
    if (!fileData) return std::nullopt;
    const auto& data = *fileData;
    if (data.size() < 64) return std::nullopt;

    // ELF identification
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        return std::nullopt;
    }
    if (data[4] != 2) return std::nullopt; // must be 64-bit

    uint16_t e_type     = rd16(data.data() + 16);
    uint16_t e_machine  = rd16(data.data() + 18);
    uint64_t e_shoff    = rd64(data.data() + 40);
    uint16_t e_shentsize= rd16(data.data() + 58);
    uint16_t e_shnum    = rd16(data.data() + 60);
    uint16_t e_shstrndx = rd16(data.data() + 62);

    if (e_shoff == 0 || e_shnum == 0) return std::nullopt;

    // Read section header string table
    std::vector<char> shstrTab;
    if (e_shstrndx != 0 && e_shstrndx < e_shnum) {
        size_t shstrSecOff = static_cast<size_t>(e_shoff) +
                             static_cast<size_t>(e_shstrndx) * static_cast<size_t>(e_shentsize);
        if (shstrSecOff + e_shentsize > data.size()) return std::nullopt;
        uint64_t shstrOffset = rd64(data.data() + shstrSecOff + 16); // sh_offset
        uint64_t shstrSize   = rd64(data.data() + shstrSecOff + 24); // sh_size
        if (shstrOffset + shstrSize > data.size()) return std::nullopt;
        shstrTab.resize(static_cast<size_t>(shstrSize));
        memcpy(shstrTab.data(), data.data() + shstrOffset, shstrSize);
    }

    for (uint16_t i = 0; i < e_shnum; ++i) {
        size_t shOff = static_cast<size_t>(e_shoff) +
                       static_cast<size_t>(i) * static_cast<size_t>(e_shentsize);
        if (shOff + e_shentsize > data.size()) return std::nullopt;

        uint32_t shType   = rd32(data.data() + shOff);
        uint64_t shOffset = rd64(data.data() + shOff + 16);
        uint64_t shSize   = rd64(data.data() + shOff + 24);
        uint32_t shName   = rd32(data.data() + shOff);

        if (shType != sectionType) continue;

        // Get section name from string table
        std::string name;
        if (shName < shstrTab.size()) {
            const char* s = shstrTab.data() + shName;
            name = s;
        }

        if (shOffset + shSize > data.size()) return std::nullopt;

        std::vector<uint8_t> sectionData(data.begin() + shOffset,
                                          data.begin() + shOffset + shSize);
        return sectionData;
    }

    return std::nullopt;
}

} // namespace rawrxd::sovereign
