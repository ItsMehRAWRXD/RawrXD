#pragma once

#include "rawr_backend_types.hpp"
#include <vector>
#include <cstdint>
#include <string>
#include <string_view>

namespace RawrXD {
namespace Backend {

// COFF64 Section Header
#pragma pack(push,1)
struct CoffSectionHeader {
    char name[8]{};
    uint32_t virtualSize = 0;
    uint32_t virtualAddress = 0;
    uint32_t sizeOfRawData = 0;
    uint32_t pointerToRawData = 0;
    uint32_t pointerToRelocations = 0;
    uint32_t pointerToLineNumbers = 0;
    uint16_t numberOfRelocations = 0;
    uint16_t numberOfLineNumbers = 0;
    uint32_t characteristics = 0;
};

struct CoffSymbol {
    union {
        char shortName[8];
        struct { uint32_t zeros; uint32_t offset; } longName;
    } name;
    uint32_t value = 0;
    int16_t sectionNumber = 0;
    uint16_t type = 0;
    uint8_t storageClass = 0;
    uint8_t numberOfAuxSymbols = 0;
};

struct CoffRelocation {
    uint32_t virtualAddress = 0;
    uint32_t symbolTableIndex = 0;
    uint16_t type = 0;
};

struct CoffFileHeader {
    uint16_t machine = 0x8664; // AMD64
    uint16_t numberOfSections = 0;
    uint32_t timeDateStamp = 0;
    uint32_t pointerToSymbolTable = 0;
    uint32_t numberOfSymbols = 0;
    uint16_t sizeOfOptionalHeader = 0;
    uint16_t characteristics = 0;
};
#pragma pack(pop)

// Relocation types for AMD64
constexpr uint16_t IMAGE_REL_AMD64_ADDR64 = 1;
constexpr uint16_t IMAGE_REL_AMD64_ADDR32 = 2;
constexpr uint16_t IMAGE_REL_AMD64_ADDR32NB = 3;
constexpr uint16_t IMAGE_REL_AMD64_REL32 = 4;
constexpr uint16_t IMAGE_REL_AMD64_REL32_1 = 5;
constexpr uint16_t IMAGE_REL_AMD64_REL32_2 = 6;
constexpr uint16_t IMAGE_REL_AMD64_REL32_3 = 7;
constexpr uint16_t IMAGE_REL_AMD64_REL32_4 = 8;
constexpr uint16_t IMAGE_REL_AMD64_REL32_5 = 9;
constexpr uint16_t IMAGE_REL_AMD64_SECTION = 0x0A;
constexpr uint16_t IMAGE_REL_AMD64_SECREL = 0x0B;

class RawrCOFFWriter {
public:
    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        std::vector<CoffRelocation> relocs;
        uint32_t characteristics = 0;
    };

    uint32_t addSymbol(const std::string& name, int16_t section, uint32_t value, uint8_t storageClass);
    uint32_t addSection(const std::string& name, uint32_t characteristics);
    uint8_t* sectionDataPtr(uint32_t sectionIndex);
    size_t sectionSize(uint32_t sectionIndex) const;
    void appendSectionData(uint32_t sectionIndex, const uint8_t* data, size_t len);
    void addRelocation(uint32_t sectionIndex, uint32_t offset, uint32_t symbolIndex, uint16_t type);

    std::vector<uint8_t> serialize() const;

private:
    CoffFileHeader m_header{};
    std::vector<Section> m_sections;
    std::vector<CoffSymbol> m_symbols;
    std::vector<char> m_stringTable;
};

} // namespace Backend
} // namespace RawrXD
