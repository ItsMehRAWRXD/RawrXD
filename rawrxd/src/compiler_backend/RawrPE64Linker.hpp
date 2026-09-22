#pragma once

#include "RawrCOFFWriter.hpp"
#include <vector>
#include <cstdint>
#include <string>

namespace RawrXD {
namespace Backend {

// Minimal PE64 linker producing a freestanding executable without external tools
class RawrPE64Linker {
public:
    struct Section {
        std::string name;
        std::vector<uint8_t> data;
        uint32_t virtualSize = 0;
        uint32_t characteristics = 0; // e.g. IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        uint32_t virtualAddress = 0;
    };

    struct ImportDesc {
        std::string dllName;
        std::vector<std::string> funcs;
    };

    uint32_t addSection(const std::string& name, uint32_t characteristics);
    uint8_t* sectionDataPtr(uint32_t sectionIndex);
    void appendSectionData(uint32_t sectionIndex, const uint8_t* data, size_t len);

    void setEntryPoint(uint32_t sectionIndex, uint32_t offset);
    void setImageBase(uint64_t base);
    void addImport(const ImportDesc& desc);
    void addBaseRelocation(uint64_t rva);

    std::vector<uint8_t> link() const;

    static constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
    static constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
    static constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    static constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
    static constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;

private:
    uint64_t m_imageBase = 0x140000000ULL; // default ASLR base
    uint32_t m_entrySection = 0;
    uint32_t m_entryOffset = 0;
    std::vector<Section> m_sections;
    std::vector<ImportDesc> m_imports;
    std::vector<uint64_t> m_relocs;

    static void writeU16(std::vector<uint8_t>& out, uint16_t v);
    static void writeU32(std::vector<uint8_t>& out, uint32_t v);
    static void writeU64(std::vector<uint8_t>& out, uint64_t v);
    static void append(std::vector<uint8_t>& out, const void* data, size_t len);

    // Import table builder
    struct IdatBuild {
        std::vector<uint8_t> data;
        uint32_t size() const { return static_cast<uint32_t>(data.size()); }
        uint32_t dirRva = 0;       // IMAGE_IMPORT_DESCRIPTOR array RVA
        uint32_t dirSize = 0;      // size of import directory (for data dir)
        uint32_t iatRva = 0;       // IAT RVA (used by code)
        uint32_t iatSize = 0;      // IAT size in bytes
    };
    IdatBuild buildIdat(uint32_t rvaBase) const;
    void patchU32(std::vector<uint8_t>& buf, size_t off, uint32_t v) const;
    void patchU64(std::vector<uint8_t>& buf, size_t off, uint64_t v) const;
};

} // namespace Backend
} // namespace RawrXD
