//==============================================================================
// RawrXD sovereign_lab_blob_io.hpp
//
// File-based blob I/O helpers for loading raw machine code and extracting
// executable sections from COFF (.obj) and ELF64 (.o) object files.
// No host introspection, no syscalls, no platform-specific loader logic.
//
// Used by: lab pipelines that load codeBytes from flat .bin or object files
// before calling compose* helpers in sovereign_emit_formats.hpp
//==============================================================================

#ifndef RAWRXD_SOVEREIGN_LAB_BLOB_IO_HPP
#define RAWRXD_SOVEREIGN_LAB_BLOB_IO_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <optional>

namespace rawrxd::sovereign {

//------------------------------------------------------------------------------
// readWholeFile — read an entire file into a byte vector.
// Returns std::nullopt if the file cannot be opened or read.
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> readWholeFile(const std::string& path);

//------------------------------------------------------------------------------
// COFF section header (from .obj file) — 40 bytes in file.
// These offsets match the PE/COFF object section table.
struct CoffSectionHeader {
    char     name[8];
    uint32_t virtualSize;
    uint32_t virtualAddress;
    uint32_t rawSize;
    uint32_t rawOffset;
    uint32_t relocOffset;
    uint32_t lineNumberOffset;
    uint16_t numberOfRelocations;
    uint16_t numberOfLineNumbers;
    uint32_t characteristics;
};

//------------------------------------------------------------------------------
// tryExtractCoffSection — extract a named section's raw data from a COFF object
// file (.obj). Returns the raw bytes of the section (e.g. .text) or nullopt if
// the section is not found or the file is not a valid COFF object.
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> tryExtractCoffSection(
    const std::string& objPath,
    const std::string& sectionName);

//------------------------------------------------------------------------------
// ELF64 section header — 64 bytes in file.
struct Elf64SectionHeader {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

//------------------------------------------------------------------------------
// ELF64 program header — 56 bytes in file.
struct Elf64ProgramHeader {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

//------------------------------------------------------------------------------
// tryExtractElf64ProgBitsSection — extract a .progbits section (typically .text)
// from an ELF64 relocatable object (.o). Returns the raw section bytes or
// nullopt if not found or invalid.
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> tryExtractElf64ProgBitsSection(
    const std::string& objPath,
    const std::string& sectionName);

//------------------------------------------------------------------------------
// tryExtractElf64SectionByType — extract an ELF64 section by section type
// (e.g. SHT_PROGBITS = 1). Returns raw bytes or nullopt.
//------------------------------------------------------------------------------
std::optional<std::vector<uint8_t>> tryExtractElf64SectionByType(
    const std::string& objPath,
    uint32_t sectionType);

} // namespace rawrxd::sovereign

#endif // RAWRXD_SOVEREIGN_LAB_BLOB_IO_HPP
