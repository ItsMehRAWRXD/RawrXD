//==============================================================================
// RawrXD sovereign_emit_formats.hpp
//
// Minimal header bootstrap for tri-format binary composition (PE64 / ELF64 / Mach-O).
// These functions produce lab-grade bootstrap bytes — NOT a full product linker.
// They take codeBytes, patch sizes so the blob is internally consistent, and
// return a std::vector<uint8_t> buffer ready to be written to disk.
//
// Used by: tests/test_sovereign_compose_lab.cpp, tests/sovereign_header_tests.cpp
// Examples: examples/01_minimal_nop_synthesis.cpp, examples/02_shellcode_payload_wrap.cpp
//==============================================================================

#ifndef RAWRXD_SOVEREIGN_EMIT_FORMATS_HPP
#define RAWRXD_SOVEREIGN_EMIT_FORMATS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <optional>

#include "sovereign_target_manifest.hpp"

namespace rawrxd::sovereign {

//------------------------------------------------------------------------------
// EmitBlueprint — neutral intermediate representation describing a minimal
// executable image. The compose* functions fill in format-specific bytes
// from this blueprint.
//------------------------------------------------------------------------------
struct EmitBlueprint {
    std::vector<uint8_t> codeBytes;      // raw machine code payload (e.g. NOP+RET)
    uint64_t             entryVA         = 0;  // virtual address of entry point
    uint32_t             codeSize        = 0;  // size of code in bytes
    uint32_t             imageSize       = 0;  // total virtual image size
    uint32_t             headerSize      = 0;  // total header size (file-aligned)
    uint32_t             sectionAlignment = 0x1000;
    uint32_t             fileAlignment   = 0x200;
    uint64_t             imageBase       = 0x0000000140000000ULL;
    std::string          sectionName     = ".text";
    bool                 isExecutable    = true;
};

//------------------------------------------------------------------------------
// emitBlueprintFromManifest — build an EmitBlueprint from a TargetManifest.
// Fills in arch-specific entry VA, section alignment, image base defaults.
//------------------------------------------------------------------------------
EmitBlueprint emitBlueprintFromManifest(const TargetManifest& manifest,
                                         const std::vector<uint8_t>& codeBytes);

//------------------------------------------------------------------------------
// emitMinimalHeaderFromManifest — produce format-specific header bytes from
// a TargetManifest alone (no code payload). Used for header-only inspection.
//------------------------------------------------------------------------------
std::vector<uint8_t> emitMinimalHeaderFromManifest(const TargetManifest& manifest);

//------------------------------------------------------------------------------
// composePe64MinimalImage — build a complete PE32+ image from codeBytes.
// Patches:
//   - AddressOfEntryPoint at RVA 0x1000
//   - SizeOfImage (section-aligned)
//   - SizeOfHeaders (file-aligned)
//   - .text section sizes
//   - CheckSum == 0 (PE64 optional header +0x40)
// Returns the complete PE file buffer.
std::vector<uint8_t> composePe64MinimalImage(const EmitBlueprint& bp);

//------------------------------------------------------------------------------
// composePe64MinimalImageFromManifest — convenience: manifest → blueprint → PE image.
std::vector<uint8_t> composePe64MinimalImageFromManifest(
    const TargetManifest& manifest, const std::vector<uint8_t>& codeBytes);

//------------------------------------------------------------------------------
// composeElf64MinimalImage — build a complete ELF64 image from codeBytes.
// Patches:
//   - e_entry (virtual address of entry)
//   - PT_LOAD p_filesz / p_memsz
//   - p_memsz >= p_filesz, page-aligned p_memsz
// Returns the complete ELF file buffer.
std::vector<uint8_t> composeElf64MinimalImage(const EmitBlueprint& bp);

//------------------------------------------------------------------------------
// composeElf64MinimalImageFromManifest — convenience: manifest → blueprint → ELF image.
std::vector<uint8_t> composeElf64MinimalImageFromManifest(
    const TargetManifest& manifest, const std::vector<uint8_t>& codeBytes);

//------------------------------------------------------------------------------
// composeMacho64MinimalImage — build a complete Mach-O 64-bit image from codeBytes.
// Patches:
//   - cputype (0x01000007 x86_64 / 0x0100000C ARM64 per manifest)
//   - LC_SEGMENT_64 __TEXT/__text sizes
//   - LC_MAIN entryoff at file offset 192
//   - sizeofcmds % 8 == 0, sizeofcmds == 152 + 24
//   - NOT codesigned
// Returns the complete Mach-O file buffer.
std::vector<uint8_t> composeMacho64MinimalImage(const EmitBlueprint& bp);

//------------------------------------------------------------------------------
// composeMacho64MinimalImageFromManifest — convenience: manifest → blueprint → Mach-O image.
std::vector<uint8_t> composeMacho64MinimalImageFromManifest(
    const TargetManifest& manifest, const std::vector<uint8_t>& codeBytes);

//------------------------------------------------------------------------------
// Alignment helpers used by compose* functions.
//------------------------------------------------------------------------------
inline uint32_t align_up(uint32_t val, uint32_t align) {
    if (align == 0) align = 1;
    return (val + align - 1) & ~(align - 1);
}

inline uint64_t align_up64(uint64_t val, uint64_t align) {
    if (align == 0) align = 1;
    return (val + align - 1) & ~(align - 1);
}

} // namespace rawrxd::sovereign

#endif // RAWRXD_SOVEREIGN_EMIT_FORMATS_HPP
