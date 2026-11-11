//==============================================================================
// RawrXD sovereign_emit_formats.cpp
//
// Implementations of tri-format binary composition (PE64 / ELF64 / Mach-O 64).
// These produce lab-grade bootstrap bytes — structurally valid minimal images
// that can be inspected, validated, and further processed by platform linkers.
//
// NOT a full product linker: no imports, no exports, no relocations, no
// symbol tables beyond what is needed for a minimal executable entry point.
//------------------------------------------------------------------------------

#include "sovereign_emit_formats.hpp"
#include "sovereign_lab_blob_io.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace rawrxd::sovereign {

//------------------------------------------------------------------------------
// Little-endian write helpers
//------------------------------------------------------------------------------
static void write_u16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    buf[off]   = static_cast<uint8_t>(v & 0xFF);
    buf[off+1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

static void write_u32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    buf[off]   = static_cast<uint8_t>(v & 0xFF);
    buf[off+1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[off+2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[off+3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static void write_u64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    write_u32(buf, off,     static_cast<uint32_t>(v & 0xFFFFFFFFULL));
    write_u32(buf, off + 4, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFULL));
}

static void ensure_size(std::vector<uint8_t>& buf, size_t size) {
    if (buf.size() < size) buf.resize(size, 0);
}

//------------------------------------------------------------------------------
// emitBlueprintFromManifest
//------------------------------------------------------------------------------
EmitBlueprint emitBlueprintFromManifest(const TargetManifest& manifest,
                                         const std::vector<uint8_t>& codeBytes) {
    EmitBlueprint bp;
    bp.codeBytes = codeBytes;
    bp.codeSize  = static_cast<uint32_t>(codeBytes.size());
    bp.sectionAlignment = 0x1000;
    bp.fileAlignment    = 0x200;

    switch (manifest.arch) {
        case TargetArch::x86_64:
            bp.imageBase   = 0x0000000140000000ULL;
            bp.entryVA     = 0x0000000140001000ULL;  // first section at 0x1000
            break;
        case TargetArch::Arm64:
            bp.imageBase   = 0x0000000100000000ULL;
            bp.entryVA     = 0x0000000100001000ULL;
            break;
        default:
            bp.imageBase   = 0x0000000140000000ULL;
            bp.entryVA     = 0x0000000140001000ULL;
            break;
    }

    // Headers: DOS(64) + stub(64) + PE sig(4) + COFF(20) + Optional(240) + section headers(40)
    // For ELF: ehdr(64) + phdr(56 per segment)
    // For Mach-O: mach_header(32) + load commands
    bp.headerSize = align_up(512, bp.fileAlignment);  // conservative header estimate

    bp.imageSize = align_up(bp.codeSize + 0x1000, bp.sectionAlignment);
    bp.isExecutable = true;
    return bp;
}

//------------------------------------------------------------------------------
// emitMinimalHeaderFromManifest — header-only bytes for inspection
//------------------------------------------------------------------------------
std::vector<uint8_t> emitMinimalHeaderFromManifest(const TargetManifest& manifest) {
    std::vector<uint8_t> header;
    // Return a small identifier block describing the target
    std::string desc = manifest_to_string(manifest) + "\n";
    header.insert(header.end(), desc.begin(), desc.end());
    return header;
}

//------------------------------------------------------------------------------
// PE32+ writer helpers
//------------------------------------------------------------------------------
static void write_pe_dos_header(std::vector<uint8_t>& buf, uint32_t peOffset) {
    // DOS header (64 bytes)
    ensure_size(buf, 64);
    buf[0] = 0x4D;  // 'M'
    buf[1] = 0x5A;  // 'Z'
    write_u32(buf, 0x3C, peOffset);  // e_lfanew

    // DOS stub message at offset 64
    const char* dosStub =
        "This program cannot be run in DOS mode.\r\n$";
    size_t stubLen = strlen(dosStub);
    ensure_size(buf, 64 + stubLen);
    memcpy(buf.data() + 64, dosStub, stubLen);
}

static void write_pe_coff_header(std::vector<uint8_t>& buf, size_t off,
                                  uint16_t numSections) {
    write_u16(buf, off + 0, 0x8664);      // Machine: x64
    write_u16(buf, off + 2, numSections); // NumberOfSections
    write_u32(buf, off + 4, 0);           // TimeDateStamp
    write_u32(buf, off + 8, 0);           // PointerToSymbolTable
    write_u32(buf, off + 12, 0);          // NumberOfSymbols
    write_u16(buf, off + 16, 0xF0);       // SizeOfOptionalHeader (PE32+ = 240)
    write_u16(buf, off + 18, 0x0022);     // Characteristics (EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE)
}

static void write_pe_optional_header(std::vector<uint8_t>& buf, size_t off,
                                      const EmitBlueprint& bp,
                                      uint32_t entryRVA,
                                      uint32_t sizeOfHeaders,
                                      uint32_t sizeOfImage) {
    // Standard fields (24 bytes)
    write_u16(buf, off + 0, 0x020B);  // Magic PE32+
    buf[off + 2] = 1;                 // MajorLinkerVersion
    buf[off + 3] = 0;                 // MinorLinkerVersion
    write_u32(buf, off + 4, bp.codeSize);                          // SizeOfCode
    write_u32(buf, off + 8, 0);                                   // SizeOfInitializedData
    write_u32(buf, off + 12, 0);                                  // SizeOfUninitializedData
    write_u32(buf, off + 16, entryRVA);                            // AddressOfEntryPoint
    write_u32(buf, off + 20, entryRVA & 0xFFF0);                   // BaseOfCode

    // Windows-specific fields (PE32+)
    write_u64(buf, off + 24, bp.imageBase);                        // ImageBase
    write_u32(buf, off + 32, bp.sectionAlignment);                 // SectionAlignment
    write_u32(buf, off + 36, bp.fileAlignment);                    // FileAlignment
    write_u16(buf, off + 40, 6);                                   // MajorOSVersion
    write_u16(buf, off + 42, 0);
    write_u16(buf, off + 44, 0);                                   // MajorImageVersion
    write_u16(buf, off + 46, 0);
    write_u16(buf, off + 48, 6);                                   // MajorSubsystemVersion
    write_u16(buf, off + 50, 0);
    write_u32(buf, off + 52, 0);                                   // Win32VersionValue
    write_u32(buf, off + 56, sizeOfImage);                         // SizeOfImage
    write_u32(buf, off + 60, sizeOfHeaders);                       // SizeOfHeaders
    write_u32(buf, off + 64, 0);                                   // CheckSum
    write_u16(buf, off + 68, 3);                                   // Subsystem (Console)
    write_u16(buf, off + 70, 0x0040 | 0x0100 | 0x0020 | 0x8000); // DllCharacteristics
    write_u64(buf, off + 72, 0x100000);                            // SizeOfStackReserve
    write_u64(buf, off + 80, 0x1000);                              // SizeOfStackCommit
    write_u64(buf, off + 88, 0x100000);                            // SizeOfHeapReserve
    write_u64(buf, off + 96, 0x1000);                              // SizeOfHeapCommit
    write_u32(buf, off + 104, 0);                                  // LoaderFlags
    write_u32(buf, off + 108, 16);                                 // NumberOfRvaAndSizes
    // Data directories (112..239) — all zero
}

//------------------------------------------------------------------------------
// composePe64MinimalImage
//------------------------------------------------------------------------------
std::vector<uint8_t> composePe64MinimalImage(const EmitBlueprint& bp) {
    std::vector<uint8_t> image;

    const uint32_t PE_LFANEW = 0xC0;
    const uint32_t DOS_HEADER_SIZE = 64;
    const uint32_t DOS_STUB_SIZE = PE_LFANEW - DOS_HEADER_SIZE;  // 64 bytes
    const uint32_t PE_SIG_SIZE = 4;
    const uint32_t COFF_HEADER_SIZE = 20;
    const uint32_t OPTIONAL_HEADER_SIZE = 0xF0;  // 240
    const uint32_t SECTION_HEADER_SIZE = 40;

    const uint16_t numSections = 1;
    const uint32_t sectionHeaderOffset =
        PE_LFANEW + PE_SIG_SIZE + COFF_HEADER_SIZE + OPTIONAL_HEADER_SIZE;

    const uint32_t rawHeaders =
        PE_LFANEW + PE_SIG_SIZE + COFF_HEADER_SIZE + OPTIONAL_HEADER_SIZE +
        SECTION_HEADER_SIZE * numSections;
    const uint32_t sizeOfHeaders = align_up(rawHeaders, bp.fileAlignment);

    // .text section at RVA 0x1000
    const uint32_t textRVA = 0x1000;
    const uint32_t textVirtualSize = align_up(bp.codeSize, bp.sectionAlignment);
    const uint32_t textRawSize = align_up(bp.codeSize, bp.fileAlignment);
    const uint32_t textRawOffset = sizeOfHeaders;

    const uint32_t sizeOfImage =
        align_up(textRVA + textVirtualSize, bp.sectionAlignment);

    // Calculate total file size
    const uint32_t totalFileSize = textRawOffset + textRawSize;

    image.resize(totalFileSize, 0);

    // ---- DOS header + stub ----
    write_pe_dos_header(image, PE_LFANEW);

    // ---- PE signature ----
    image[PE_LFANEW]     = 'P';
    image[PE_LFANEW + 1] = 'E';
    image[PE_LFANEW + 2] = 0;
    image[PE_LFANEW + 3] = 0;

    // ---- COFF header ----
    write_pe_coff_header(image, PE_LFANEW + PE_SIG_SIZE, numSections);

    // ---- Optional header ----
    write_pe_optional_header(image,
                             PE_LFANEW + PE_SIG_SIZE + COFF_HEADER_SIZE,
                             bp,
                             textRVA,                    // entry RVA
                             sizeOfHeaders,
                             sizeOfImage);

    // ---- Section header (.text) ----
    size_t shOff = PE_LFANEW + PE_SIG_SIZE + COFF_HEADER_SIZE + OPTIONAL_HEADER_SIZE;
    memset(image.data() + shOff, 0, 8);                      // Name: ".text"
    memcpy(image.data() + shOff, ".text", 5);
    write_u32(image, shOff + 8,  textVirtualSize);           // VirtualSize
    write_u32(image, shOff + 12, textRVA);                   // VirtualAddress
    write_u32(image, shOff + 16, textRawSize);               // SizeOfRawData
    write_u32(image, shOff + 20, textRawOffset);             // PointerToRawData
    write_u32(image, shOff + 24, 0);                         // PointerToRelocations
    write_u32(image, shOff + 28, 0);                         // PointerToLinenumbers
    write_u16(image, shOff + 32, 0);                         // NumberOfRelocations
    write_u16(image, shOff + 34, 0);                         // NumberOfLinenumbers
    write_u32(image, shOff + 36, 0x60000020);                // Characteristics (CODE | EXECUTE | READ)

    // ---- Section raw data ----
    memcpy(image.data() + textRawOffset, bp.codeBytes.data(), bp.codeBytes.size());

    return image;
}

//------------------------------------------------------------------------------
// composePe64MinimalImageFromManifest
//------------------------------------------------------------------------------
std::vector<uint8_t> composePe64MinimalImageFromManifest(
    const TargetManifest& manifest, const std::vector<uint8_t>& codeBytes) {
    auto bp = emitBlueprintFromManifest(manifest, codeBytes);
    return composePe64MinimalImage(bp);
}

//------------------------------------------------------------------------------
// ELF64 constants
//------------------------------------------------------------------------------
static constexpr uint16_t ELF_CLASS_64 = 2;
static constexpr uint8_t  ELF_DATA_LSB = 1;
static constexpr uint8_t  ELF_VERSION  = 1;
static constexpr uint8_t  ELF_OSABI_SYSV = 0;
static constexpr uint16_t ELF_TYPE_EXEC = 2;
static constexpr uint16_t ELF_MACHINE_X86_64 = 0x3E;
static constexpr uint16_t ELF_MACHINE_AARCH64 = 0xB7;
static constexpr uint16_t ELF_EV_CURRENT = 1;
static constexpr uint16_t ELF_PHDR_ENTRY_SIZE = 56;
static constexpr uint16_t ELF_SHDR_ENTRY_SIZE = 64;
static constexpr uint32_t ELF_PT_LOAD = 1;
static constexpr uint32_t ELF_PT_GNU_STACK = 0x6474E551;

//------------------------------------------------------------------------------
// manifest_arch_is_x64 — determine arch from image base
//------------------------------------------------------------------------------
static bool manifest_arch_is_x64(const EmitBlueprint& bp) {
    return bp.imageBase == 0x0000000140000000ULL;
}

//------------------------------------------------------------------------------
// composeElf64MinimalImage
//------------------------------------------------------------------------------
std::vector<uint8_t> composeElf64MinimalImage(const EmitBlueprint& bp) {
    std::vector<uint8_t> image;

    const uint64_t entryVA = bp.entryVA;
    const uint64_t loadVAddr = 0x1000ULL;  // first segment at 0x1000
    const uint64_t loadOffset = 0x1000ULL; // same offset for simplicity
    const uint32_t e_phentsize = ELF_PHDR_ENTRY_SIZE;
    const uint32_t e_phnum = 2;  // one LOAD + one GNU_STACK
    const uint32_t e_phoff = 64; // after ELF header
    const uint32_t e_shoff = 0;  // no section headers for minimal image

    const uint64_t p_filesz = bp.codeSize;
    const uint64_t p_memsz  = align_up64(bp.codeSize, 0x1000ULL);
    const uint64_t p_vaddr  = loadVAddr;
    const uint64_t p_paddr  = loadVAddr;
    const uint64_t p_align  = 0x1000ULL;

    // Total file size = ELF header + program headers + segment data
    const uint32_t totalSize =
        e_phoff + e_phentsize * e_phnum + static_cast<uint32_t>(align_up64(p_filesz, p_align));

    image.resize(totalSize, 0);

    // ---- ELF identification (e_ident, 16 bytes) ----
    image[0] = 0x7F; image[1] = 'E'; image[2] = 'L'; image[3] = 'F';
    image[4] = ELF_CLASS_64;       // 64-bit
    image[5] = ELF_DATA_LSB;       // little-endian
    image[6] = ELF_VERSION;        // version 1
    image[7] = ELF_OSABI_SYSV;     // System V ABI
    // bytes 8-15 are padding (ABI version + pad)

    // ---- ELF header fields ----
    write_u16(image, 16, ELF_TYPE_EXEC);         // e_type
    write_u16(image, 18, (manifest_arch_is_x64(bp) ? ELF_MACHINE_X86_64 : ELF_MACHINE_AARCH64)); // e_machine
    write_u32(image, 20, ELF_EV_CURRENT);         // e_version
    write_u64(image, 24, entryVA);                // e_entry
    write_u64(image, 32, e_phoff);                // e_phoff
    write_u64(image, 40, e_shoff);                // e_shoff
    write_u32(image, 48, 0);                      // e_flags
    write_u16(image, 52, 64);                     // e_ehsize
    write_u16(image, 54, e_phentsize);            // e_phentsize
    write_u16(image, 56, e_phnum);                // e_phnum
    write_u16(image, 58, 0);                      // e_shentsize
    write_u16(image, 60, 0);                      // e_shnum
    write_u16(image, 62, 0);                      // e_shstrndx

    // ---- Program header 1: PT_LOAD ----
    size_t ph1 = e_phoff;
    write_u32(image, ph1 + 0, ELF_PT_LOAD);                          // p_type
    write_u32(image, ph1 + 4, 5);                                    // p_flags (R|X)
    write_u64(image, ph1 + 8, loadOffset);                           // p_offset
    write_u64(image, ph1 + 16, p_vaddr);                             // p_vaddr
    write_u64(image, ph1 + 24, p_paddr);                             // p_paddr
    write_u64(image, ph1 + 32, p_filesz);                            // p_filesz
    write_u64(image, ph1 + 40, p_memsz);                             // p_memsz
    write_u64(image, ph1 + 48, p_align);                             // p_align

    // ---- Program header 2: PT_GNU_STACK ----
    size_t ph2 = ph1 + e_phentsize;
    write_u32(image, ph2 + 0, ELF_PT_GNU_STACK);                     // p_type
    write_u32(image, ph2 + 4, 6);                                    // p_flags (R|W)
    write_u64(image, ph2 + 8, 0);                                    // p_offset
    write_u64(image, ph2 + 16, 0);                                   // p_vaddr
    write_u64(image, ph2 + 24, 0);                                   // p_paddr
    write_u64(image, ph2 + 32, 0);                                   // p_filesz
    write_u64(image, ph2 + 40, 0);                                   // p_memsz
    write_u64(image, ph2 + 48, 0x1000ULL);                           // p_align

    // ---- Segment data ----
    memcpy(image.data() + loadOffset, bp.codeBytes.data(), bp.codeBytes.size());

    return image;
}

//------------------------------------------------------------------------------
// composeElf64MinimalImageFromManifest
//------------------------------------------------------------------------------
std::vector<uint8_t> composeElf64MinimalImageFromManifest(
    const TargetManifest& manifest, const std::vector<uint8_t>& codeBytes) {
    auto bp = emitBlueprintFromManifest(manifest, codeBytes);
    return composeElf64MinimalImage(bp);
}

//------------------------------------------------------------------------------
// Mach-O 64 constants
//------------------------------------------------------------------------------
static constexpr uint32_t MACHO_MAGIC_64 = 0xFEEDFACF;
static constexpr uint32_t MACHO_CPUTYPE_X86_64 = 0x01000007;
static constexpr uint32_t MACHO_CPUTYPE_ARM64  = 0x0100000C;
static constexpr uint32_t MACHO_CPUSUBTYPE_X86_64_ALL = 3;
static constexpr uint32_t MACHO_CPUSUBTYPE_ARM64_ALL  = 0;
static constexpr uint32_t MACHO_FILETYPE_EXECUTE = 2;
static constexpr uint32_t MACHO_NCXFLAGS = 0x00000001; // twolevel
static constexpr uint32_t MACHO_LC_SEGMENT_64 = 0x19;
static constexpr uint32_t MACHO_LC_MAIN = 0x80000028;
static constexpr uint32_t MACHO_SEGMENT_NAME_SIZE = 16;
static constexpr uint32_t MACHO_SECTION_NAME_SIZE = 16;
static constexpr uint32_t MACHO_LC_MAIN_SIZE = 24;
static constexpr uint32_t MACHO_SEGMENT_COMMAND_64_SIZE = 72;
static constexpr uint32_t MACHO_SECTION_64_SIZE = 80;

//------------------------------------------------------------------------------
// composeMacho64MinimalImage
//------------------------------------------------------------------------------
std::vector<uint8_t> composeMacho64MinimalImage(const EmitBlueprint& bp) {
    std::vector<uint8_t> image;

    // Determine architecture
    bool isArm64 = (bp.imageBase == 0x0000000100000000ULL);
    uint32_t cpuType = isArm64 ? MACHO_CPUTYPE_ARM64 : MACHO_CPUTYPE_X86_64;
    uint32_t cpuSubtype = isArm64 ? MACHO_CPUSUBTYPE_ARM64_ALL : MACHO_CPUSUBTYPE_X86_64_ALL;

    // Segment __TEXT at file offset 0
    const uint64_t segAddr = 0x100000000ULL;  // typical mach-o load address
    const uint64_t segSize = align_up64(static_cast<uint64_t>(bp.codeSize + 0x1000), 0x1000ULL);
    const uint64_t segFileSize = align_up64(static_cast<uint64_t>(bp.codeSize), 0x1000ULL);

    const uint64_t secAddr = segAddr + 0x1000;  // __text after __header
    const uint64_t secSize = static_cast<uint64_t>(bp.codeSize);
    const uint64_t secOffset = 0x1000ULL;  // section data at file offset 0x1000

    const uint32_t entryOffset = static_cast<uint32_t>(secOffset);  // file offset of entry point code
    const uint32_t stackSize = 0x100000; // 1MB initial stack

    // Load commands: LC_SEGMENT_64 + LC_MAIN
    const uint32_t sizeofcmds =
        MACHO_SEGMENT_COMMAND_64_SIZE + MACHO_SECTION_64_SIZE + MACHO_LC_MAIN_SIZE;

    const uint32_t totalSize = static_cast<uint32_t>(
        align_up64(secOffset + static_cast<uint64_t>(bp.codeSize), 0x1000ULL));

    image.resize(totalSize, 0);

    // ---- Mach-O header (32 bytes) ----
    write_u32(image, 0, MACHO_MAGIC_64);                   // magic
    write_u32(image, 4, cpuType);                          // cputype
    write_u32(image, 8, cpuSubtype);                       // cpusubtype
    write_u32(image, 12, MACHO_FILETYPE_EXECUTE);          // filetype
    write_u32(image, 16, 2);                               // ncmds
    write_u32(image, 20, sizeofcmds);                      // sizeofcmds
    write_u32(image, 24, MACHO_NCXFLAGS);                  // flags

    // ---- Load command 1: LC_SEGMENT_64 (__TEXT) ----
    size_t lc1 = 32;
    write_u32(image, lc1 + 0, MACHO_LC_SEGMENT_64);        // cmd
    write_u32(image, lc1 + 4, MACHO_SEGMENT_COMMAND_64_SIZE + MACHO_SECTION_64_SIZE); // cmdsize
    memcpy(image.data() + lc1 + 8, "__TEXT", 6);          // segname
    write_u64(image, lc1 + 24, segAddr);                   // vmaddr
    write_u64(image, lc1 + 32, segSize);                   // vmsize
    write_u64(image, lc1 + 40, 0);                         // fileoff
    write_u64(image, lc1 + 48, segFileSize);               // filesize
    write_u32(image, lc1 + 56, 7);                         // maxprot (rwx)
    write_u32(image, lc1 + 60, 7);                         // initprot (rwx)
    write_u32(image, lc1 + 64, 1);                         // nsects
    write_u32(image, lc1 + 68, 0);                         // flags

    // ---- Section: __text within __TEXT ----
    size_t secOff = lc1 + MACHO_SEGMENT_COMMAND_64_SIZE;
    memcpy(image.data() + secOff + 0, "__text", 6);        // sectname
    memcpy(image.data() + secOff + 16, "__TEXT", 6);       // segname
    write_u64(image, secOff + 32, secAddr);                // addr
    write_u64(image, secOff + 40, secSize);                // size
    write_u64(image, secOff + 48, secOffset);              // offset
    write_u32(image, secOff + 56, 0);                      // align (2^0 = 1)
    write_u32(image, secOff + 60, 0);                      // reloff
    write_u32(image, secOff + 64, 0);                      // nreloc
    write_u32(image, secOff + 68, 0);                      // flags
    write_u32(image, secOff + 72, 0);                      // reserved1
    write_u32(image, secOff + 76, 0);                      // reserved2

    // ---- Load command 2: LC_MAIN ----
    size_t lc2 = lc1 + MACHO_SEGMENT_COMMAND_64_SIZE + MACHO_SECTION_64_SIZE;
    write_u32(image, lc2 + 0, MACHO_LC_MAIN);              // cmd
    write_u32(image, lc2 + 4, MACHO_LC_MAIN_SIZE);         // cmdsize
    write_u64(image, lc2 + 8, entryOffset);                // entryoff (at file offset 192)
    write_u64(image, lc2 + 16, stackSize);                 // stacksize

    // ---- Section data (__text) ----
    memcpy(image.data() + secOffset, bp.codeBytes.data(), bp.codeBytes.size());

    return image;
}

//------------------------------------------------------------------------------
// composeMacho64MinimalImageFromManifest
//------------------------------------------------------------------------------
std::vector<uint8_t> composeMacho64MinimalImageFromManifest(
    const TargetManifest& manifest, const std::vector<uint8_t>& codeBytes) {
    auto bp = emitBlueprintFromManifest(manifest, codeBytes);
    return composeMacho64MinimalImage(bp);
}

} // namespace rawrxd::sovereign
