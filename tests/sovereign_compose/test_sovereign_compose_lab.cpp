//==============================================================================
// test_sovereign_compose_lab.cpp
//
// Tri-format compose lab test — verifies structural properties of PE64, ELF64,
// and Mach-O 64 minimal images produced by compose* functions.
//
// Tests:
//   testTriFormatEntryContract — NOP+RET payload validation
//   testPe64Structure          — PE header, section, entry point validation
//   testElf64Structure         — ELF header, program headers validation
//   testMacho64Structure       — Mach-O header, load commands validation
//==============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>

#include "sovereign_target_manifest.hpp"
#include "sovereign_emit_formats.hpp"

using namespace rawrxd::sovereign;

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg)                                              \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::printf("  FAIL: %s (line %d)\n", msg, __LINE__);           \
            g_tests_failed++;                                               \
        } else {                                                            \
            g_tests_passed++;                                               \
        }                                                                   \
    } while (0)

//------------------------------------------------------------------------------
// Minimal NOP+RET payload (x86_64): 90 C3
//------------------------------------------------------------------------------
static std::vector<uint8_t> make_nop_ret_payload() {
    return {0x90, 0xC3};  // nop; ret
}

//------------------------------------------------------------------------------
// testPe64Structure — validate PE64 minimal image
//------------------------------------------------------------------------------
static void testPe64Structure() {
    std::printf("testPe64Structure...\n");

    auto manifest = default_windows_x64_manifest();
    auto payload = make_nop_ret_payload();
    auto image = composePe64MinimalImageFromManifest(manifest, payload);

    // File must be non-empty
    TEST_ASSERT(!image.empty(), "PE image not empty");

    // DOS header: MZ signature
    TEST_ASSERT(image[0] == 0x4D && image[1] == 0x5A, "PE DOS MZ signature");

    // PE signature at e_lfanew
    uint32_t peOffset = (image[0x3C] | (image[0x3D] << 8) |
                        (image[0x3E] << 16) | (image[0x3F] << 24));
    TEST_ASSERT(peOffset == 0xC0, "PE e_lfanew == 0xC0");
    TEST_ASSERT(image[peOffset] == 'P' && image[peOffset+1] == 'E',
                "PE signature 'PE\\0\\0'");

    // COFF header: Machine = 0x8664 (x64)
    uint16_t machine = image[peOffset+4] | (image[peOffset+5] << 8);
    TEST_ASSERT(machine == 0x8664, "PE machine == x64");

    // Optional header: Magic = 0x020B (PE32+)
    uint16_t magic = image[peOffset+4+20+0] | (image[peOffset+4+20+1] << 8);
    TEST_ASSERT(magic == 0x020B, "PE optional header magic == PE32+");

    // Entry point at RVA 0x1000
    uint32_t entryRVA = image[peOffset+4+20+16] |
                       (image[peOffset+4+20+17] << 8) |
                       (image[peOffset+4+20+18] << 16) |
                       (image[peOffset+4+20+19] << 24);
    TEST_ASSERT(entryRVA == 0x1000, "PE entry point RVA == 0x1000");

    // SizeOfImage divisible by SectionAlignment (0x1000)
    uint32_t sizeOfImage = image[peOffset+4+20+56] |
                          (image[peOffset+4+20+57] << 8) |
                          (image[peOffset+4+20+58] << 16) |
                          (image[peOffset+4+20+59] << 24);
    TEST_ASSERT(sizeOfImage % 0x1000 == 0, "PE SizeOfImage divisible by 0x1000");

    // CheckSum == 0
    uint32_t checkSum = image[peOffset+4+20+64] |
                       (image[peOffset+4+20+65] << 8) |
                       (image[peOffset+4+20+66] << 16) |
                       (image[peOffset+4+20+67] << 24);
    TEST_ASSERT(checkSum == 0, "PE CheckSum == 0");

    // .text section data present at file offset
    uint32_t sizeOfHeaders = image[peOffset+4+20+60] |
                            (image[peOffset+4+20+61] << 8) |
                            (image[peOffset+4+20+62] << 16) |
                            (image[peOffset+4+20+63] << 24);
    TEST_ASSERT(sizeOfHeaders > 0, "PE SizeOfHeaders > 0");
    TEST_ASSERT(image.size() > sizeOfHeaders, "PE file larger than headers");

    // NOP+RET payload bytes present in .text section
    bool foundNopRet = false;
    for (size_t i = sizeOfHeaders; i + 1 < image.size(); i++) {
        if (image[i] == 0x90 && image[i+1] == 0xC3) {
            foundNopRet = true;
            break;
        }
    }
    TEST_ASSERT(foundNopRet, "PE .text contains NOP+RET payload");

    std::printf("  PE64: size=%zu, entry=0x%X, imageSize=0x%X, headers=0x%X\n",
                image.size(), entryRVA, sizeOfImage, sizeOfHeaders);
}

//------------------------------------------------------------------------------
// testElf64Structure — validate ELF64 minimal image
//------------------------------------------------------------------------------
static void testElf64Structure() {
    std::printf("testElf64Structure...\n");

    auto manifest = default_linux_x64_manifest();
    auto payload = make_nop_ret_payload();
    auto image = composeElf64MinimalImageFromManifest(manifest, payload);

    TEST_ASSERT(!image.empty(), "ELF image not empty");

    // ELF magic
    TEST_ASSERT(image[0] == 0x7F && image[1] == 'E' && image[2] == 'L' &&
                image[3] == 'F', "ELF magic");
    TEST_ASSERT(image[4] == 2, "ELF 64-bit class");
    TEST_ASSERT(image[5] == 1, "ELF little-endian data");

    // e_type = ET_EXEC (2)
    uint16_t eType = image[16] | (image[17] << 8);
    TEST_ASSERT(eType == 2, "ELF e_type == ET_EXEC");

    // e_machine = EM_X86_64 (0x3E)
    uint16_t eMachine = image[18] | (image[19] << 8);
    TEST_ASSERT(eMachine == 0x3E, "ELF e_machine == EM_X86_64");

    // e_entry — entry point virtual address
    uint64_t eEntry = image[24] | (image[25] << 8) | (image[26] << 16) |
                      (image[27] << 24) | ((uint64_t)image[28] << 32) |
                      ((uint64_t)image[29] << 40) | ((uint64_t)image[30] << 48) |
                      ((uint64_t)image[31] << 56);
    TEST_ASSERT(eEntry != 0, "ELF e_entry != 0");

    // e_phoff — program header offset
    uint64_t ePhoff = image[32] | (image[33] << 8) | (image[34] << 16) |
                      (image[35] << 24);
    TEST_ASSERT(ePhoff == 64, "ELF e_phoff == 64");

    // e_phentsize = 56
    uint16_t ePhentsize = image[54] | (image[55] << 8);
    TEST_ASSERT(ePhentsize == 56, "ELF e_phentsize == 56");

    // e_phnum = 2
    uint16_t ePhnum = image[56] | (image[57] << 8);
    TEST_ASSERT(ePhnum == 2, "ELF e_phnum == 2");

    // PT_LOAD segment: p_type = 1 at offset e_phoff
    uint32_t pType = image[ePhoff] | (image[ePhoff+1] << 8) |
                     (image[ePhoff+2] << 16) | (image[ePhoff+3] << 24);
    TEST_ASSERT(pType == 1, "ELF PT_LOAD segment present");

    // p_filesz <= p_memsz, p_memsz page-aligned
    uint64_t pFilesz = image[ePhoff+32] | (image[ePhoff+33] << 8) |
                       (image[ePhoff+34] << 16) | (image[ePhoff+35] << 24) |
                       ((uint64_t)image[ePhoff+36] << 32) |
                       ((uint64_t)image[ePhoff+37] << 40) |
                       ((uint64_t)image[ePhoff+38] << 48) |
                       ((uint64_t)image[ePhoff+39] << 56);
    uint64_t pMemsz  = image[ePhoff+40] | (image[ePhoff+41] << 8) |
                       (image[ePhoff+42] << 16) | (image[ePhoff+43] << 24) |
                       ((uint64_t)image[ePhoff+44] << 32) |
                       ((uint64_t)image[ePhoff+45] << 40) |
                       ((uint64_t)image[ePhoff+46] << 48) |
                       ((uint64_t)image[ePhoff+47] << 56);
    TEST_ASSERT(pMemsz >= pFilesz, "ELF p_memsz >= p_filesz");
    TEST_ASSERT(pMemsz % 0x1000 == 0, "ELF p_memsz page-aligned");

    // NOP+RET payload in segment data
    bool foundNopRet = false;
    for (size_t i = 0x1000; i + 1 < image.size(); i++) {
        if (image[i] == 0x90 && image[i+1] == 0xC3) {
            foundNopRet = true;
            break;
        }
    }
    TEST_ASSERT(foundNopRet, "ELF segment contains NOP+RET payload");

    std::printf("  ELF64: size=%zu, entry=0x%llX, filesz=%llu, memsz=%llu\n",
                image.size(), (unsigned long long)eEntry,
                (unsigned long long)pFilesz, (unsigned long long)pMemsz);
}

//------------------------------------------------------------------------------
// testMacho64Structure — validate Mach-O 64 minimal image
//------------------------------------------------------------------------------
static void testMacho64Structure() {
    std::printf("testMacho64Structure...\n");

    auto manifest = default_macos_x64_manifest();
    auto payload = make_nop_ret_payload();
    auto image = composeMacho64MinimalImageFromManifest(manifest, payload);

    TEST_ASSERT(!image.empty(), "Mach-O image not empty");

    // Mach-O magic 64
    uint32_t magic = image[0] | (image[1] << 8) | (image[2] << 16) | (image[3] << 24);
    TEST_ASSERT(magic == 0xFEEDFACF, "Mach-O magic 64");

    // cputype: x86_64 = 0x01000007
    uint32_t cpuType = image[4] | (image[5] << 8) | (image[6] << 16) | (image[7] << 24);
    TEST_ASSERT(cpuType == 0x01000007, "Mach-O cputype == x86_64");

    // filetype = 2 (EXECUTE)
    uint32_t fileType = image[12] | (image[13] << 8) | (image[14] << 16) | (image[15] << 24);
    TEST_ASSERT(fileType == 2, "Mach-O filetype == MH_EXECUTE");

    // ncmds
    uint32_t ncmds = image[16] | (image[17] << 8) | (image[18] << 16) | (image[19] << 24);
    TEST_ASSERT(ncmds == 2, "Mach-O ncmds == 2");

    // sizeofcmds
    uint32_t sizeofcmds = image[20] | (image[21] << 8) | (image[22] << 16) | (image[23] << 24);
    TEST_ASSERT(sizeofcmds == 152 + 24, "Mach-O sizeofcmds == 176");
    TEST_ASSERT(sizeofcmds % 8 == 0, "Mach-O sizeofcmds % 8 == 0");

    // LC_MAIN command starts at offset 184 (32 header + 72 segment + 80 section)
    // LC_MAIN.cmd at offset 184, LC_MAIN.entryoff at offset 192
    uint32_t lcMainCmd = image[184] | (image[185] << 8) | (image[186] << 16) | (image[187] << 24);
    TEST_ASSERT(lcMainCmd == 0x80000028, "Mach-O LC_MAIN.cmd at offset 184");

    uint64_t lcMainEntryoff = image[192] | (image[193] << 8) | (image[194] << 16) | (image[195] << 24) |
                              ((uint64_t)image[196] << 32) | ((uint64_t)image[197] << 40) |
                              ((uint64_t)image[198] << 48) | ((uint64_t)image[199] << 56);
    TEST_ASSERT(lcMainEntryoff == 0x1000, "Mach-O LC_MAIN.entryoff at offset 192 == 0x1000");

    // Segment data present
    bool foundNopRet = false;
    for (size_t i = 0x1000; i + 1 < image.size(); i++) {
        if (image[i] == 0x90 && image[i+1] == 0xC3) {
            foundNopRet = true;
            break;
        }
    }
    TEST_ASSERT(foundNopRet, "Mach-O __text contains NOP+RET payload");

    std::printf("  Mach-O: size=%zu, magic=0x%X, cpuType=0x%X, ncmds=%u, sizeofcmds=%u\n",
                image.size(), magic, cpuType, ncmds, sizeofcmds);
}

//------------------------------------------------------------------------------
// testTriFormatEntryContract — the contract test from the spec
//------------------------------------------------------------------------------
static void testTriFormatEntryContract() {
    std::printf("testTriFormatEntryContract...\n");

    // Test all three formats with NOP+RET payload
    auto winManifest = default_windows_x64_manifest();
    auto linManifest = default_linux_x64_manifest();
    auto macManifest = default_macos_x64_manifest();
    auto payload = make_nop_ret_payload();

    auto peImage = composePe64MinimalImageFromManifest(winManifest, payload);
    auto elfImage = composeElf64MinimalImageFromManifest(linManifest, payload);
    auto machImage = composeMacho64MinimalImageFromManifest(macManifest, payload);

    // All three must be non-empty
    TEST_ASSERT(!peImage.empty(), "PE image non-empty");
    TEST_ASSERT(!elfImage.empty(), "ELF image non-empty");
    TEST_ASSERT(!machImage.empty(), "Mach-O image non-empty");

    // All three must contain the NOP+RET payload
    bool peHasPayload = false, elfHasPayload = false, machHasPayload = false;
    for (size_t i = 0; i + 1 < peImage.size(); i++) {
        if (peImage[i] == 0x90 && peImage[i+1] == 0xC3) { peHasPayload = true; break; }
    }
    for (size_t i = 0; i + 1 < elfImage.size(); i++) {
        if (elfImage[i] == 0x90 && elfImage[i+1] == 0xC3) { elfHasPayload = true; break; }
    }
    for (size_t i = 0; i + 1 < machImage.size(); i++) {
        if (machImage[i] == 0x90 && machImage[i+1] == 0xC3) { machHasPayload = true; break; }
    }
    TEST_ASSERT(peHasPayload, "PE contains NOP+RET");
    TEST_ASSERT(elfHasPayload, "ELF contains NOP+RET");
    TEST_ASSERT(machHasPayload, "Mach-O contains NOP+RET");

    // Each format must have distinct magic bytes
    TEST_ASSERT(peImage[0] == 0x4D && peImage[1] == 0x5A, "PE starts with MZ");
    TEST_ASSERT(elfImage[0] == 0x7F && elfImage[1] == 'E', "ELF starts with 0x7FELF");
    TEST_ASSERT(machImage[0] == 0xCF && machImage[1] == 0xFA &&
                machImage[2] == 0xED && machImage[3] == 0xFE, "Mach-O starts with FEEDFACF (little-endian read)");

    std::printf("  Tri-format contract: all 3 formats produce valid images with payload\n");
}

//------------------------------------------------------------------------------
// main
//------------------------------------------------------------------------------
int main(void) {
    std::printf("=== RawrXD Sovereign Tri-Format Compose Lab Test ===\n\n");

    testPe64Structure();
    testElf64Structure();
    testMacho64Structure();
    testTriFormatEntryContract();

    std::printf("\n=== Results: %d passed, %d failed ===\n",
                g_tests_passed, g_tests_failed);

    return g_tests_failed > 0 ? 1 : 0;
}
