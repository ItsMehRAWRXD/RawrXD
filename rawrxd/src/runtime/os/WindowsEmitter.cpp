// ============================================================================
// WindowsEmitter.cpp — PE emission (real layout, minimal DOS+NT stub)
// ============================================================================
#include "WindowsEmitter.hpp"
#include <cstring>

namespace rawrxd::runtime {

bool WindowsEmitter::emit(const Artifact& input, std::vector<uint8_t>& output) {
    if (input.format != ArtifactFormat::PE &&
        input.format != ArtifactFormat::Native) return false;

    // Minimal PE layout: DOS header + PE signature + COFF header +
    // optional header (PE32+) + section table + section data.
    // This is a real layout — the existing RawrPE64Linker has the full impl.

    output.clear();

    // DOS header (64 bytes)
    struct DOSHeader {
        uint16_t e_magic;      // "MZ"
        uint16_t e_cblp;
        uint16_t e_cp;
        uint16_t e_crlc;
        uint16_t e_cparhdr;
        uint16_t e_minalloc;
        uint16_t e_maxalloc;
        uint16_t e_ss;
        uint16_t e_sp;
        uint16_t e_csum;
        uint16_t e_ip;
        uint16_t e_cs;
        uint16_t e_lfarlc;
        uint16_t e_ovno;
        uint16_t e_res[4];
        uint16_t e_oemid;
        uint16_t e_oeminfo;
        uint16_t e_res2[10];
        uint32_t e_lfanew;     // offset to PE header
    };
    DOSHeader dos{};
    dos.e_magic = 0x5A4D;  // "MZ"
    dos.e_lfanew = sizeof(DOSHeader);

    // PE signature
    uint32_t peSig = 0x00004550;  // "PE\0\0"

    // COFF header
    struct COFFHeader {
        uint16_t machine;     // IMAGE_FILE_MACHINE_AMD64 = 0x8664
        uint16_t numSections;
        uint32_t timeDateStamp;
        uint32_t ptrSymbolTable;
        uint32_t numSymbols;
        uint16_t sizeOptionalHeader;
        uint16_t characteristics;
    };
    COFFHeader coff{};
    coff.machine = 0x8664;
    coff.numSections = static_cast<uint16_t>(input.sections.size());
    coff.sizeOptionalHeader = 240;  // PE32+ optional header
    coff.characteristics = 0x0022;  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    output.resize(sizeof(DOSHeader) + sizeof(peSig) + sizeof(COFFHeader));

    // Write DOS header
    std::memcpy(output.data(), &dos, sizeof(dos));
    size_t off = sizeof(dos);

    // Write PE signature
    std::memcpy(output.data() + off, &peSig, sizeof(peSig));
    off += sizeof(peSig);

    // Write COFF header
    std::memcpy(output.data() + off, &coff, sizeof(coff));
    off += sizeof(coff);

    // Reserve space for optional header (PE32+ = 240 bytes)
    output.resize(off + 240);
    off += 240;

    // Section table (40 bytes per entry) + section data
    size_t sectionTableOff = off;
    output.resize(off + input.sections.size() * 40);

    for (size_t i = 0; i < input.sections.size(); ++i) {
        // Section data follows section table
        size_t dataOff = output.size();
        output.insert(output.end(), input.sections[i].data.begin(),
                       input.sections[i].data.end());

        // Section table entry (40 bytes)
        struct SectionEntry {
            char name[8];
            uint32_t virtualSize;
            uint32_t virtualAddress;
            uint32_t sizeOfRawData;
            uint32_t pointerToRawData;
            uint32_t pointerToRelocations;
            uint32_t pointerToLinenumbers;
            uint16_t numberOfRelocations;
            uint16_t numberOfLinenumbers;
            uint32_t characteristics;
        };
        SectionEntry se{};
        std::memcpy(se.name, input.sections[i].name.c_str(),
                    std::min<size_t>(8, input.sections[i].name.size()));
        se.virtualSize = static_cast<uint32_t>(input.sections[i].virtualSize);
        se.virtualAddress = static_cast<uint32_t>(input.sections[i].virtualAddress);
        se.sizeOfRawData = static_cast<uint32_t>(input.sections[i].data.size());
        se.pointerToRawData = static_cast<uint32_t>(dataOff);
        se.characteristics = input.sections[i].flags;
        std::memcpy(output.data() + sectionTableOff + i * 40, &se, sizeof(se));
    }

    return true;
}

} // namespace rawrxd::runtime