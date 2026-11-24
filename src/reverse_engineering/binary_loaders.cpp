// =============================================================================
// binary_loaders.cpp — R1 ELF/Mach-O/PE header parsing.
// =============================================================================
#include "binary_loaders.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

namespace rawrxd::re {

namespace {

bool ReadAll(const std::string& path, std::vector<uint8_t>& buf) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size <= 0 || size > 64 * 1024 * 1024) return false;
    buf.resize((size_t)size);
    in.seekg(0);
    in.read(reinterpret_cast<char*>(buf.data()), size);
    return (bool)in;
}

template <typename T>
bool ReadStruct(const std::vector<uint8_t>& b, size_t off, T& out) {
    if (off + sizeof(T) > b.size()) return false;
    std::memcpy(&out, b.data() + off, sizeof(T));
    return true;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

// ELF64 header (64 bytes) — fields at fixed offsets.
bool ParseElf64(const std::vector<uint8_t>& b, BinaryInfo& info) {
    if (b.size() < 64) return false;
    const bool le = b[5] == 1;
    (void)le;  // little-endian assumed (x86/arm64 targets)
    const uint16_t e_type = b[16] | (b[17] << 8);
    (void)e_type;
    const uint16_t e_machine = b[18] | (b[19] << 8);
    info.arch = e_machine == 0x3e ? "x86-64"
              : e_machine == 0xb7 ? "aarch64"
              : e_machine == 0x28 ? "arm" : "unknown";
    const uint64_t e_entry = (uint64_t)b[24] | ((uint64_t)b[25] << 8) |
        ((uint64_t)b[26] << 16) | ((uint64_t)b[27] << 24) |
        ((uint64_t)b[28] << 32) | ((uint64_t)b[29] << 40) |
        ((uint64_t)b[30] << 48) | ((uint64_t)b[31] << 56);
    info.entry = e_entry;
    const uint64_t e_shoff = (uint64_t)b[40] | ((uint64_t)b[41] << 8) |
        ((uint64_t)b[42] << 16) | ((uint64_t)b[43] << 24) |
        ((uint64_t)b[44] << 32) | ((uint64_t)b[45] << 40) |
        ((uint64_t)b[46] << 48) | ((uint64_t)b[47] << 56);
    const uint16_t e_shentsize = b[58] | (b[59] << 8);
    const uint16_t e_shnum = b[60] | (b[61] << 8);
    const uint16_t e_shstrndx = b[62] | (b[63] << 8);
    if (e_shoff == 0 || e_shnum == 0 || e_shentsize < 64) return true;
    // Section header string table index.
    const uint64_t strOff = e_shoff + (uint64_t)e_shstrndx * e_shentsize;
    uint64_t strSize = 0, strAddr = 0;
    if (strOff + 64 <= b.size()) {
        strSize = (uint64_t)b[strOff + 32] | ((uint64_t)b[strOff + 33] << 8) |
            ((uint64_t)b[strOff + 34] << 16) | ((uint64_t)b[strOff + 35] << 24);
        strAddr = (uint64_t)b[strOff + 24] | ((uint64_t)b[strOff + 25] << 8) |
            ((uint64_t)b[strOff + 26] << 16) | ((uint64_t)b[strOff + 27] << 24);
    }
    for (uint16_t i = 0; i < e_shnum; ++i) {
        const uint64_t off = e_shoff + (uint64_t)i * e_shentsize;
        uint64_t sh = 0;
        if (!ReadStruct(b, off, sh)) break;
        const uint32_t nameOff = (uint32_t)(sh & 0xffffffffu);
        const uint64_t addr = (uint64_t)b[off + 16] | ((uint64_t)b[off + 17] << 8) |
            ((uint64_t)b[off + 18] << 16) | ((uint64_t)b[off + 19] << 24) |
            ((uint64_t)b[off + 20] << 32) | ((uint64_t)b[off + 21] << 40) |
            ((uint64_t)b[off + 22] << 48) | ((uint64_t)b[off + 23] << 56);
        const uint64_t size = (uint64_t)b[off + 32] | ((uint64_t)b[off + 33] << 8) |
            ((uint64_t)b[off + 34] << 16) | ((uint64_t)b[off + 35] << 24);
        SectionInfo s;
        s.address = addr;
        s.size = size;
        if (strSize > 0 && nameOff < strSize &&
            strAddr + nameOff < b.size()) {
            const char* p = reinterpret_cast<const char*>(b.data() + strAddr + nameOff);
            s.name = p;
        }
        info.sections.push_back(std::move(s));
    }
    return true;
}

// Mach-O 64 header (32 bytes).
bool ParseMacho64(const std::vector<uint8_t>& b, BinaryInfo& info) {
    if (b.size() < 32) return false;
    const uint32_t cputype = (uint32_t)b[4] | ((uint32_t)b[5] << 8) |
        ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
    info.arch = cputype == 0x01000007 ? "x86-64"
              : cputype == 0x0100000c ? "arm64" : "unknown";
    const uint64_t entry = (uint64_t)b[8] | ((uint64_t)b[9] << 8) |
        ((uint64_t)b[10] << 16) | ((uint64_t)b[11] << 24) |
        ((uint64_t)b[12] << 32) | ((uint64_t)b[13] << 40) |
        ((uint64_t)b[14] << 48) | ((uint64_t)b[15] << 56);
    info.entry = entry;
    const uint32_t ncmds = (uint32_t)b[16] | ((uint32_t)b[17] << 8) |
        ((uint32_t)b[18] << 16) | ((uint32_t)b[19] << 24);
    uint32_t off = 32;
    for (uint32_t i = 0; i < ncmds && off + 8 <= b.size(); ++i) {
        const uint32_t cmd = (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
            ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
        const uint32_t cmdsize = (uint32_t)b[off + 4] | ((uint32_t)b[off + 5] << 8) |
            ((uint32_t)b[off + 6] << 16) | ((uint32_t)b[off + 7] << 24);
        if (cmdsize < 8) break;
        if (cmd == 0x19 && off + 72 <= b.size()) {  // LC_SEGMENT_64
            const char* segname = reinterpret_cast<const char*>(b.data() + off + 8);
            SectionInfo s;
            s.name = segname;
            s.address = (uint64_t)b[off + 24] | ((uint64_t)b[off + 25] << 8) |
                ((uint64_t)b[off + 26] << 16) | ((uint64_t)b[off + 27] << 24);
            s.size = (uint64_t)b[off + 32] | ((uint64_t)b[off + 33] << 8) |
                ((uint64_t)b[off + 34] << 16) | ((uint64_t)b[off + 35] << 24);
            info.sections.push_back(std::move(s));
        }
        off += cmdsize;
    }
    return true;
}

// PE: DOS header -> NT headers (64-bit optional header).
bool ParsePe(const std::vector<uint8_t>& b, BinaryInfo& info) {
    if (b.size() < 0x40) return false;
    const uint32_t peOff = (uint32_t)b[0x3c] | ((uint32_t)b[0x3d] << 8) |
        ((uint32_t)b[0x3e] << 16) | ((uint32_t)b[0x3f] << 24);
    if (peOff + 24 > b.size()) return false;
    const uint16_t machine = (uint16_t)(b[peOff + 4] | (b[peOff + 5] << 8));
    info.arch = machine == 0x8664 ? "x86-64"
              : machine == 0xaa64 ? "arm64"
              : machine == 0x14c ? "x86" : "unknown";
    const bool pe32plus = b[peOff + 24] == 0x20;
    const uint16_t optSize = (uint16_t)(b[peOff + 20] | (b[peOff + 21] << 8));
    const uint32_t entryRva = (uint32_t)b[peOff + 24 + 16] |
        ((uint32_t)b[peOff + 24 + 17] << 8) |
        ((uint32_t)b[peOff + 24 + 18] << 16) |
        ((uint32_t)b[peOff + 24 + 19] << 24);
    info.entry = entryRva;
    const uint32_t numSec = (uint32_t)b[peOff + 6] | ((uint32_t)b[peOff + 7] << 8);
    const uint32_t secOff = peOff + 24 + optSize;
    for (uint32_t i = 0; i < numSec && secOff + (i + 1) * 40 <= b.size(); ++i) {
        const uint32_t o = secOff + i * 40;
        SectionInfo s;
        s.name = reinterpret_cast<const char*>(b.data() + o);
        s.address = (uint32_t)b[o + 12] | ((uint32_t)b[o + 13] << 8) |
            ((uint32_t)b[o + 14] << 16) | ((uint32_t)b[o + 15] << 24);
        s.size = (uint32_t)b[o + 16] | ((uint32_t)b[o + 17] << 8) |
            ((uint32_t)b[o + 18] << 16) | ((uint32_t)b[o + 19] << 24);
        info.sections.push_back(std::move(s));
    }
    (void)pe32plus;
    return true;
}

}  // namespace

bool BinaryLoader::Load(const std::string& path, BinaryInfo& out) const {
    std::vector<uint8_t> b;
    if (!ReadAll(path, b) || b.size() < 8) return false;
    out = BinaryInfo{};
    if (b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
        out.format = b[4] == 2 ? BinaryFormat::Elf64 : BinaryFormat::Elf32;
        return ParseElf64(b, out);
    }
    const uint32_t magic = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
        ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    if (magic == 0xfeedfacf) {
        out.format = BinaryFormat::MachO64;
        return ParseMacho64(b, out);
    }
    if (magic == 0xcefaedfe) {
        out.format = BinaryFormat::MachO32;
        return ParseMacho64(b, out);
    }
    if (b[0] == 'M' && b[1] == 'Z') {
        out.format = BinaryFormat::Pe;
        return ParsePe(b, out);
    }
    return false;
}

const char* BinaryLoader::FormatName(BinaryFormat f) {
    switch (f) {
        case BinaryFormat::Elf32: return "ELF32";
        case BinaryFormat::Elf64: return "ELF64";
        case BinaryFormat::MachO32: return "Mach-O32";
        case BinaryFormat::MachO64: return "Mach-O64";
        case BinaryFormat::Pe: return "PE";
        default: return "unknown";
    }
}

std::string BinaryLoader::ToJson(const BinaryInfo& info) {
    std::ostringstream out;
    out << "{\"format\":\"" << FormatName(info.format) << "\",\"arch\":\""
        << JsonEscape(info.arch) << "\",\"entry\":" << info.entry
        << ",\"sections\":[";
    for (size_t i = 0; i < info.sections.size(); ++i) {
        const auto& s = info.sections[i];
        out << "{\"name\":\"" << JsonEscape(s.name) << "\",\"address\":"
            << s.address << ",\"size\":" << s.size << "}";
        if (i + 1 < info.sections.size()) out << ",";
    }
    out << "]}";
    return out.str();
}

}  // namespace rawrxd::re