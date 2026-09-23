#include "RawrPE64Linker.hpp"
#include <cstring>

namespace RawrXD {
namespace Backend {

uint32_t RawrPE64Linker::addSection(const std::string& name, uint32_t characteristics) {
    Section sec;
    sec.name = name;
    sec.characteristics = characteristics;
    m_sections.push_back(std::move(sec));
    return static_cast<uint32_t>(m_sections.size()) - 1;
}

uint8_t* RawrPE64Linker::sectionDataPtr(uint32_t sectionIndex) {
    if (sectionIndex >= m_sections.size()) return nullptr;
    return m_sections[sectionIndex].data.data();
}

void RawrPE64Linker::appendSectionData(uint32_t sectionIndex, const uint8_t* data, size_t len) {
    if (sectionIndex >= m_sections.size()) return;
    auto& sec = m_sections[sectionIndex];
    sec.data.insert(sec.data.end(), data, data + len);
    sec.virtualSize = static_cast<uint32_t>(sec.data.size());
}

void RawrPE64Linker::setEntryPoint(uint32_t sectionIndex, uint32_t offset) {
    m_entrySection = sectionIndex;
    m_entryOffset = offset;
}

void RawrPE64Linker::setImageBase(uint64_t base) { m_imageBase = base; }
void RawrPE64Linker::addImport(const ImportDesc& desc) { m_imports.push_back(desc); }
void RawrPE64Linker::addBaseRelocation(uint64_t rva) { m_relocs.push_back(rva); }

void RawrPE64Linker::writeU8(std::vector<uint8_t>& out, uint8_t v) {
    out.push_back(v);
}
void RawrPE64Linker::writeU16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}
void RawrPE64Linker::writeU32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((v >> (i*8)) & 0xFF));
}
void RawrPE64Linker::writeU64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (i*8)) & 0xFF));
}
void RawrPE64Linker::append(std::vector<uint8_t>& out, const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    out.insert(out.end(), p, p + len);
}

void RawrPE64Linker::patchU32(std::vector<uint8_t>& buf, size_t off, uint32_t v) const {
    if (off + 4 > buf.size()) return;
    buf[off+0] = static_cast<uint8_t>(v & 0xFF);
    buf[off+1] = static_cast<uint8_t>((v>>8) & 0xFF);
    buf[off+2] = static_cast<uint8_t>((v>>16) & 0xFF);
    buf[off+3] = static_cast<uint8_t>((v>>24) & 0xFF);
}
void RawrPE64Linker::patchU64(std::vector<uint8_t>& buf, size_t off, uint64_t v) const {
    if (off + 8 > buf.size()) return;
    for (int i = 0; i < 8; ++i) buf[off+i] = static_cast<uint8_t>((v >> (i*8)) & 0xFF);
}

RawrPE64Linker::IdatBuild RawrPE64Linker::buildIdat(uint32_t rvaBase) const {
    IdatBuild id;
    if (m_imports.empty()) return id;

    // Layout:
    // IMAGE_IMPORT_DESCRIPTOR[] (null terminated)
    // ILT (Import Lookup Table) 8-byte entries per func + 0 terminator per DLL
    // IAT (Import Address Table) 8-byte entries per func + 0 terminator per DLL (same layout initially)
    // Hint/Name table (2-byte hint + null-terminated name, aligned to 2)
    // DLL names

    size_t dirCount = m_imports.size();
    size_t dirSize = (dirCount + 1) * 20; // IMAGE_IMPORT_DESCRIPTOR = 20 bytes

    size_t iltOffset = dirSize;
    size_t iltSize = 0;
    size_t iatSize = 0;
    for (const auto& imp : m_imports) {
        iltSize += (imp.funcs.size() + 1) * 8;
        iatSize += (imp.funcs.size() + 1) * 8;
    }

    size_t iatOffset = iltOffset + iltSize;
    size_t hintNameOffset = iatOffset + iatSize;

    // Pre-calculate total size including variable-length hint/name entries and DLL names
    size_t totalSize = hintNameOffset;
    for (size_t d = 0; d < dirCount; ++d) {
        const auto& imp = m_imports[d];
        for (size_t f = 0; f < imp.funcs.size(); ++f) {
            size_t nameLen = 2 + imp.funcs[f].size() + 1;
            size_t pad = (nameLen % 2 == 0) ? 0 : 1;
            totalSize += nameLen + pad;
        }
        size_t dllNameLen = imp.dllName.size() + 1;
        size_t dllPad = (dllNameLen % 2 == 0) ? 0 : 1;
        totalSize += dllNameLen + dllPad;
    }
    std::vector<uint8_t> buf;
    buf.resize(totalSize, 0);

    // Write IMAGE_IMPORT_DESCRIPTOR array
    size_t nameRvaAccum = static_cast<size_t>(hintNameOffset);
    size_t iltCursor = iltOffset;
    size_t iatCursor = iatOffset;

    for (size_t d = 0; d < dirCount; ++d) {
        const auto& imp = m_imports[d];
        size_t dirOff = d * 20;
        // OriginalFirstThunk -> ILT RVA
        patchU32(buf, dirOff + 0, static_cast<uint32_t>(rvaBase + iltCursor));
        patchU32(buf, dirOff + 4, 0); // TimeDateStamp
        patchU32(buf, dirOff + 8, 0); // ForwarderChain
        // FirstThunk -> IAT RVA
        patchU32(buf, dirOff + 16, static_cast<uint32_t>(rvaBase + iatCursor));

        // Hint/Name entries for this DLL
        size_t funcNameBase = nameRvaAccum;
        for (size_t f = 0; f < imp.funcs.size(); ++f) {
            size_t entryRva = static_cast<size_t>(rvaBase + funcNameBase);
            // ILT entry (8 bytes, OR with IMAGE_ORDINAL_FLAG64 if by ordinal; here by name)
            patchU64(buf, iltCursor + f*8, entryRva);
            // IAT entry (same initially)
            patchU64(buf, iatCursor + f*8, entryRva);

            size_t hnaOff = funcNameBase;
            // 2-byte hint (0 = unknown)
            buf[hnaOff+0] = 0; buf[hnaOff+1] = 0;
            // name
            std::memcpy(buf.data() + hnaOff + 2, imp.funcs[f].data(), imp.funcs[f].size() + 1);
            size_t nameLen = 2 + imp.funcs[f].size() + 1;
            size_t pad = (nameLen % 2 == 0) ? 0 : 1;
            funcNameBase += nameLen + pad;
        }
        // ILT / IAT terminators (8-byte zero)
        // Already zero from resize; just advance cursor
        iltCursor += (imp.funcs.size() + 1) * 8;
        iatCursor += (imp.funcs.size() + 1) * 8;

        // DLL name
        size_t dllNameOff = funcNameBase;
        std::memcpy(buf.data() + dllNameOff, imp.dllName.data(), imp.dllName.size() + 1);
        size_t dllNameLen = imp.dllName.size() + 1;
        size_t dllPad = (dllNameLen % 2 == 0) ? 0 : 1;
        // Name RVA must point to the DLL name string, which comes after all function entries
        patchU32(buf, dirOff + 12, static_cast<uint32_t>(rvaBase + dllNameOff));
        nameRvaAccum = dllNameOff + dllNameLen + dllPad;
    }

    // Null terminator descriptor (already zero from resize)
    buf.resize(nameRvaAccum, 0);

    id.data = std::move(buf);
    id.dirRva = rvaBase;
    id.dirSize = static_cast<uint32_t>(dirSize);
    id.iatRva = static_cast<uint32_t>(rvaBase + iatOffset);
    id.iatSize = static_cast<uint32_t>(iatSize);
    return id;
}

std::vector<uint8_t> RawrPE64Linker::link() const {
    std::vector<uint8_t> out;
    const uint32_t fileAlignment = 0x200;
    const uint32_t sectionAlignment = 0x1000;
    auto alignFile = [fileAlignment](size_t x) { return (x + fileAlignment - 1) & ~(static_cast<size_t>(fileAlignment) - 1); };
    auto alignSection = [sectionAlignment](size_t x) { return (x + sectionAlignment - 1) & ~(static_cast<size_t>(sectionAlignment) - 1); };

    // Build import table if needed
    IdatBuild idat;
    uint32_t numSections = static_cast<uint32_t>(m_sections.size());
    bool hasImports = !m_imports.empty();
    if (hasImports) {
        // Compute where .idata will live in virtual address space
        uint32_t idatRva = static_cast<uint32_t>(sectionAlignment * (numSections + 1));
        idat = buildIdat(idatRva);
    }

    // Headers size
    size_t dosHeaderSize = 0x40;
    size_t peSigSize = 4;
    size_t coffHeaderSize = 24;
    size_t optHeaderSize = 240; // PE32+ optional header (standard fields + data directories)
    size_t sectionTableSize = (m_sections.size() + (hasImports ? 1 : 0)) * 40;
    size_t headersSize = dosHeaderSize + peSigSize + coffHeaderSize + optHeaderSize + sectionTableSize;
    size_t headersFileSize = alignFile(headersSize);

    // DOS Header
    out.resize(0x40, 0);
    out[0] = 'M'; out[1] = 'Z';
    // e_lfanew at offset 0x3C points to PE signature (immediately after DOS header)
    out[0x3C] = 0x40; out[0x3D] = 0x00; out[0x3E] = 0x00; out[0x3F] = 0x00;
    out.resize(0x40);
    // PE Signature
    append(out, "PE\0\0", 4);
    // COFF Header
    writeU16(out, 0x8664); // machine AMD64
    writeU16(out, static_cast<uint16_t>(m_sections.size() + (hasImports ? 1 : 0)));
    writeU32(out, 0); // time stamp
    writeU32(out, 0); // symbol table
    writeU32(out, 0); // number of symbols
    writeU16(out, static_cast<uint16_t>(optHeaderSize)); // size of optional header = 240 (data dirs are INSIDE opt header)
    writeU16(out, 0x22); // characteristics: executable, large address aware

    // Optional Header (PE32+)
    writeU16(out, 0x20b); // PE32+ magic
    out.push_back(14);    // major linker version (U8)
    out.push_back(0);     // minor linker version (U8)
    writeU32(out, 0);     // size of code
    uint32_t sizeOfInitData = 0;
    if (hasImports) sizeOfInitData = static_cast<uint32_t>(alignSection(idat.size()));
    writeU32(out, sizeOfInitData); // size of initialized data
    writeU32(out, 0);     // size of uninitialized data
    uint32_t entryRva = 0;
    if (m_entrySection < m_sections.size()) {
        entryRva = static_cast<uint32_t>(sectionAlignment + m_entrySection * sectionAlignment + m_entryOffset);
    }
    writeU32(out, entryRva); // entry point
    writeU32(out, static_cast<uint32_t>(sectionAlignment)); // base of code
    writeU64(out, m_imageBase);
    writeU32(out, sectionAlignment);
    writeU32(out, fileAlignment);
    writeU16(out, 6);   // major OS version
    writeU16(out, 0);   // minor OS version
    writeU16(out, 0);   // major image version
    writeU16(out, 0);   // minor image version
    writeU16(out, 5);   // major subsystem version
    writeU16(out, 0);   // minor subsystem version
    writeU32(out, 0);   // win32 version value
    uint32_t totalImageSize = sectionAlignment;
    if (!m_sections.empty()) {
        totalImageSize = static_cast<uint32_t>(sectionAlignment * (m_sections.size() + 1));
    }
    if (hasImports) {
        totalImageSize += static_cast<uint32_t>(alignSection(idat.size()));
    }
    writeU32(out, totalImageSize); // size of image
    writeU32(out, static_cast<uint32_t>(headersFileSize)); // size of headers
    writeU32(out, 0); // checksum
    writeU16(out, 2); // subsystem: WINDOWS_GUI (GUI)
    writeU16(out, 0x8160); // dll characteristics (high entropy ASLR, nx compat, dynamic base, guard)
    writeU64(out, 0x100000); // size of stack reserve
    writeU64(out, 0x10000);  // size of stack commit
    writeU64(out, 0x100000); // size of heap reserve
    writeU64(out, 0x10000);  // size of heap commit
    writeU32(out, 0); // loader flags
    writeU32(out, 16); // number of RVA and sizes

    // Data directories (all zeroed initially)
    size_t dataDirOffset = out.size();
    for (int i = 0; i < 16; ++i) { writeU32(out, 0); writeU32(out, 0); }

    // Section table
    size_t rawDataPtr = headersFileSize;
    size_t virtualAddr = sectionAlignment;
    for (size_t i = 0; i < m_sections.size(); ++i) {
        const auto& sec = m_sections[i];
        char name[8] = {};
        std::memcpy(name, sec.name.c_str(), std::min(sec.name.size(), size_t(8)));
        append(out, name, 8);
        writeU32(out, sec.virtualSize);
        writeU32(out, static_cast<uint32_t>(virtualAddr));
        writeU32(out, static_cast<uint32_t>(alignFile(sec.data.size())));
        writeU32(out, static_cast<uint32_t>(rawDataPtr));
        writeU32(out, 0); // reloc ptr
        writeU32(out, 0); // line numbers ptr
        writeU16(out, 0); // reloc count
        writeU16(out, 0); // line number count
        writeU32(out, sec.characteristics);
        rawDataPtr += alignFile(sec.data.size());
        virtualAddr += sectionAlignment;
    }
    // .idata section header
    if (hasImports) {
        char iname[8] = {'.','i','d','a','t','a',0,0};
        append(out, iname, 8);
        writeU32(out, idat.size());
        writeU32(out, static_cast<uint32_t>(virtualAddr));
        writeU32(out, static_cast<uint32_t>(alignFile(idat.size())));
        writeU32(out, static_cast<uint32_t>(rawDataPtr));
        writeU32(out, 0);
        writeU32(out, 0);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU32(out, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
    }
    out.resize(headersFileSize, 0);

    // Section raw data
    for (size_t i = 0; i < m_sections.size(); ++i) {
        const auto& sec = m_sections[i];
        if (!sec.data.empty()) {
            append(out, sec.data.data(), sec.data.size());
        }
        size_t pad = alignFile(out.size()) - out.size();
        out.resize(out.size() + pad, 0);
    }
    if (hasImports) {
        append(out, idat.data.data(), idat.data.size());
        size_t pad = alignFile(out.size()) - out.size();
        out.resize(out.size() + pad, 0);

        // Patch import data directory (index 1)
        patchU32(out, dataDirOffset + 1*8 + 0, idat.dirRva);
        patchU32(out, dataDirOffset + 1*8 + 4, idat.dirSize);
        // Patch IAT data directory (index 12)
        patchU32(out, dataDirOffset + 12*8 + 0, idat.iatRva);
        patchU32(out, dataDirOffset + 12*8 + 4, idat.iatSize);
    }

    // Base relocations (.reloc) if needed
    if (!m_relocs.empty()) {
        // Simplified: skip for now since we can produce position-independent code
    }

    return out;
}

} // namespace Backend
} // namespace RawrXD
