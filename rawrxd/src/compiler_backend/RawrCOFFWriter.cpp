#include "RawrCOFFWriter.hpp"
#include <string>

namespace RawrXD {
namespace Backend {

uint32_t RawrCOFFWriter::addSymbol(const std::string& name, int16_t section, uint32_t value, uint8_t storageClass) {
    CoffSymbol sym{};
    if (name.size() <= 8) {
        std::memcpy(sym.name.shortName, name.data(), name.size());
    } else {
        sym.name.longName.zeros = 0;
        sym.name.longName.offset = static_cast<uint32_t>(m_stringTable.size() + 4);
        size_t oldSize = m_stringTable.size();
        m_stringTable.resize(oldSize + name.size() + 1);
        std::memcpy(m_stringTable.data() + oldSize, name.data(), name.size() + 1);
    }
    sym.sectionNumber = section;
    sym.value = value;
    sym.storageClass = storageClass;
    m_symbols.push_back(sym);
    return static_cast<uint32_t>(m_symbols.size()) - 1;
}

uint32_t RawrCOFFWriter::addSection(const std::string& name, uint32_t characteristics) {
    Section sec{};
    sec.name = name;
    sec.characteristics = characteristics;
    m_sections.push_back(std::move(sec));
    return static_cast<uint32_t>(m_sections.size()) - 1;
}

uint8_t* RawrCOFFWriter::sectionDataPtr(uint32_t sectionIndex) {
    if (sectionIndex >= m_sections.size()) return nullptr;
    return m_sections[sectionIndex].data.data();
}

size_t RawrCOFFWriter::sectionSize(uint32_t sectionIndex) const {
    if (sectionIndex >= m_sections.size()) return 0;
    return m_sections[sectionIndex].data.size();
}

void RawrCOFFWriter::appendSectionData(uint32_t sectionIndex, const uint8_t* data, size_t len) {
    if (sectionIndex >= m_sections.size()) return;
    auto& sec = m_sections[sectionIndex];
    sec.data.insert(sec.data.end(), data, data + len);
}

void RawrCOFFWriter::addRelocation(uint32_t sectionIndex, uint32_t offset, uint32_t symbolIndex, uint16_t type) {
    if (sectionIndex >= m_sections.size()) return;
    CoffRelocation r{};
    r.virtualAddress = offset;
    r.symbolTableIndex = symbolIndex;
    r.type = type;
    m_sections[sectionIndex].relocs.push_back(r);
}

std::vector<uint8_t> RawrCOFFWriter::serialize() const {
    std::vector<uint8_t> out;
    auto append = [&](const void* ptr, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(ptr);
        out.insert(out.end(), p, p + len);
    };

    CoffFileHeader header = m_header;
    header.numberOfSections = static_cast<uint16_t>(m_sections.size());
    header.numberOfSymbols = static_cast<uint32_t>(m_symbols.size());
    header.pointerToSymbolTable = 0; // will patch

    size_t headerOff = out.size();
    append(&header, sizeof(header));

    std::vector<CoffSectionHeader> secHeaders;
    secHeaders.reserve(m_sections.size());
    size_t rawDataOffset = sizeof(header) + m_sections.size() * sizeof(CoffSectionHeader);
    // Align raw data to 512 bytes for simplicity (or 16)
    auto align = [](size_t off, size_t a) { return (off + a - 1) & ~(a - 1); };
    rawDataOffset = align(rawDataOffset, 16);

    for (const auto& sec : m_sections) {
        CoffSectionHeader sh{};
        std::memcpy(sh.name, sec.name.c_str(), std::min(sec.name.size(), size_t(8)));
        sh.sizeOfRawData = static_cast<uint32_t>(sec.data.size());
        sh.pointerToRawData = static_cast<uint32_t>(rawDataOffset);
        sh.pointerToRelocations = 0;
        sh.numberOfRelocations = static_cast<uint16_t>(sec.relocs.size());
        sh.characteristics = sec.characteristics;
        secHeaders.push_back(sh);
        rawDataOffset = align(rawDataOffset + sec.data.size(), 16);
    }

    // Append section headers
    for (const auto& sh : secHeaders) append(&sh, sizeof(sh));
    size_t current = align(out.size(), 16);
    out.resize(current);

    // Patch section header offsets for raw data and relocs
    for (size_t i = 0; i < m_sections.size(); ++i) {
        size_t secHeaderOff = headerOff + sizeof(CoffFileHeader) + i * sizeof(CoffSectionHeader);
        // pointerToRawData already set above
        // Write raw data
        const auto& sec = m_sections[i];
        if (!sec.data.empty()) {
            size_t off = out.size();
            out.resize(off + sec.data.size());
            std::memcpy(out.data() + off, sec.data.data(), sec.data.size());
        }
        current = align(out.size(), 16);
        out.resize(current);
    }

    // Relocations
    for (size_t i = 0; i < m_sections.size(); ++i) {
        auto& sec = m_sections[i];
        if (!sec.relocs.empty()) {
            size_t secHeaderOff = headerOff + sizeof(CoffFileHeader) + i * sizeof(CoffSectionHeader);
            uint32_t relOff = static_cast<uint32_t>(out.size());
            // Patch relocation pointer in section header
            std::memcpy(out.data() + secHeaderOff + offsetof(CoffSectionHeader, pointerToRelocations), &relOff, sizeof(uint32_t));
            for (const auto& r : sec.relocs) append(&r, sizeof(r));
        }
    }

    current = align(out.size(), 16);
    out.resize(current);

    // Symbol table
    uint32_t symTableOff = static_cast<uint32_t>(out.size());
    for (const auto& sym : m_symbols) append(&sym, sizeof(sym));

    // String table
    uint32_t strTableSize = static_cast<uint32_t>(m_stringTable.size() + 4);
    append(&strTableSize, sizeof(uint32_t));
    if (!m_stringTable.empty()) append(m_stringTable.data(), m_stringTable.size());

    // Patch header
    std::memcpy(out.data() + offsetof(CoffFileHeader, pointerToSymbolTable), &symTableOff, sizeof(uint32_t));
    std::memcpy(out.data() + offsetof(CoffFileHeader, numberOfSymbols), &header.numberOfSymbols, sizeof(uint32_t));

    return out;
}

} // namespace Backend
} // namespace RawrXD
