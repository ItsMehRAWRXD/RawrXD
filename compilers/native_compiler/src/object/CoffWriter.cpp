#include "object/CoffWriter.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;
using rawrstd::Vector;

// ---------------------------------------------------------------------------
// Symbol constructors
// ---------------------------------------------------------------------------

CoffSymbol CoffSymbol::external(const char* name, int16 section, uint32 value,
                                bool is_function) {
    CoffSymbol s;
    s.name = name;
    s.section = section;
    s.value = value;
    s.storage_class = kSymClassExternal;
    s.type = is_function ? 0x20 : 0;
    return s;
}

CoffSymbol CoffSymbol::internal(const char* name, int16 section, uint32 value,
                                bool is_function) {
    CoffSymbol s;
    s.name = name;
    s.section = section;
    s.value = value;
    s.storage_class = kSymClassStatic;
    s.type = is_function ? 0x20 : 0;
    return s;
}

CoffSymbol CoffSymbol::file(const char* name) {
    CoffSymbol s;
    s.name = name;
    s.section = -2;
    s.storage_class = kSymClassFile;
    return s;
}

CoffSymbol CoffSymbol::section_symbol(const char* name, int16 section) {
    CoffSymbol s;
    s.name = name;
    s.section = section;
    s.storage_class = kSymClassStatic;
    return s;
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

CoffWriter::CoffWriter() {
    // Every object starts with a file symbol, which is what the linker
    // expects as symbol index 0.
    add_symbol(CoffSymbol::file("rawr.obj"));
}

int CoffWriter::add_section(const char* name, uint32 characteristics, uint32 alignment) {
    CoffSection s;
    s.name = name;
    s.characteristics = characteristics;
    s.alignment = alignment ? alignment : 1;
    sections_.push_back(static_cast<CoffSection&&>(s));
    return static_cast<int>(sections_.size());
}

void CoffWriter::append_data(int section, const void* data, size_type size) {
    if (section < 1 || section > static_cast<int>(sections_.size())) return;
    const uint8* p = static_cast<const uint8*>(data);
    for (size_type i = 0; i < size; ++i) {
        sections_[section - 1].data.push_back(p[i]);
    }
}

void CoffWriter::append_data(int section, const char* text) {
    if (!text) return;
    append_data(section, text, rawrstd::strlen_raw(text));
}

void CoffWriter::add_relocation(int section, uint32 offset, uint32 symbol_index,
                                CoffReloc type) {
    if (section < 1 || section > static_cast<int>(sections_.size())) return;
    CoffRelocation r;
    r.offset = offset;
    r.symbol_index = symbol_index;
    r.type = type;
    sections_[section - 1].relocations.push_back(r);
}

int CoffWriter::add_symbol(const CoffSymbol& symbol) {
    symbols_.push_back(symbol);
    return static_cast<int>(symbols_.size()) - 1;
}

int CoffWriter::find_symbol(const char* name) const {
    if (!name) return -1;
    for (size_type i = 0; i < symbols_.size(); ++i) {
        if (symbols_[i].name == name) return static_cast<int>(i);
    }
    return -1;
}

void CoffWriter::add_directive(const char* directive) {
    if (!directive) return;
    if (!directives_.empty()) directives_.push_back(' ');
    directives_.append(directive);
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

namespace {

void put8(Vector<uint8>& out, uint8 v) { out.push_back(v); }

void put16(Vector<uint8>& out, uint16 v) {
    out.push_back(static_cast<uint8>(v));
    out.push_back(static_cast<uint8>(v >> 8));
}

void put32(Vector<uint8>& out, uint32 v) {
    out.push_back(static_cast<uint8>(v));
    out.push_back(static_cast<uint8>(v >> 8));
    out.push_back(static_cast<uint8>(v >> 16));
    out.push_back(static_cast<uint8>(v >> 24));
}

void put_bytes(Vector<uint8>& out, const void* data, size_type size) {
    const uint8* p = static_cast<const uint8*>(data);
    for (size_type i = 0; i < size; ++i) out.push_back(p[i]);
}

} // namespace

Vector<uint8> CoffWriter::serialize() const {
    // ---- Build the string table ----
    //
    // The first DWORD is the table size, including those four bytes.
    // Names of eight characters or fewer are stored inline.
    Vector<uint8> strtab;
    put32(strtab, 0);
    Vector<uint32> strtab_offsets(symbols_.size(), 0);

    for (size_type i = 0; i < symbols_.size(); ++i) {
        const String& name = symbols_[i].name;
        if (name.size() <= 8) continue;
        strtab_offsets[i] = static_cast<uint32>(strtab.size());
        put_bytes(strtab, name.data(), name.size());
        put8(strtab, 0);
    }
    // Patch the size now that the table is complete.
    {
        uint32 size = static_cast<uint32>(strtab.size());
        strtab[0] = static_cast<uint8>(size);
        strtab[1] = static_cast<uint8>(size >> 8);
        strtab[2] = static_cast<uint8>(size >> 16);
        strtab[3] = static_cast<uint8>(size >> 24);
    }

    // ---- Compute the file layout ----
    //
    // The .drectve section, when present, is emitted as the LAST section
    // so that the section indices in the file match the indices returned
    // by add_section(). A symbol that names a section index therefore
    // always refers to the section the caller created.
    uint32 num_sections = static_cast<uint32>(sections_.size());
    bool has_directives = !directives_.empty();
    uint32 total_sections = num_sections + (has_directives ? 1 : 0);

    uint32 header_size = 20 + total_sections * 40;

    Vector<uint32> section_offsets(total_sections, 0);
    Vector<uint32> reloc_offsets(total_sections, 0);

    uint32 offset = header_size;
    for (uint32 i = 0; i < total_sections; ++i) {
        section_offsets[i] = offset;
        uint32 size = (has_directives && i == total_sections - 1)
                          ? static_cast<uint32>(directives_.size())
                          : static_cast<uint32>(sections_[i].data.size());
        offset += (size + 1) & ~1u;   // align to 2 bytes
    }

    for (uint32 i = 0; i < total_sections; ++i) {
        reloc_offsets[i] = offset;
        if (has_directives && i == total_sections - 1) { offset += 0; continue; }
        offset += static_cast<uint32>(sections_[i].relocations.size()) * 10;
    }

    uint32 symtab_offset = offset;
    offset += static_cast<uint32>(symbols_.size()) * 18;
    uint32 strtab_offset = offset;
    offset += static_cast<uint32>(strtab.size());

    // ---- Build the file ----
    Vector<uint8> out;
    out.reserve(offset);

    // COFF file header.
    put16(out, kCoffMachineAmd64);
    put16(out, static_cast<uint16>(total_sections));
    put32(out, timestamp_);
    put32(out, symtab_offset);
    put32(out, static_cast<uint32>(symbols_.size()));
    put16(out, 0);   // no optional header
    put16(out, 0);   // characteristics

    // Section headers.
    for (uint32 i = 0; i < total_sections; ++i) {
        String name;
        uint32 characteristics = 0;
        uint32 alignment = 1;
        uint32 size = 0;
        uint32 reloc_count = 0;

        if (has_directives && i == total_sections - 1) {
            name = ".drectve";
            characteristics = kScnCntInitialized | kScnMemRead | kScnMemDiscardable;
            alignment = 1;
            size = static_cast<uint32>(directives_.size());
        } else {
            name = sections_[i].name;
            characteristics = sections_[i].characteristics;
            alignment = sections_[i].alignment;
            size = static_cast<uint32>(sections_[i].data.size());
            reloc_count = static_cast<uint32>(sections_[i].relocations.size());
        }

        // The alignment is encoded in the characteristics field.
        uint32 encoded_alignment = 0;
        if (alignment > 1) {
            uint32 shift = 0;
            uint32 v = alignment;
            while (v > 1) { v >>= 1; ++shift; }
            encoded_alignment = (shift + 1) << kScnAlignShift;
        }

        // The name field is NUL padded, not space padded.
        char name_buf[8];
        for (int k = 0; k < 8; ++k) name_buf[k] = 0;
        for (size_type k = 0; k < name.size() && k < 8; ++k) name_buf[k] = name[k];
        put_bytes(out, name_buf, 8);

        put32(out, 0);                      // virtual size
        put32(out, 0);                      // virtual address
        put32(out, size);                   // raw size
        put32(out, section_offsets[i]);     // raw offset
        put32(out, reloc_count ? reloc_offsets[i] : 0);  // pointer to relocations
        put32(out, 0);                      // pointer to line numbers (DWORD)
        put16(out, static_cast<uint16>(reloc_count));     // number of relocations
        put16(out, 0);                      // number of line numbers
        put32(out, (characteristics & ~kScnAlignMask) | encoded_alignment);
    }

    // Section data.
    for (uint32 i = 0; i < total_sections; ++i) {
        if (has_directives && i == total_sections - 1) {
            put_bytes(out, directives_.data(), directives_.size());
            if (directives_.size() & 1) put8(out, 0);
            continue;
        }
        const Vector<uint8>& data = sections_[i].data;
        if (!data.empty()) put_bytes(out, data.data(), data.size());
        if (data.size() & 1) put8(out, 0);
    }

    // Relocation tables.
    for (uint32 i = 0; i < total_sections; ++i) {
        if (has_directives && i == total_sections - 1) continue;
        const Vector<CoffRelocation>& relocs = sections_[i].relocations;
        for (size_type r = 0; r < relocs.size(); ++r) {
            put32(out, relocs[r].offset);
            put32(out, relocs[r].symbol_index);
            put16(out, static_cast<uint16>(relocs[r].type));
        }
    }

    // Symbol table.
    for (size_type i = 0; i < symbols_.size(); ++i) {
        const CoffSymbol& sym = symbols_[i];
        if (sym.name.size() <= 8) {
            char name_buf[8];
            for (int k = 0; k < 8; ++k) name_buf[k] = 0;
            for (size_type k = 0; k < sym.name.size() && k < 8; ++k) {
                name_buf[k] = sym.name[k];
            }
            put_bytes(out, name_buf, 8);
        } else {
            // Long names use the zeroes-plus-offset encoding.
            put32(out, 0);
            put32(out, strtab_offsets[i]);
        }
        put32(out, sym.value);
        put16(out, static_cast<uint16>(sym.section));
        put16(out, sym.type);
        put8(out, sym.storage_class);
        put8(out, 0);   // auxiliary symbol count
    }

    // String table.
    put_bytes(out, strtab.data(), strtab.size());

    return out;
}

bool CoffWriter::write(const char* path) const {
    Vector<uint8> bytes = serialize();
    rawrstd::File f;
    if (!f.open(path, rawrstd::FileMode::Write)) return false;
    int64 written = f.write(bytes.data(), bytes.size());
    f.close();
    return written == static_cast<int64>(bytes.size());
}

} // namespace rawr
