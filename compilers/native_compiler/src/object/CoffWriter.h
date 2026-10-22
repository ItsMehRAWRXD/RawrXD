// COFF object file writer for the RawrXD native compiler.
//
// Emits x86-64 COFF objects that the RawrXD native linker consumes
// directly. The format is the Microsoft COFF specification:
//
//   [COFF File Header (20 bytes)]
//   [Section Headers (40 bytes each)]
//   [Section Data]
//   [Relocation Tables (10 bytes each)]
//   [Symbol Table (18 bytes each)]
//   [String Table]
//
// Symbol names longer than eight characters live in the string table and
// are referenced through the zeroes-plus-offset encoding.

#ifndef RAWR_COMPILER_COFF_WRITER_H
#define RAWR_COMPILER_COFF_WRITER_H

#include "common/Types.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawr {

// ---- COFF machine types ----
constexpr uint16 kCoffMachineAmd64 = 0x8664;
constexpr uint16 kCoffMachineI386  = 0x014C;

// ---- Section characteristics (IMAGE_SCN_*) ----
constexpr uint32 kScnCntCode           = 0x00000020;
constexpr uint32 kScnCntInitialized    = 0x00000040;
constexpr uint32 kScnCntUninitialized  = 0x00000080;
constexpr uint32 kScnLnkComdat         = 0x00001000;
constexpr uint32 kScnMemDiscardable    = 0x02000000;
constexpr uint32 kScnMemExecute        = 0x20000000;
constexpr uint32 kScnMemRead           = 0x40000000;
constexpr uint32 kScnMemWrite          = 0x80000000;

// Alignment encoding: bits 20-23 hold 2^(N-1).
constexpr uint32 kScnAlignMask  = 0x00F00000;
constexpr uint32 kScnAlignShift = 20;

// ---- Symbol storage classes ----
constexpr uint8 kSymClassExternal = 2;
constexpr uint8 kSymClassStatic   = 3;
constexpr uint8 kSymClassFunction = 101;
constexpr uint8 kSymClassFile     = 103;
constexpr uint8 kSymClassSection  = 104;

// ---- x64 relocation types (IMAGE_REL_AMD64_*) ----
enum class CoffReloc : uint16 {
    Absolute  = 0x0000,
    Addr64    = 0x0001,
    Addr32    = 0x0002,
    Addr32Nb  = 0x0003,
    Rel32     = 0x0004,
    Rel32_1   = 0x0005,
    Rel32_2   = 0x0006,
    Rel32_3   = 0x0007,
    Rel32_4   = 0x0008,
    Rel32_5   = 0x0009,
    Section   = 0x000A,
    SecRel    = 0x000B,
    SecRel7   = 0x000C,
};

// A symbol in the object file.
struct CoffSymbol {
    String name;
    uint32 value = 0;
    int16 section = 0;        // 1-based; 0 = undefined; -1 = absolute; -2 = debug
    uint16 type = 0;          // 0x20 = function
    uint8 storage_class = kSymClassStatic;

    // Convenience constructors.
    static CoffSymbol external(const char* name, int16 section = 0, uint32 value = 0,
                               bool is_function = false);
    static CoffSymbol internal(const char* name, int16 section, uint32 value = 0,
                               bool is_function = false);
    static CoffSymbol file(const char* name);
    static CoffSymbol section_symbol(const char* name, int16 section);
};

// A relocation entry.
struct CoffRelocation {
    uint32 offset = 0;        // offset within the section's data
    uint32 symbol_index = 0;  // index into the symbol table
    CoffReloc type = CoffReloc::Rel32;
};

// A section in the object file.
struct CoffSection {
    String name;
    uint32 characteristics = 0;
    uint32 alignment = 1;
    rawrstd::Vector<uint8> data;
    rawrstd::Vector<CoffRelocation> relocations;
    // The .drectve payload is emitted as a special section.
    String directives;
};

class CoffWriter {
public:
    CoffWriter();

    // Adds a section and returns its 1-based index.
    int add_section(const char* name, uint32 characteristics, uint32 alignment = 1);

    // Appends bytes to a section.
    void append_data(int section, const void* data, size_type size);
    void append_data(int section, const char* text);

    // Appends a relocation to a section.
    void add_relocation(int section, uint32 offset, uint32 symbol_index, CoffReloc type);

    // Adds a symbol and returns its index.
    int add_symbol(const CoffSymbol& symbol);

    // Adds a linker directive, e.g. "/DEFAULTLIB:kernel32.lib".
    void add_directive(const char* directive);

    // Number of symbols currently in the table.
    uint32 symbol_count() const { return static_cast<uint32>(symbols_.size()); }

    // Looks up a symbol by name; returns the index or -1.
    int find_symbol(const char* name) const;

    // Serializes the object.
    rawrstd::Vector<uint8> serialize() const;

    // Writes the object to a file. Returns false on failure.
    bool write(const char* path) const;

private:
    rawrstd::Vector<CoffSection> sections_;
    rawrstd::Vector<CoffSymbol> symbols_;
    String directives_;
    uint32 timestamp_ = 0;
};

} // namespace rawr

#endif // RAWR_COMPILER_COFF_WRITER_H
