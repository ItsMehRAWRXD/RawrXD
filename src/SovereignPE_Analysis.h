// =============================================================================
// SovereignPE_Analysis.h
// Self-Hosted PE Analysis Engine for RawrXD IDE
// Extracted from: CODEX v7.0, Omega-Polyglot v3.0, DumpBin Proper v6.0
// Ported to: Zero-dependency C/C++ compatible with self-hosted compiler
//
// Your IDE already has: parser, lexer, machine code emitter, linker, PE emitter.
// This module adds: PE analysis, entropy calculation, string extraction,
// import/export enumeration, section analysis, packer detection.
//
// All algorithms are standalone. No external libs. No ml64/ml.exe deps.
// =============================================================================

#pragma once
#include <windows.h>  // Only for HANDLE/FILETIME types - replace with your own if needed

// =============================================================================
// PE Format Constants (self-documenting for your parser)
// =============================================================================
constexpr uint16_t PE_DOS_MAGIC     = 0x5A4D;       // "MZ"
constexpr uint32_t PE_NT_MAGIC      = 0x00004550;   // "PE\\0\\0"
constexpr uint16_t PE_OPT_MAGIC32   = 0x010B;       // PE32
constexpr uint16_t PE_OPT_MAGIC64   = 0x020B;       // PE32+ (x64)

// Characteristics flags
constexpr uint16_t PE_CHAR_RELOCS_STRIPPED   = 0x0001;
constexpr uint16_t PE_CHAR_EXECUTABLE_IMAGE  = 0x0002;
constexpr uint16_t PE_CHAR_LARGE_ADDRESS_AWARE = 0x0020;
constexpr uint16_t PE_CHAR_32BIT_MACHINE     = 0x0100;
constexpr uint16_t PE_CHAR_DLL               = 0x2000;

// Section characteristics
constexpr uint32_t SEC_CHAR_CODE      = 0x00000020;
constexpr uint32_t SEC_CHAR_DATA      = 0x00000040;
constexpr uint32_t SEC_CHAR_BSS       = 0x00000080;
constexpr uint32_t SEC_CHAR_EXEC      = 0x20000000;
constexpr uint32_t SEC_CHAR_READ      = 0x40000000;
constexpr uint32_t SEC_CHAR_WRITE     = 0x80000000;

// Directory entries
enum class PE_Directory : uint32_t {
    Export        = 0,
    Import        = 1,
    Resource      = 2,
    Exception     = 3,
    Security      = 4,
    Relocation    = 5,
    Debug         = 6,
    Architecture  = 7,
    GlobalPtr     = 8,
    TLS           = 9,
    LoadConfig    = 10,
    BoundImport   = 11,
    IAT           = 12,
    DelayImport   = 13,
    CLR           = 14,
    Count         = 15
};

// =============================================================================
// PE Data Structures (raw layout - your parser reads these from file)
// =============================================================================

// DOS Header (64 bytes)
struct PE_DOS_Header {
    uint16_t e_magic;       // MZ
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
    uint32_t e_lfanew;      // Offset to PE header (critical!)
};

// COFF File Header (20 bytes)
struct PE_COFF_Header {
    uint16_t Machine;           // 0x8664 = AMD64, 0x014C = x86, 0xAA64 = ARM64
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;     // Unix timestamp - compiler detection
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

// Data Directory (8 bytes each)
struct PE_Data_Directory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

// Optional Header (x64 = 240 bytes, x86 = 224 bytes)
struct PE_Optional_Header64 {
    uint16_t Magic;             // 0x020B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;   // EP = ImageBase + this
    uint32_t BaseOfCode;
    uint64_t ImageBase;             // 64-bit! x86 has 32-bit ImageBase
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOSVersion;
    uint16_t MinorOSVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;             // 1=NATIVE, 2=WINDOWS_GUI, 3=WINDOWS_CUI, 5=OS2_CUI, 7=POSIX_CUI
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;   // Should be 16
    PE_Data_Directory DataDirectory[16];
};

// Section Header (40 bytes each)
struct PE_Section_Header {
    char     Name[8];           // Not null-terminated! Check for '/' = long name
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

// Import Directory Entry (20 bytes)
struct PE_Import_Directory {
    uint32_t ImportLookupTableRVA;   // ILT / INT (Import Name Table)
    uint32_t TimeDateStamp;          // 0 = not bound, -1 = bound, other = bound timestamp
    uint32_t ForwarderChain;
    uint32_t NameRVA;                // DLL name string
    uint32_t ImportAddressTableRVA;  // IAT (thunks patched by loader)
};

// Export Directory (40 bytes)
struct PE_Export_Directory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t NameRVA;                // Module name
    uint32_t OrdinalBase;
    uint32_t AddressTableEntries;    // NumberOfFunctions
    uint32_t NumberOfNamePointers;   // NumberOfNames
    uint32_t ExportAddressTableRVA;  // EAT
    uint32_t NamePointerRVA;         // Names array
    uint32_t OrdinalTableRVA;        // Ordinals array
};

// Rich Header (undocumented, between DOS stub and PE header)
// Format: "DanS" XOR key, then (comp_id << 16 | count) XOR key pairs
struct PE_Rich_Entry {
    uint16_t comp_id;       // Compiler tool ID (e.g., 0x00FC = VS 2022 17.4)
    uint16_t count;         // Number of objects built with this tool
};

// =============================================================================
// Parsed PE Document (your IDE's internal representation)
// =============================================================================
struct PE_Analysis {
    // Raw headers
    PE_DOS_Header       dos;
    PE_COFF_Header      coff;
    PE_Optional_Header64 opt64;     // Union with opt32 if needed
    
    // Sections
    uint32_t            num_sections;
    PE_Section_Header*  sections;
    
    // Analysis results
    bool                is_64bit;
    bool                is_dll;
    bool                is_packed;
    float               total_entropy;
    float*              section_entropy;  // Per-section
    
    // Imports
    struct Import_DLL {
        char        dll_name[64];
        struct Import_Symbol {
            char    name[128];
            uint16_t ordinal;
            bool    by_ordinal;
            uint32_t rva;       // IAT slot
        }* symbols;
        uint32_t    num_symbols;
    }* imports;
    uint32_t num_imports;
    
    // Exports
    struct Export_Symbol {
        char        name[128];
        uint32_t    rva;
        uint16_t    ordinal;
        bool        forwarded;
        char        forwarder[128];  // "DLL.Name"
    }* exports;
    uint32_t num_exports;
    
    // Strings
    struct Extracted_String {
        char        text[256];
        uint32_t    file_offset;
        bool        is_unicode;
        uint32_t    length;
    }* strings;
    uint32_t num_strings;
    uint32_t string_capacity;
    
    // Rich header
    PE_Rich_Entry* rich_entries;
    uint32_t num_rich_entries;
    char rich_xor_key_hex[16];
    
    // Security / Certificates
    bool has_signature;
    uint32_t cert_directory_rva;
    uint32_t cert_directory_size;
    
    // Resources
    uint32_t resource_rva;
    uint32_t resource_size;
    
    // File mapping
    const uint8_t* file_base;
    uint64_t file_size;
    
    // Memory (allocated by your allocator)
    void* allocator_context;
};

// =============================================================================
// Self-Hosted API (no external dependencies)
// =============================================================================
extern "C" {

// --- Core PE Parsing ---
PE_Analysis* PE_Open(const uint8_t* file_data, uint64_t file_size, void* alloc_ctx);
void         PE_Close(PE_Analysis* pe);

// --- Header Queries ---
const char*  PE_GetMachineName(uint16_t machine);
const char*  PE_GetSubsystemName(uint16_t subsystem);
const char*  PE_GetSectionFlagsString(uint32_t flags, char* buf, size_t buf_size);
uint64_t     PE_GetImageBase(PE_Analysis* pe);
uint32_t     PE_GetEntryPoint(PE_Analysis* pe);

// --- Section Analysis ---
PE_Section_Header* PE_GetSectionByName(PE_Analysis* pe, const char* name);
PE_Section_Header* PE_GetSectionByRVA(PE_Analysis* pe, uint32_t rva);
uint32_t           PE_RVAToFileOffset(PE_Analysis* pe, uint32_t rva);

// --- Entropy (Shannon) ---
float PE_CalcEntropy(const uint8_t* data, uint32_t len);
float PE_CalcSectionEntropy(PE_Analysis* pe, uint32_t section_idx);
bool  PE_IsPackedHeuristic(PE_Analysis* pe);  // entropy + section names + imports

// --- String Extraction ---
uint32_t PE_ExtractStrings(PE_Analysis* pe, uint32_t min_length, bool include_unicode);

// --- Import/Export Enumeration ---
uint32_t PE_EnumerateImports(PE_Analysis* pe);
uint32_t PE_EnumerateExports(PE_Analysis* pe);

// --- Rich Header ---
bool PE_ParseRichHeader(PE_Analysis* pe);
const char* PE_GetCompilerFromRichId(uint16_t comp_id);

// --- Certificate / Security ---
bool PE_HasDigitalSignature(PE_Analysis* pe);
bool PE_VerifySignature(PE_Analysis* pe);  // Windows CryptoAPI or your own

// --- AI Integration ---
// Returns a JSON-like string describing the binary for AI analysis
void PE_GenerateAIContext(PE_Analysis* pe, char* out_buf, size_t out_size);

} // extern "C"
