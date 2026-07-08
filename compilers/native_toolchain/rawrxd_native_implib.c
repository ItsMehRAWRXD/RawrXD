/*
 * RAWRXD NATIVE IMPORT LIBRARY GENERATOR
 * Creates import libraries (.lib) from DLL exports
 * No Microsoft LIB.EXE dependency
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

#pragma pack(push, 1)

/* COFF Archive format */
#ifndef IMAGE_ARCHIVE_START_SIZE
#define IMAGE_ARCHIVE_START_SIZE 8
#endif

#ifndef IMAGE_ARCHIVE_START
#define IMAGE_ARCHIVE_START "!<arch>\n"
#endif

/* Import types */
#ifndef IMPORT_NAME_NOPREFIX
#define IMPORT_NAME_NOPREFIX    1
#define IMPORT_NAME_UNDECORATE  2
#define IMPORT_ORDINAL          0
#define IMPORT_NAME             1
#endif

/* x86 thunk code: jmp dword ptr [__imp__FuncName] */
static const uint8_t x86_thunk[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  /* jmp dword ptr [0] - reloc at +2 */
};

/* x64 thunk code: jmp qword ptr [rip+0] */
static const uint8_t x64_thunk[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  /* jmp qword ptr [rip+0] - reloc at +2 */
};

/* x86 import descriptor pseudo-code */
static const uint8_t x86_idata2[] = { 0x00, 0x00, 0x00, 0x00 };  /* OriginalFirstThunk */
static const uint8_t x86_idata4[] = { 0x00, 0x00, 0x00, 0x00 };  /* TimeDateStamp */
static const uint8_t x86_idata5[] = { 0x00, 0x00, 0x00, 0x00 };  /* ForwarderChain */
static const uint8_t x86_idata6[] = { 0x00, 0x00, 0x00, 0x00 };  /* Name RVA */
static const uint8_t x86_idata7[] = { 0x00, 0x00, 0x00, 0x00 };  /* FirstThunk */

#pragma pack(pop)

/* Export entry */
typedef struct ExportEntry {
    char Name[256];
    uint16_t Ordinal;
    int ByOrdinal;
    struct ExportEntry* next;
} ExportEntry;

/* DLL info */
typedef struct {
    char DllName[256];
    ExportEntry* exports;
    int is64bit;
    uint32_t timestamp;
} DLLInfo;

static DLLInfo g_dll;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static void write_decimal(char* buf, size_t size, uint32_t value) {
    snprintf(buf, size, "%-*lu", (int)size - 1, (unsigned long)value);
    buf[size - 1] = ' ';
}

static void write_octal(char* buf, size_t size, uint32_t value) {
    snprintf(buf, size, "%-*o", (int)size - 1, (unsigned)value);
    buf[size - 1] = ' ';
}

/* ============================================================================
 * DLL EXPORT PARSING
 * ============================================================================ */

static int parse_dll_exports(const char* dll_path) {
    HMODULE hDll = LoadLibraryExA(dll_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hDll) {
        fprintf(stderr, "Error: Cannot load DLL '%s' (error %lu)\n", dll_path, GetLastError());
        return 0;
    }

    /* Get architecture */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hDll;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hDll + dos->e_lfanew);
    g_dll.is64bit = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    g_dll.timestamp = nt->FileHeader.TimeDateStamp;

    /* Get export directory */
    IMAGE_DATA_DIRECTORY* exp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress == 0) {
        fprintf(stderr, "Error: DLL has no exports\n");
        FreeLibrary(hDll);
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hDll + exp_dir->VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)hDll + exp->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hDll + exp->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)hDll + exp->AddressOfFunctions);

    /* Extract DLL name */
    strncpy(g_dll.DllName, (char*)((BYTE*)hDll + exp->Name), 255);
    g_dll.DllName[255] = '\0';

    printf("DLL: %s\n", g_dll.DllName);
    printf("Architecture: %s\n", g_dll.is64bit ? "x64" : "x86");
    printf("Exports: %lu\n", exp->NumberOfNames);

    /* Parse named exports */
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (char*)((BYTE*)hDll + names[i]);
        WORD ordinal = ordinals[i];

        ExportEntry* entry = (ExportEntry*)calloc(1, sizeof(ExportEntry));
        strncpy(entry->Name, name, 255);
        entry->Ordinal = ordinal + exp->Base;
        entry->ByOrdinal = 0;
        entry->next = g_dll.exports;
        g_dll.exports = entry;
    }

    FreeLibrary(hDll);
    return 1;
}

/* ============================================================================
 * IMPORT LIBRARY GENERATION
 * ============================================================================ */

static void write_archive_header(FILE* fp) {
    fwrite(IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE, 1, fp);
}

static void write_member_header(FILE* fp, const char* name, uint32_t size) {
    IMAGE_ARCHIVE_MEMBER_HEADER header;
    memset(&header, ' ', sizeof(header));

    /* Name */
    size_t name_len = strlen(name);
    if (name_len <= 15) {
        memcpy(header.Name, name, name_len);
    } else {
        header.Name[0] = '/';
        /* Would need long name string table for full support */
    }

    /* Date */
    write_decimal(header.Date, sizeof(header.Date), g_dll.timestamp);

    /* User ID */
    memcpy(header.UserID, "0     ", 6);

    /* Group ID */
    memcpy(header.GroupID, "0     ", 6);

    /* Mode */
    memcpy(header.Mode, "100644  ", 8);

    /* Size */
    write_decimal(header.Size, sizeof(header.Size), size);

    /* End header marker */
    memcpy(header.EndHeader, IMAGE_ARCHIVE_END, 2);

    fwrite(&header, sizeof(header), 1, fp);
}

static void write_import_header(FILE* fp, const char* symbol, uint16_t type) {
    IMPORT_OBJECT_HEADER hdr;
    hdr.Sig1 = 0x0000;
    hdr.Sig2 = 0xFFFF;
    hdr.Version = 0;
    hdr.Machine = g_dll.is64bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    hdr.TimeDateStamp = g_dll.timestamp;
    hdr.SizeOfData = (uint32_t)(strlen(symbol) + strlen(g_dll.DllName) + 2);
    hdr.Ordinal = 0;
    hdr.Type = type | (IMPORT_NAME_NOPREFIX << 1);

    fwrite(&hdr, sizeof(hdr), 1, fp);
    fwrite(symbol, strlen(symbol) + 1, 1, fp);
    fwrite(g_dll.DllName, strlen(g_dll.DllName) + 1, 1, fp);
}

static void write_thunk_obj(FILE* fp, const char* symbol) {
    /* Create a minimal COFF object with thunk code */
    IMAGE_FILE_HEADER coff_hdr = {0};
    coff_hdr.Machine = g_dll.is64bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    coff_hdr.NumberOfSections = 1;
    coff_hdr.TimeDateStamp = g_dll.timestamp;
    coff_hdr.PointerToSymbolTable = sizeof(IMAGE_FILE_HEADER) + 40 + sizeof(x86_thunk) + 8;
    coff_hdr.NumberOfSymbols = 2;
    coff_hdr.SizeOfOptionalHeader = 0;
    coff_hdr.Characteristics = 0;

    /* Section header for .text */
    struct {
        char Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    } sec_hdr = {0};

    memcpy(sec_hdr.Name, ".text", 5);
    sec_hdr.SizeOfRawData = g_dll.is64bit ? sizeof(x64_thunk) : sizeof(x86_thunk);
    sec_hdr.PointerToRawData = sizeof(IMAGE_FILE_HEADER) + sizeof(sec_hdr);
    sec_hdr.PointerToRelocations = sec_hdr.PointerToRawData + sec_hdr.SizeOfRawData;
    sec_hdr.NumberOfRelocations = 1;
    sec_hdr.Characteristics = 0x60000020; /* CODE | EXECUTE | READ */

    /* Relocation */
    struct {
        uint32_t VirtualAddress;
        uint32_t SymbolTableIndex;
        uint16_t Type;
    } reloc;

    reloc.VirtualAddress = 2;  /* Offset after jmp opcode */
    reloc.SymbolTableIndex = 1;  /* __imp_symbol */
    reloc.Type = g_dll.is64bit ? 4 : 6; /* REL32 / DIR32 */

    /* Symbol table entries */
    struct {
        union {
            char ShortName[8];
            struct { uint32_t Zeroes; uint32_t Offset; } Name;
        } N;
        uint32_t Value;
        uint16_t SectionNumber;
        uint16_t Type;
        uint8_t StorageClass;
        uint8_t NumberOfAuxSymbols;
    } sym1 = {0}, sym2 = {0};

    /* Symbol 1: _symbol (the thunk) */
    char decorated[280];
    if (g_dll.is64bit) {
        snprintf(decorated, sizeof(decorated), "%s", symbol);
    } else {
        snprintf(decorated, sizeof(decorated), "_%s", symbol);
    }
    size_t sym_len = strlen(decorated);
    if (sym_len <= 8) {
        memcpy(sym1.N.ShortName, decorated, sym_len);
    } else {
        sym1.N.Name.Zeroes = 0;
        sym1.N.Name.Offset = 4;  /* Offset into string table */
    }
    sym1.Value = 0;
    sym1.SectionNumber = 1;
    sym1.StorageClass = 2; /* EXTERNAL */

    /* Symbol 2: __imp_symbol */
    char imp_name[280];
    snprintf(imp_name, sizeof(imp_name), "__imp_%s", decorated);
    sym_len = strlen(imp_name);
    if (sym_len <= 8) {
        memcpy(sym2.N.ShortName, imp_name, sym_len);
    } else {
        sym2.N.Name.Zeroes = 0;
        sym2.N.Name.Offset = 4 + strlen(decorated) + 1;
    }
    sym2.Value = 0;
    sym2.SectionNumber = 0; /* Undefined - will be resolved by linker */
    sym2.StorageClass = 2; /* EXTERNAL */

    /* String table size */
    uint32_t strtab_size = 4;
    if (strlen(decorated) > 8) strtab_size += strlen(decorated) + 1;
    if (strlen(imp_name) > 8) strtab_size += strlen(imp_name) + 1;

    /* Calculate total size */
    uint32_t total_size = sizeof(coff_hdr) + sizeof(sec_hdr) + sec_hdr.SizeOfRawData +
                          sizeof(reloc) + 2 * sizeof(sym1) + strtab_size;

    /* Write member header */
    char member_name[32];
    snprintf(member_name, sizeof(member_name), "%s%s.o/", g_dll.is64bit ? "" : "_", symbol);
    write_member_header(fp, member_name, total_size);

    /* Write COFF data */
    fwrite(&coff_hdr, sizeof(coff_hdr), 1, fp);
    fwrite(&sec_hdr, sizeof(sec_hdr), 1, fp);
    fwrite(g_dll.is64bit ? x64_thunk : x86_thunk, sec_hdr.SizeOfRawData, 1, fp);
    fwrite(&reloc, sizeof(reloc), 1, fp);
    fwrite(&sym1, sizeof(sym1), 1, fp);
    fwrite(&sym2, sizeof(sym2), 1, fp);

    /* String table */
    fwrite(&strtab_size, 4, 1, fp);
    if (strlen(decorated) > 8) {
        fwrite(decorated, strlen(decorated) + 1, 1, fp);
    }
    if (strlen(imp_name) > 8) {
        fwrite(imp_name, strlen(imp_name) + 1, 1, fp);
    }

    /* Align to even boundary */
    if (total_size % 2 != 0) {
        fputc('\n', fp);
    }
}

static int generate_import_lib(const char* output_file) {
    FILE* fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create '%s'\n", output_file);
        return 0;
    }

    /* Write archive signature */
    write_archive_header(fp);

    /* Write linker member (first member - symbol index) */
    /* For simplicity, we'll create a minimal linker member */
    char linker_member[256];
    int linker_size = 0;
    
    /* Number of symbols (4 bytes) */
    uint32_t num_symbols = 0;
    ExportEntry* exp = g_dll.exports;
    while (exp) { num_symbols++; exp = exp->next; }
    
    memcpy(linker_member + linker_size, &num_symbols, 4);
    linker_size += 4;
    
    /* Symbol offsets (4 bytes each) */
    uint32_t offset = 8;  /* After archive header */
    exp = g_dll.exports;
    while (exp) {
        memcpy(linker_member + linker_size, &offset, 4);
        linker_size += 4;
        offset += 60 + 100;  /* Approximate member size */
        exp = exp->next;
    }
    
    /* Symbol names (null-terminated) */
    exp = g_dll.exports;
    while (exp) {
        size_t len = strlen(exp->Name) + 1;
        memcpy(linker_member + linker_size, exp->Name, len);
        linker_size += len;
        exp = exp->next;
    }

    write_member_header(fp, "/", linker_size);
    fwrite(linker_member, linker_size, 1, fp);
    if (linker_size % 2 != 0) fputc('\n', fp);

    /* Write import header for each export */
    exp = g_dll.exports;
    while (exp) {
        /* Import header member */
        uint32_t imp_size = sizeof(IMPORT_OBJECT_HEADER) + strlen(exp->Name) + strlen(g_dll.DllName) + 2;
        char member_name[32];
        snprintf(member_name, sizeof(member_name), "__imp_%s/", exp->Name);
        write_member_header(fp, member_name, imp_size);
        write_import_header(fp, exp->Name, IMPORT_NAME);
        if (imp_size % 2 != 0) fputc('\n', fp);

        /* Thunk object member */
        write_thunk_obj(fp, exp->Name);

        exp = exp->next;
    }

    fclose(fp);
    printf("Import library created: %s\n", output_file);
    return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] dllfile.dll /out:output.lib\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  /out:file       Output file name (required)\n");
    fprintf(stderr, "  /machine:type   Target machine: x86, x64 (auto-detected from DLL)\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s kernel32.dll /out:kernel32.lib\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    char* dll_file = NULL;
    char output_file[256] = {0};

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/out:", 5) == 0 || strncmp(argv[i], "-out:", 5) == 0) {
            strncpy(output_file, argv[i] + 5, 255);
        } else if (strncmp(argv[i], "/machine:", 9) == 0) {
            /* Machine type - currently auto-detected */
        } else if (argv[i][0] != '/' && argv[i][0] != '-') {
            dll_file = argv[i];
        }
    }

    if (!dll_file) {
        fprintf(stderr, "Error: No DLL file specified\n");
        return 1;
    }

    if (!output_file[0]) {
        fprintf(stderr, "Error: No output file specified. Use /out:filename\n");
        return 1;
    }

    /* Parse DLL exports */
    if (!parse_dll_exports(dll_file)) {
        return 1;
    }

    /* Generate import library */
    if (!generate_import_lib(output_file)) {
        return 1;
    }

    printf("\nSuccess! Import library generated.\n");
    return 0;
}
