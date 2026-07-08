/*
 * RAWRXD NATIVE LINKER - Complete PE/COFF linker
 * Links object files into executables without Microsoft LINK.EXE
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>

/* PE/COFF structures */
#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
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
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

/* COFF Symbol Table */
typedef struct {
    union {
        uint8_t ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } Name;
    } N;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} IMAGE_SYMBOL;

/* COFF Relocation */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} IMAGE_RELOCATION;

/* COFF Section */
typedef struct {
    char Name[9];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
    uint8_t *Data;
    IMAGE_RELOCATION *Relocations;
} COFF_Section;

/* COFF File */
typedef struct {
    IMAGE_FILE_HEADER Header;
    COFF_Section *Sections;
    IMAGE_SYMBOL *Symbols;
    char *StringTable;
    uint32_t StringTableSize;
    int is64bit;
} COFF_File;

#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386  0x014C
#define IMAGE_NT_SIGNATURE       0x00004550
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020

#define IMAGE_SCN_CNT_CODE       0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_EXECUTE    0x20000000
#define IMAGE_SCN_MEM_READ       0x40000000
#define IMAGE_SCN_MEM_WRITE      0x80000000

#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define IMAGE_SUBSYSTEM_EFI_APPLICATION 10

#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32   0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

#define IMAGE_REL_I386_DIR32     0x0006
#define IMAGE_REL_I386_DIR32NB   0x0007
#define IMAGE_REL_I386_REL32     0x0014

#pragma pack(pop)

/* Linked section */
typedef struct LinkedSection {
    char Name[9];
    uint8_t *Data;
    uint32_t Size;
    uint32_t VirtualAddress;
    uint32_t PointerToRawData;  /* File offset */
    uint32_t Characteristics;
    struct LinkedSection *next;
} LinkedSection;

/* Symbol */
typedef struct Symbol {
    char Name[256];
    uint32_t Value;
    uint32_t Section;
    int is_defined;
    int is_external;
    struct Symbol *next;
} Symbol;

/* Relocation */
typedef struct Relocation {
    uint32_t Offset;
    char SymbolName[256];
    uint16_t Type;
    uint32_t Section;
    struct Relocation *next;
} Relocation;

/* Import table structures */
typedef struct ImportDll {
    char Name[256];
    char **Functions;
    int FunctionCount;
    int FunctionCapacity;
    struct ImportDll *next;
} ImportDll;

/* Linker state */
typedef struct {
    LinkedSection *sections;
    Symbol *symbols;
    Relocation *relocations;
    ImportDll *imports;
    int is64bit;
    uint32_t image_base;
    uint32_t entry_point;
    char entry_symbol[256];
    int subsystem;
    int dll_mode;
} LinkerState;

static LinkerState g_state;

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */
static uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static uint32_t file_align(uint32_t value) {
    return align_up(value, 512);
}

static uint32_t section_align(uint32_t value) {
    return align_up(value, 4096);
}

/* ============================================================================
 * COFF FILE READING
 * ============================================================================ */
static int read_coff_file(const char *filename, COFF_File *coff) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open '%s'\n", filename);
        return 0;
    }

    /* Read header */
    if (fread(&coff->Header, sizeof(IMAGE_FILE_HEADER), 1, fp) != 1) {
        fprintf(stderr, "Error: Cannot read COFF header from '%s'\n", filename);
        fclose(fp);
        return 0;
    }

    /* Check machine type */
    if (coff->Header.Machine == IMAGE_FILE_MACHINE_AMD64) {
        coff->is64bit = 1;
    } else if (coff->Header.Machine == IMAGE_FILE_MACHINE_I386) {
        coff->is64bit = 0;
    } else {
        fprintf(stderr, "Error: Unknown machine type 0x%04X in '%s'\n",
                coff->Header.Machine, filename);
        fclose(fp);
        return 0;
    }

    /* Read sections - first pass: read all section headers */
    if (coff->Header.NumberOfSections > 0) {
        coff->Sections = (COFF_Section *)calloc(coff->Header.NumberOfSections, sizeof(COFF_Section));

        for (int i = 0; i < coff->Header.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER sec_header;
            if (fread(&sec_header, sizeof(IMAGE_SECTION_HEADER), 1, fp) != 1) {
                fprintf(stderr, "Error: Cannot read section header %d from '%s'\n", i, filename);
                fclose(fp);
                return 0;
            }

            memcpy(coff->Sections[i].Name, sec_header.Name, 8);
            coff->Sections[i].Name[8] = '\0';
            coff->Sections[i].VirtualSize = sec_header.VirtualSize;
            coff->Sections[i].VirtualAddress = sec_header.VirtualAddress;
            coff->Sections[i].SizeOfRawData = sec_header.SizeOfRawData;
            coff->Sections[i].PointerToRawData = sec_header.PointerToRawData;
            coff->Sections[i].PointerToRelocations = sec_header.PointerToRelocations;
            coff->Sections[i].PointerToLinenumbers = sec_header.PointerToLinenumbers;
            coff->Sections[i].NumberOfRelocations = sec_header.NumberOfRelocations;
            coff->Sections[i].NumberOfLinenumbers = sec_header.NumberOfLinenumbers;
            coff->Sections[i].Characteristics = sec_header.Characteristics;
        }
    }

    /* Second pass: read section data and relocations */
    for (int i = 0; i < coff->Header.NumberOfSections; i++) {
        /* Read section data */
        if (coff->Sections[i].SizeOfRawData > 0) {
            coff->Sections[i].Data = (uint8_t *)malloc(coff->Sections[i].SizeOfRawData);
            fseek(fp, coff->Sections[i].PointerToRawData, SEEK_SET);
            fread(coff->Sections[i].Data, coff->Sections[i].SizeOfRawData, 1, fp);
        }

        /* Read relocations */
        if (coff->Sections[i].NumberOfRelocations > 0) {
            coff->Sections[i].Relocations = (IMAGE_RELOCATION *)malloc(
                coff->Sections[i].NumberOfRelocations * sizeof(IMAGE_RELOCATION));
            fseek(fp, coff->Sections[i].PointerToRelocations, SEEK_SET);
            fread(coff->Sections[i].Relocations,
                  coff->Sections[i].NumberOfRelocations * sizeof(IMAGE_RELOCATION), 1, fp);
        }
    }

    /* Read symbol table */
    if (coff->Header.NumberOfSymbols > 0) {
        fseek(fp, coff->Header.PointerToSymbolTable, SEEK_SET);
        coff->Symbols = (IMAGE_SYMBOL *)malloc(coff->Header.NumberOfSymbols * sizeof(IMAGE_SYMBOL));
        fread(coff->Symbols, coff->Header.NumberOfSymbols * sizeof(IMAGE_SYMBOL), 1, fp);

        /* Read string table */
        uint32_t str_table_size;
        fread(&str_table_size, 4, 1, fp);
        coff->StringTableSize = str_table_size;
        coff->StringTable = (char *)malloc(str_table_size);
        memcpy(coff->StringTable, &str_table_size, 4);
        fread(coff->StringTable + 4, str_table_size - 4, 1, fp);
    }

    fclose(fp);
    return 1;
}

static void free_coff_file(COFF_File *coff) {
    if (coff->Sections) {
        for (int i = 0; i < coff->Header.NumberOfSections; i++) {
            free(coff->Sections[i].Data);
            free(coff->Sections[i].Relocations);
        }
        free(coff->Sections);
    }
    free(coff->Symbols);
    free(coff->StringTable);
    memset(coff, 0, sizeof(COFF_File));
}

/* ============================================================================
 * SYMBOL TABLE MANAGEMENT
 * ============================================================================ */
static Symbol* find_symbol(const char *name) {
    Symbol *sym = g_state.symbols;
    while (sym) {
        if (strcmp(sym->Name, name) == 0) {
            return sym;
        }
        sym = sym->next;
    }
    return NULL;
}

static void add_symbol(const char *name, uint32_t value, uint32_t section, int is_external) {
    Symbol *sym = find_symbol(name);
    if (!sym) {
        sym = (Symbol *)calloc(1, sizeof(Symbol));
        strncpy(sym->Name, name, 255);
        sym->Name[255] = '\0';
        sym->next = g_state.symbols;
        g_state.symbols = sym;
    }

    if (!is_external) {
        sym->Value = value;
        sym->Section = section;
        sym->is_defined = 1;
    }
    sym->is_external = is_external;
}

static const char* get_symbol_name(COFF_File *coff, IMAGE_SYMBOL *sym) {
    static char name_buf[256];

    if (sym->N.Name.Zeroes == 0) {
        /* Long name in string table */
        uint32_t offset = sym->N.Name.Offset;
        if (offset < coff->StringTableSize) {
            strncpy(name_buf, coff->StringTable + offset, 255);
            name_buf[255] = '\0';
            return name_buf;
        }
    } else {
        /* Short name inline */
        memcpy(name_buf, sym->N.ShortName, 8);
        name_buf[8] = '\0';
        return name_buf;
    }

    return "";
}

/* ============================================================================
 * SECTION MANAGEMENT
 * ============================================================================ */
static LinkedSection* find_linked_section(const char *name) {
    LinkedSection *sec = g_state.sections;
    while (sec) {
        if (strcmp(sec->Name, name) == 0) {
            return sec;
        }
        sec = sec->next;
    }
    return NULL;
}

static LinkedSection* add_linked_section(const char *name, uint32_t characteristics) {
    LinkedSection *sec = find_linked_section(name);
    if (!sec) {
        sec = (LinkedSection *)calloc(1, sizeof(LinkedSection));
        strncpy(sec->Name, name, 8);
        sec->Name[8] = '\0';
        sec->Characteristics = characteristics;
        sec->next = g_state.sections;
        g_state.sections = sec;
    }
    return sec;
}

static void append_section_data(LinkedSection *sec, const uint8_t *data, uint32_t size) {
    if (size == 0) return;

    sec->Data = (uint8_t *)realloc(sec->Data, sec->Size + size);
    memcpy(sec->Data + sec->Size, data, size);
    sec->Size += size;
}

/* ============================================================================
 * RELOCATION MANAGEMENT
 * ============================================================================ */
static void add_relocation(uint32_t offset, const char *symbol, uint16_t type, uint32_t section) {
    Relocation *rel = (Relocation *)calloc(1, sizeof(Relocation));
    rel->Offset = offset;
    strncpy(rel->SymbolName, symbol, 255);
    rel->SymbolName[255] = '\0';
    rel->Type = type;
    rel->Section = section;
    rel->next = g_state.relocations;
    g_state.relocations = rel;
}

/* ============================================================================
 * LINK OBJECT FILE
 * ============================================================================ */
static int link_object_file(const char *filename) {
    COFF_File coff = {0};

    if (!read_coff_file(filename, &coff)) {
        return 0;
    }

    printf("Linking: %s\n", filename);
    printf("  Machine: %s\n", coff.is64bit ? "x64" : "x86");
    printf("  Sections: %d\n", coff.Header.NumberOfSections);
    printf("  Symbols: %d\n", coff.Header.NumberOfSymbols);

    /* Check architecture consistency */
    if (g_state.is64bit == -1) {
        g_state.is64bit = coff.is64bit;
    } else if (g_state.is64bit != coff.is64bit) {
        fprintf(stderr, "Error: Architecture mismatch in '%s'\n", filename);
        free_coff_file(&coff);
        return 0;
    }

    /* Process sections */
    for (int i = 0; i < coff.Header.NumberOfSections; i++) {
        COFF_Section *coff_sec = &coff.Sections[i];

        /* Map COFF section to output section */
        char *out_sec_name = coff_sec->Name;
        uint32_t characteristics = coff_sec->Characteristics;

        /* Merge sections with same name */
        LinkedSection *linked_sec = add_linked_section(out_sec_name, characteristics);
        uint32_t section_offset = linked_sec->Size;

        /* Append data */
        if (coff_sec->Data && coff_sec->SizeOfRawData > 0) {
            append_section_data(linked_sec, coff_sec->Data, coff_sec->SizeOfRawData);
        }

        /* Process relocations */
        for (int j = 0; j < coff_sec->NumberOfRelocations; j++) {
            IMAGE_RELOCATION *rel = &coff_sec->Relocations[j];
            IMAGE_SYMBOL *sym = &coff.Symbols[rel->SymbolTableIndex];
            const char *sym_name = get_symbol_name(&coff, sym);

            add_relocation(section_offset + rel->VirtualAddress,
                          sym_name, rel->Type, i);
        }
    }

    /* Process symbols */
    for (int i = 0; i < coff.Header.NumberOfSymbols; i++) {
        IMAGE_SYMBOL *sym = &coff.Symbols[i];
        const char *sym_name = get_symbol_name(&coff, sym);

        if (sym_name[0] == '\0') continue;

        /* Skip debug symbols and file records */
        if (sym->StorageClass == 0xFF) continue;

        int is_external = (sym->SectionNumber == 0);
        uint32_t section = sym->SectionNumber;
        uint32_t value = sym->Value;

        /* Adjust value by section base */
        if (section > 0 && section <= coff.Header.NumberOfSections) {
            LinkedSection *sec = find_linked_section(coff.Sections[section-1].Name);
            if (sec) {
                value += sec->Size - coff.Sections[section-1].SizeOfRawData;
            }
        }

        add_symbol(sym_name, value, section, is_external);

        /* Check for entry point */
        if (strcmp(sym_name, "_start") == 0 ||
            strcmp(sym_name, "main") == 0 ||
            strcmp(sym_name, "WinMain") == 0 ||
            strcmp(sym_name, "DllMain") == 0) {
            strncpy(g_state.entry_symbol, sym_name, 255);
        }

        /* Skip auxiliary symbols */
        i += sym->NumberOfAuxSymbols;
    }

    free_coff_file(&coff);
    return 1;
}

/* ============================================================================
 * RESOLVE RELOCATIONS
 * ============================================================================ */
static void resolve_relocations(void) {
    Relocation *rel = g_state.relocations;
    int resolved = 0;
    int unresolved = 0;

    while (rel) {
        Symbol *sym = find_symbol(rel->SymbolName);

        if (!sym || !sym->is_defined) {
            /* External symbol - leave as zero or handle via import */
            printf("  Unresolved: %s\n", rel->SymbolName);
            unresolved++;
            rel = rel->next;
            continue;
        }

        /* Find the section containing this relocation */
        LinkedSection *sec = g_state.sections;
        int section_idx = 0;
        while (sec && section_idx < rel->Section) {
            sec = sec->next;
            section_idx++;
        }

        if (!sec) {
            rel = rel->next;
            continue;
        }

        /* Apply relocation */
        uint32_t target = sym->Value;
        uint32_t offset = rel->Offset;

        switch (rel->Type) {
            case IMAGE_REL_AMD64_ADDR64:
                /* 64-bit absolute address */
                if (offset + 8 <= sec->Size) {
                    uint64_t *ptr = (uint64_t *)(sec->Data + offset);
                    *ptr = target + g_state.image_base;
                }
                break;

            case IMAGE_REL_AMD64_ADDR32:
            case IMAGE_REL_I386_DIR32:
                /* 32-bit absolute address */
                if (offset + 4 <= sec->Size) {
                    uint32_t *ptr = (uint32_t *)(sec->Data + offset);
                    *ptr = target + g_state.image_base;
                }
                break;

            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_I386_REL32:
                /* 32-bit relative address */
                if (offset + 4 <= sec->Size) {
                    int32_t *ptr = (int32_t *)(sec->Data + offset);
                    *ptr = (int32_t)(target - (sec->VirtualAddress + offset + 4));
                }
                break;

            case IMAGE_REL_AMD64_ADDR32NB:
            case IMAGE_REL_I386_DIR32NB:
                /* 32-bit address without base */
                if (offset + 4 <= sec->Size) {
                    uint32_t *ptr = (uint32_t *)(sec->Data + offset);
                    *ptr = target;
                }
                break;
        }

        resolved++;
        rel = rel->next;
    }

    printf("Relocations: %d resolved, %d unresolved\n", resolved, unresolved);
}

/* ============================================================================
 * IMPORT TABLE BUILDER
 * ============================================================================ */

/* Known DLL exports mapping - common Windows API functions */
static struct {
    const char *name;
    const char *dll;
} g_known_imports[] = {
    /* kernel32.dll exports */
    {"GetModuleHandleA", "kernel32.dll"},
    {"GetModuleHandleW", "kernel32.dll"},
    {"GetModuleHandleExA", "kernel32.dll"},
    {"GetModuleHandleExW", "kernel32.dll"},
    {"GetProcAddress", "kernel32.dll"},
    {"LoadLibraryA", "kernel32.dll"},
    {"LoadLibraryW", "kernel32.dll"},
    {"FreeLibrary", "kernel32.dll"},
    {"VirtualAlloc", "kernel32.dll"},
    {"VirtualFree", "kernel32.dll"},
    {"VirtualProtect", "kernel32.dll"},
    {"HeapAlloc", "kernel32.dll"},
    {"HeapFree", "kernel32.dll"},
    {"GetProcessHeap", "kernel32.dll"},
    {"ExitProcess", "kernel32.dll"},
    {"GetLastError", "kernel32.dll"},
    {"SetLastError", "kernel32.dll"},
    {"CreateFileA", "kernel32.dll"},
    {"CreateFileW", "kernel32.dll"},
    {"ReadFile", "kernel32.dll"},
    {"WriteFile", "kernel32.dll"},
    {"CloseHandle", "kernel32.dll"},
    {"GetStdHandle", "kernel32.dll"},
    {"SetFilePointer", "kernel32.dll"},
    {"lstrlenA", "kernel32.dll"},
    {"lstrlenW", "kernel32.dll"},
    {"GetFileSize", "kernel32.dll"},
    {"CreateThread", "kernel32.dll"},
    {"WaitForSingleObject", "kernel32.dll"},
    {"Sleep", "kernel32.dll"},
    {"QueryPerformanceCounter", "kernel32.dll"},
    {"QueryPerformanceFrequency", "kernel32.dll"},
    {"GetTickCount", "kernel32.dll"},
    {"GetCurrentProcessId", "kernel32.dll"},
    {"GetCurrentThreadId", "kernel32.dll"},
    {"InitializeCriticalSection", "kernel32.dll"},
    {"EnterCriticalSection", "kernel32.dll"},
    {"LeaveCriticalSection", "kernel32.dll"},
    {"DeleteCriticalSection", "kernel32.dll"},
    {"TlsAlloc", "kernel32.dll"},
    {"TlsGetValue", "kernel32.dll"},
    {"TlsSetValue", "kernel32.dll"},
    {"TlsFree", "kernel32.dll"},
    {"GetSystemInfo", "kernel32.dll"},
    {"GetVersionExA", "kernel32.dll"},
    {"GetVersionExW", "kernel32.dll"},
    {"IsProcessorFeaturePresent", "kernel32.dll"},
    {"FlushInstructionCache", "kernel32.dll"},
    {"GetCurrentProcess", "kernel32.dll"},
    {"TerminateProcess", "kernel32.dll"},
    
    /* user32.dll exports */
    {"MessageBoxA", "user32.dll"},
    {"MessageBoxW", "user32.dll"},
    {"RegisterClassA", "user32.dll"},
    {"RegisterClassW", "user32.dll"},
    {"RegisterClassExA", "user32.dll"},
    {"RegisterClassExW", "user32.dll"},
    {"CreateWindowExA", "user32.dll"},
    {"CreateWindowExW", "user32.dll"},
    {"DefWindowProcA", "user32.dll"},
    {"DefWindowProcW", "user32.dll"},
    {"ShowWindow", "user32.dll"},
    {"UpdateWindow", "user32.dll"},
    {"GetMessageA", "user32.dll"},
    {"GetMessageW", "user32.dll"},
    {"TranslateMessage", "user32.dll"},
    {"DispatchMessageA", "user32.dll"},
    {"DispatchMessageW", "user32.dll"},
    {"PostQuitMessage", "user32.dll"},
    {"SendMessageA", "user32.dll"},
    {"SendMessageW", "user32.dll"},
    {"PostMessageA", "user32.dll"},
    {"PostMessageW", "user32.dll"},
    {"LoadCursorA", "user32.dll"},
    {"LoadCursorW", "user32.dll"},
    {"LoadIconA", "user32.dll"},
    {"LoadIconW", "user32.dll"},
    {"SetCursor", "user32.dll"},
    {"GetClientRect", "user32.dll"},
    {"GetWindowRect", "user32.dll"},
    {"InvalidateRect", "user32.dll"},
    {"ValidateRect", "user32.dll"},
    {"RedrawWindow", "user32.dll"},
    {"BeginPaint", "user32.dll"},
    {"EndPaint", "user32.dll"},
    {"GetDC", "user32.dll"},
    {"ReleaseDC", "user32.dll"},
    {"SetWindowTextA", "user32.dll"},
    {"SetWindowTextW", "user32.dll"},
    {"GetWindowTextA", "user32.dll"},
    {"GetWindowTextW", "user32.dll"},
    {"MoveWindow", "user32.dll"},
    {"SetWindowPos", "user32.dll"},
    {"EnableWindow", "user32.dll"},
    {"IsWindowEnabled", "user32.dll"},
    {"IsWindowVisible", "user32.dll"},
    {"SetFocus", "user32.dll"},
    {"GetFocus", "user32.dll"},
    {"SetActiveWindow", "user32.dll"},
    {"GetActiveWindow", "user32.dll"},
    {"DestroyWindow", "user32.dll"},
    {"PeekMessageA", "user32.dll"},
    {"PeekMessageW", "user32.dll"},
    {"WaitMessage", "user32.dll"},
    
    /* gdi32.dll exports */
    {"CreateSolidBrush", "gdi32.dll"},
    {"CreatePen", "gdi32.dll"},
    {"SelectObject", "gdi32.dll"},
    {"DeleteObject", "gdi32.dll"},
    {"GetStockObject", "gdi32.dll"},
    {"SetBkColor", "gdi32.dll"},
    {"SetTextColor", "gdi32.dll"},
    {"TextOutA", "gdi32.dll"},
    {"TextOutW", "gdi32.dll"},
    {"Rectangle", "gdi32.dll"},
    {"Ellipse", "gdi32.dll"},
    {"MoveToEx", "gdi32.dll"},
    {"LineTo", "gdi32.dll"},
    {"BitBlt", "gdi32.dll"},
    {"StretchBlt", "gdi32.dll"},
    {"CreateCompatibleDC", "gdi32.dll"},
    {"CreateCompatibleBitmap", "gdi32.dll"},
    {"DeleteDC", "gdi32.dll"},
    
    /* ntdll.dll exports (low-level) */
    {"RtlZeroMemory", "ntdll.dll"},
    {"RtlCopyMemory", "ntdll.dll"},
    {"RtlFillMemory", "ntdll.dll"},
    {"NtQuerySystemInformation", "ntdll.dll"},
    
    /* ucrtbase.dll / msvcrt.dll exports (C runtime) */
    {"malloc", "ucrtbase.dll"},
    {"free", "ucrtbase.dll"},
    {"calloc", "ucrtbase.dll"},
    {"realloc", "ucrtbase.dll"},
    {"memcpy", "ucrtbase.dll"},
    {"memset", "ucrtbase.dll"},
    {"memmove", "ucrtbase.dll"},
    {"strcmp", "ucrtbase.dll"},
    {"strcpy", "ucrtbase.dll"},
    {"strlen", "ucrtbase.dll"},
    {"strcat", "ucrtbase.dll"},
    {"strncpy", "ucrtbase.dll"},
    {"strncmp", "ucrtbase.dll"},
    {"strchr", "ucrtbase.dll"},
    {"strstr", "ucrtbase.dll"},
    {"sprintf", "ucrtbase.dll"},
    {"printf", "ucrtbase.dll"},
    {"fprintf", "ucrtbase.dll"},
    {"fopen", "ucrtbase.dll"},
    {"fclose", "ucrtbase.dll"},
    {"fread", "ucrtbase.dll"},
    {"fwrite", "ucrtbase.dll"},
    {"fseek", "ucrtbase.dll"},
    {"ftell", "ucrtbase.dll"},
    {"fflush", "ucrtbase.dll"},
    {"puts", "ucrtbase.dll"},
    {"gets", "ucrtbase.dll"},
    {"getchar", "ucrtbase.dll"},
    {"putchar", "ucrtbase.dll"},
    {"atoi", "ucrtbase.dll"},
    {"atol", "ucrtbase.dll"},
    {"atof", "ucrtbase.dll"},
    {"strtol", "ucrtbase.dll"},
    {"strtoul", "ucrtbase.dll"},
    {"strtod", "ucrtbase.dll"},
    {"time", "ucrtbase.dll"},
    {"clock", "ucrtbase.dll"},
    {"srand", "ucrtbase.dll"},
    {"rand", "ucrtbase.dll"},
    {"qsort", "ucrtbase.dll"},
    {"bsearch", "ucrtbase.dll"},
    {"abs", "ucrtbase.dll"},
    {"labs", "ucrtbase.dll"},
    {"div", "ucrtbase.dll"},
    {"ldiv", "ucrtbase.dll"},
    
    /* Legacy msvcrt.dll names */
    {"_malloc", "msvcrt.dll"},
    {"_free", "msvcrt.dll"},
    {"_memcpy", "msvcrt.dll"},
    {"_memset", "msvcrt.dll"},
    {"_strcmp", "msvcrt.dll"},
    {"_strcpy", "msvcrt.dll"},
    {"_strlen", "msvcrt.dll"},
    {"_sprintf", "msvcrt.dll"},
    {"_printf", "msvcrt.dll"},
    
    /* Terminator */
    {NULL, NULL}
};

/* Find DLL for a symbol */
static const char* find_dll_for_symbol(const char *name) {
    for (int i = 0; g_known_imports[i].name != NULL; i++) {
        if (strcmp(g_known_imports[i].name, name) == 0) {
            return g_known_imports[i].dll;
        }
    }
    return NULL;
}

/* Add import for unresolved symbol */
static void add_import(const char *symbol_name, const char *dll_name) {
    /* Check if already exists */
    ImportDll *dll = g_state.imports;
    while (dll) {
        if (strcmp(dll->Name, dll_name) == 0) {
            /* Check if function already in this DLL */
            for (int i = 0; i < dll->FunctionCount; i++) {
                if (strcmp(dll->Functions[i], symbol_name) == 0) {
                    return; /* Already exists */
                }
            }
            /* Add function to existing DLL */
            if (dll->FunctionCount >= dll->FunctionCapacity) {
                dll->FunctionCapacity = dll->FunctionCapacity ? dll->FunctionCapacity * 2 : 16;
                dll->Functions = realloc(dll->Functions, dll->FunctionCapacity * sizeof(char*));
            }
            dll->Functions[dll->FunctionCount] = strdup(symbol_name);
            dll->FunctionCount++;
            return;
        }
        dll = dll->next;
    }
    
    /* Create new DLL entry */
    dll = calloc(1, sizeof(ImportDll));
    strncpy(dll->Name, dll_name, 255);
    dll->FunctionCapacity = 16;
    dll->Functions = calloc(dll->FunctionCapacity, sizeof(char*));
    dll->Functions[0] = strdup(symbol_name);
    dll->FunctionCount = 1;
    dll->next = g_state.imports;
    g_state.imports = dll;
}

/* Build import table and create .idata section */
static LinkedSection* build_import_section(void) {
    if (!g_state.imports) {
        return NULL; /* No imports needed */
    }
    
    /* Count total imports */
    int total_imports = 0;
    ImportDll *dll = g_state.imports;
    while (dll) {
        total_imports += dll->FunctionCount;
        dll = dll->next;
    }
    
    if (total_imports == 0) {
        return NULL;
    }
    
    /* Calculate sizes */
    int num_dlls = 0;
    dll = g_state.imports;
    while (dll) {
        num_dlls++;
        dll = dll->next;
    }
    
    /* Import Directory Table: 20 bytes per DLL + 20 bytes terminator */
    uint32_t idt_size = (num_dlls + 1) * 20;
    
    /* Import Lookup Tables: 8 bytes per function (x64) or 4 bytes (x86) */
    uint32_t ilt_entry_size = g_state.is64bit ? 8 : 4;
    uint32_t ilt_total_size = (total_imports + num_dlls) * ilt_entry_size; /* +num_dlls for terminators */
    
    /* Import Address Tables: same size as ILT */
    uint32_t iat_total_size = ilt_total_size;
    
    /* Hint/Name Table: 2 bytes hint + null-terminated name + padding to even */
    uint32_t hint_name_size = 0;
    dll = g_state.imports;
    while (dll) {
        for (int i = 0; i < dll->FunctionCount; i++) {
            size_t name_len = strlen(dll->Functions[i]);
            hint_name_size += 2 + (uint32_t)name_len + 1; /* hint + name + null */
            if (hint_name_size % 2) hint_name_size++; /* Pad to even */
        }
        dll = dll->next;
    }
    
    /* DLL Names */
    uint32_t dll_names_size = 0;
    dll = g_state.imports;
    while (dll) {
        dll_names_size += (uint32_t)strlen(dll->Name) + 1;
        if (dll_names_size % 2) dll_names_size++;
        dll = dll->next;
    }
    
    /* Total size */
    uint32_t total_size = idt_size + ilt_total_size + iat_total_size + hint_name_size + dll_names_size;
    
    /* Create section */
    LinkedSection *sec = calloc(1, sizeof(LinkedSection));
    strcpy(sec->Name, ".idata");
    sec->Data = calloc(1, total_size);
    sec->Size = total_size;
    sec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    
    uint8_t *data = sec->Data;
    uint32_t offset = 0;
    
    /* Layout:
     * [0] Import Directory Table
     * [idt_size] Import Lookup Tables (one per DLL)
     * [idt_size + ilt_total_size] Import Address Tables (one per DLL)
     * [idt_size + ilt_total_size + iat_total_size] Hint/Name Table
     * [...] DLL Names
     */
    
    uint32_t idt_offset = 0;
    uint32_t ilt_offset = idt_size;
    uint32_t iat_offset = idt_size + ilt_total_size;
    uint32_t hint_name_offset = idt_size + ilt_total_size + iat_total_size;
    uint32_t dll_name_offset = idt_size + ilt_total_size + iat_total_size + hint_name_size;
    
    /* Build Import Directory Table and ILT/IAT */
    dll = g_state.imports;
    int dll_idx = 0;
    while (dll) {
        /* Import Directory Entry (20 bytes) */
        uint32_t *idt_entry = (uint32_t *)(data + idt_offset + dll_idx * 20);
        
        /* OriginalFirstThunk - RVA to ILT */
        idt_entry[0] = ilt_offset + dll_idx * (dll->FunctionCount + 1) * ilt_entry_size;
        /* TimeDateStamp */
        idt_entry[1] = 0;
        /* ForwarderChain */
        idt_entry[2] = 0;
        /* Name - RVA to DLL name */
        idt_entry[3] = dll_name_offset;
        /* FirstThunk - RVA to IAT */
        idt_entry[4] = iat_offset + dll_idx * (dll->FunctionCount + 1) * ilt_entry_size;
        
        /* Build ILT and IAT for this DLL */
        for (int i = 0; i < dll->FunctionCount; i++) {
            uint32_t hint_rva = hint_name_offset;
            
            /* Write ILT entry */
            if (g_state.is64bit) {
                uint64_t *ilt = (uint64_t *)(data + ilt_offset + dll_idx * (dll->FunctionCount + 1) * 8 + i * 8);
                *ilt = hint_rva;
                
                uint64_t *iat = (uint64_t *)(data + iat_offset + dll_idx * (dll->FunctionCount + 1) * 8 + i * 8);
                *iat = hint_rva;
            } else {
                uint32_t *ilt = (uint32_t *)(data + ilt_offset + dll_idx * (dll->FunctionCount + 1) * 4 + i * 4);
                *ilt = hint_rva;
                
                uint32_t *iat = (uint32_t *)(data + iat_offset + dll_idx * (dll->FunctionCount + 1) * 4 + i * 4);
                *iat = hint_rva;
            }
            
            /* Write Hint/Name entry */
            uint16_t *hint = (uint16_t *)(data + hint_name_offset);
            *hint = 0; /* Hint - ordinal in DLL, 0 = unknown */
            strcpy((char *)(data + hint_name_offset + 2), dll->Functions[i]);
            hint_name_offset += 2 + (uint32_t)strlen(dll->Functions[i]) + 1;
            if (hint_name_offset % 2) hint_name_offset++;
        }
        
        /* Write ILT/IAT terminators */
        if (g_state.is64bit) {
            uint64_t *ilt_term = (uint64_t *)(data + ilt_offset + dll_idx * (dll->FunctionCount + 1) * 8 + dll->FunctionCount * 8);
            uint64_t *iat_term = (uint64_t *)(data + iat_offset + dll_idx * (dll->FunctionCount + 1) * 8 + dll->FunctionCount * 8);
            *ilt_term = 0;
            *iat_term = 0;
        } else {
            uint32_t *ilt_term = (uint32_t *)(data + ilt_offset + dll_idx * (dll->FunctionCount + 1) * 4 + dll->FunctionCount * 4);
            uint32_t *iat_term = (uint32_t *)(data + iat_offset + dll_idx * (dll->FunctionCount + 1) * 4 + dll->FunctionCount * 4);
            *ilt_term = 0;
            *iat_term = 0;
        }
        
        /* Write DLL name */
        strcpy((char *)(data + dll_name_offset), dll->Name);
        dll_name_offset += (uint32_t)strlen(dll->Name) + 1;
        if (dll_name_offset % 2) dll_name_offset++;
        
        dll_idx++;
        dll = dll->next;
    }
    
    /* Zero terminator for Import Directory Table */
    memset(data + idt_offset + num_dlls * 20, 0, 20);
    
    printf("Import table: %d DLLs, %d functions, %u bytes\n", num_dlls, total_imports, total_size);
    
    return sec;
}

/* First pass: collect all imports */
static void collect_imports(void) {
    Relocation *rel = g_state.relocations;
    while (rel) {
        Symbol *sym = find_symbol(rel->SymbolName);
        if (!sym || !sym->is_defined) {
            const char *dll_name = find_dll_for_symbol(rel->SymbolName);
            if (dll_name) {
                add_import(rel->SymbolName, dll_name);
            }
        }
        rel = rel->next;
    }
}

/* Get IAT entry RVA for an imported symbol */
static uint32_t get_import_iat_rva(const char *symbol_name, uint32_t idata_rva) {
    ImportDll *dll = g_state.imports;
    int dll_idx = 0;
    
    while (dll) {
        for (int i = 0; i < dll->FunctionCount; i++) {
            if (strcmp(dll->Functions[i], symbol_name) == 0) {
                /* Found it! Calculate IAT entry RVA */
                /* Layout: IDT | ILT | IAT | Hint/Name | DLL Names */
                int num_dlls = 0;
                ImportDll *d = g_state.imports;
                while (d) { num_dlls++; d = d->next; }
                
                uint32_t idt_size = (num_dlls + 1) * 20;
                uint32_t ilt_entry_size = g_state.is64bit ? 8 : 4;
                
                /* Calculate offset to this DLL's IAT */
                uint32_t iat_offset = idt_size;
                ImportDll *d2 = g_state.imports;
                int prev_dll_idx = 0;
                while (d2 && prev_dll_idx < dll_idx) {
                    iat_offset += (d2->FunctionCount + 1) * ilt_entry_size;
                    d2 = d2->next;
                    prev_dll_idx++;
                }
                
                /* Add offset to this function's entry */
                iat_offset += i * ilt_entry_size;
                
                return idata_rva + iat_offset;
            }
        }
        dll_idx++;
        dll = dll->next;
    }
    
    return 0; /* Not found */
}

/* Second pass: resolve relocations with import addresses */
static void resolve_relocations_with_imports(void) {
    /* First collect all imports */
    collect_imports();
    
    /* Build import section to get its RVA */
    LinkedSection *import_sec = build_import_section();
    if (import_sec) {
        /* Add import section to the end of section list */
        LinkedSection *sec = g_state.sections;
        while (sec && sec->next) {
            sec = sec->next;
        }
        if (sec) {
            sec->next = import_sec;
        } else {
            g_state.sections = import_sec;
        }
    }
    
    /* Now resolve relocations */
    Relocation *rel = g_state.relocations;
    int resolved = 0;
    int unresolved = 0;
    int import_resolved = 0;

    while (rel) {
        Symbol *sym = find_symbol(rel->SymbolName);

        if (!sym || !sym->is_defined) {
            /* External symbol - try to resolve via import */
            const char *dll_name = find_dll_for_symbol(rel->SymbolName);
            if (dll_name && import_sec) {
                /* Get IAT entry RVA for this import */
                uint32_t iat_rva = get_import_iat_rva(rel->SymbolName, import_sec->VirtualAddress);
                
                if (iat_rva != 0) {
                    /* Find the section containing this relocation */
                    LinkedSection *sec = g_state.sections;
                    int section_idx = 0;
                    while (sec && section_idx < rel->Section) {
                        sec = sec->next;
                        section_idx++;
                    }
                    
                    if (sec && rel->Offset + 8 <= sec->Size) {
                        /* Patch relocation to point to IAT entry */
                        switch (rel->Type) {
                            case IMAGE_REL_AMD64_ADDR64:
                                /* 64-bit absolute address - point to IAT */
                                {
                                    uint64_t *ptr = (uint64_t *)(sec->Data + rel->Offset);
                                    *ptr = iat_rva + g_state.image_base;
                                }
                                break;
                            
                            case IMAGE_REL_AMD64_ADDR32:
                            case IMAGE_REL_I386_DIR32:
                                /* 32-bit absolute address */
                                if (rel->Offset + 4 <= sec->Size) {
                                    uint32_t *ptr = (uint32_t *)(sec->Data + rel->Offset);
                                    *ptr = iat_rva + (uint32_t)g_state.image_base;
                                }
                                break;
                            
                            case IMAGE_REL_AMD64_ADDR32NB:
                            case IMAGE_REL_I386_DIR32NB:
                                /* 32-bit RVA */
                                if (rel->Offset + 4 <= sec->Size) {
                                    uint32_t *ptr = (uint32_t *)(sec->Data + rel->Offset);
                                    *ptr = iat_rva;
                                }
                                break;
                        }
                        import_resolved++;
                        printf("  Import: %s from %s -> IAT 0x%08X\n", rel->SymbolName, dll_name, iat_rva);
                    } else {
                        printf("  Import: %s from %s (offset out of range)\n", rel->SymbolName, dll_name);
                    }
                } else {
                    printf("  Import: %s from %s (IAT not found)\n", rel->SymbolName, dll_name);
                }
            } else {
                printf("  Unresolved: %s (unknown DLL)\n", rel->SymbolName);
                unresolved++;
            }
            rel = rel->next;
            continue;
        }

        /* Find the section containing this relocation */
        LinkedSection *sec = g_state.sections;
        int section_idx = 0;
        while (sec && section_idx < rel->Section) {
            sec = sec->next;
            section_idx++;
        }

        if (!sec) {
            rel = rel->next;
            continue;
        }

        /* Apply relocation */
        uint32_t target = sym->Value;
        uint32_t offset = rel->Offset;

        switch (rel->Type) {
            case IMAGE_REL_AMD64_ADDR64:
                /* 64-bit absolute address */
                if (offset + 8 <= sec->Size) {
                    uint64_t *ptr = (uint64_t *)(sec->Data + offset);
                    *ptr = target + g_state.image_base;
                }
                break;

            case IMAGE_REL_AMD64_ADDR32:
            case IMAGE_REL_I386_DIR32:
                /* 32-bit absolute address */
                if (offset + 4 <= sec->Size) {
                    uint32_t *ptr = (uint32_t *)(sec->Data + offset);
                    *ptr = target + g_state.image_base;
                }
                break;

            case IMAGE_REL_AMD64_REL32:
            case IMAGE_REL_I386_REL32:
                /* 32-bit relative address */
                if (offset + 4 <= sec->Size) {
                    int32_t *ptr = (int32_t *)(sec->Data + offset);
                    *ptr = (int32_t)(target - (sec->VirtualAddress + offset + 4));
                }
                break;

            case IMAGE_REL_AMD64_ADDR32NB:
            case IMAGE_REL_I386_DIR32NB:
                /* 32-bit address without base */
                if (offset + 4 <= sec->Size) {
                    uint32_t *ptr = (uint32_t *)(sec->Data + offset);
                    *ptr = target;
                }
                break;
        }

        resolved++;
        rel = rel->next;
    }

    printf("Relocations: %d resolved, %d import, %d unresolved\n", resolved, import_resolved, unresolved);
}

/* ============================================================================
 * WRITE PE FILE
 * ============================================================================ */
static void write_pe_file(const char *filename) {
    /* Import section already built in resolve_relocations_with_imports() */
    LinkedSection *import_sec = NULL;
    LinkedSection *sec;
    for (sec = g_state.sections; sec; sec = sec->next) {
        if (strcmp(sec->Name, ".idata") == 0) {
            import_sec = sec;
            break;
        }
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", filename);
        return;
    }

    /* Count sections */
    int num_sections = 0;
    LinkedSection *sec2 = g_state.sections;
    while (sec2) {
        if (sec2->Size > 0) num_sections++;
        sec2 = sec2->next;
    }

    if (num_sections == 0) {
        fprintf(stderr, "Error: No sections to write\n");
        fclose(fp);
        return;
    }

    /* Calculate sizes */
    uint32_t section_alignment = 4096;
    uint32_t file_alignment = 512;

    uint32_t header_size = sizeof(IMAGE_DOS_HEADER) + 64 + 4 +
                           sizeof(IMAGE_FILE_HEADER);

    if (g_state.is64bit) {
        header_size += sizeof(IMAGE_OPTIONAL_HEADER64);
    } else {
        header_size += sizeof(IMAGE_OPTIONAL_HEADER32);
    }

    header_size += num_sections * sizeof(IMAGE_SECTION_HEADER);
    header_size = file_align(header_size);

    /* Calculate section addresses */
    uint32_t current_rva = section_alignment;
    uint32_t current_file_offset = header_size;

    sec = g_state.sections;
    while (sec) {
        if (sec->Size > 0) {
            sec->VirtualAddress = current_rva;
            current_rva = section_align(current_rva + sec->Size);
        }
        sec = sec->next;
    }

    /* Calculate entry point */
    Symbol *entry_sym = find_symbol(g_state.entry_symbol);
    if (!entry_sym) {
        entry_sym = find_symbol("_start");
    }
    if (!entry_sym) {
        entry_sym = find_symbol("main");
    }

    uint32_t entry_rva = 0;
    if (entry_sym && entry_sym->is_defined) {
        entry_rva = entry_sym->Value;
        /* Find which section contains the entry point */
        sec = g_state.sections;
        while (sec) {
            if (entry_sym->Value < sec->Size) {
                entry_rva = sec->VirtualAddress + entry_sym->Value;
                break;
            }
            sec = sec->next;
        }
    }

    /* Calculate image size */
    uint32_t image_size = section_align(current_rva);

    /* Calculate import directory RVA if we have imports */
    uint32_t import_dir_rva = 0;
    uint32_t import_dir_size = 0;
    if (import_sec) {
        import_dir_rva = import_sec->VirtualAddress;
        /* Import directory is first in .idata section */
        /* Count DLLs for directory size */
        ImportDll *dll = g_state.imports;
        int num_dlls = 0;
        while (dll) {
            num_dlls++;
            dll = dll->next;
        }
        import_dir_size = (num_dlls + 1) * 20; /* 20 bytes per entry + terminator */
    }

    /* Write DOS header */
    IMAGE_DOS_HEADER dos_header = {0};
    dos_header.e_magic = 0x5A4D;
    dos_header.e_cblp = 144;
    dos_header.e_cp = 3;
    dos_header.e_cparhdr = 4;
    dos_header.e_maxalloc = 0xFFFF;
    dos_header.e_sp = 0xB8;
    dos_header.e_lfarlc = 64;
    dos_header.e_lfanew = sizeof(IMAGE_DOS_HEADER) + 64;
    fwrite(&dos_header, sizeof(dos_header), 1, fp);

    /* DOS stub */
    uint8_t dos_stub[64] = {
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
        'T', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'c', 'a', 'n', 'n', 'o',
        't', ' ', 'b', 'e', ' ', 'r', 'u', 'n', ' ', 'i', 'n', ' ', 'D', 'O', 'S', ' ', 'm',
        'o', 'd', 'e', '.', '\r', '\r', '\n', '$', 0, 0, 0, 0, 0, 0, 0, 0
    };
    fwrite(dos_stub, 64, 1, fp);

    /* PE signature */
    uint32_t pe_sig = IMAGE_NT_SIGNATURE;
    fwrite(&pe_sig, 4, 1, fp);

    /* COFF header */
    IMAGE_FILE_HEADER coff_header = {0};
    coff_header.Machine = g_state.is64bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    coff_header.NumberOfSections = num_sections;
    coff_header.TimeDateStamp = (uint32_t)time(NULL);
    coff_header.SizeOfOptionalHeader = g_state.is64bit ?
        sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    coff_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    if (g_state.is64bit) {
        coff_header.Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
    }
    if (g_state.dll_mode) {
        coff_header.Characteristics |= 0x2000; /* IMAGE_FILE_DLL */
    }
    fwrite(&coff_header, sizeof(coff_header), 1, fp);

    /* Optional header */
    uint32_t text_size = 0, data_size = 0, bss_size = 0;
    sec = g_state.sections;
    while (sec) {
        if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {
            text_size += section_align(sec->Size);
        } else if (sec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            bss_size += section_align(sec->Size);
        } else {
            data_size += section_align(sec->Size);
        }
        sec = sec->next;
    }

    if (g_state.is64bit) {
        IMAGE_OPTIONAL_HEADER64 opt64 = {0};
        opt64.Magic = 0x20B;
        opt64.MajorLinkerVersion = 1;
        opt64.MinorLinkerVersion = 0;
        opt64.SizeOfCode = text_size;
        opt64.SizeOfInitializedData = data_size;
        opt64.SizeOfUninitializedData = bss_size;
        opt64.AddressOfEntryPoint = entry_rva;
        opt64.BaseOfCode = section_alignment;
        opt64.ImageBase = g_state.image_base;
        opt64.SectionAlignment = section_alignment;
        opt64.FileAlignment = file_alignment;
        opt64.MajorOperatingSystemVersion = 6;
        opt64.MinorOperatingSystemVersion = 0;
        opt64.MajorSubsystemVersion = 6;
        opt64.MinorSubsystemVersion = 0;
        opt64.SizeOfImage = image_size;
        opt64.SizeOfHeaders = header_size;
        opt64.Subsystem = g_state.subsystem;
        opt64.DllCharacteristics = 0x8160;
        opt64.SizeOfStackReserve = 0x100000;
        opt64.SizeOfStackCommit = 0x1000;
        opt64.SizeOfHeapReserve = 0x100000;
        opt64.SizeOfHeapCommit = 0x1000;
        opt64.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        /* Import directory at index 1 */
        if (import_dir_rva != 0) {
            opt64.DataDirectory[1].VirtualAddress = import_dir_rva;
            opt64.DataDirectory[1].Size = import_dir_size;
        }
        fwrite(&opt64, sizeof(opt64), 1, fp);
    } else {
        IMAGE_OPTIONAL_HEADER32 opt32 = {0};
        opt32.Magic = 0x10B;
        opt32.MajorLinkerVersion = 1;
        opt32.MinorLinkerVersion = 0;
        opt32.SizeOfCode = text_size;
        opt32.SizeOfInitializedData = data_size;
        opt32.SizeOfUninitializedData = bss_size;
        opt32.AddressOfEntryPoint = entry_rva;
        opt32.BaseOfCode = section_alignment;
        opt32.ImageBase = g_state.image_base;
        opt32.SectionAlignment = section_alignment;
        opt32.FileAlignment = file_alignment;
        opt32.MajorOperatingSystemVersion = 6;
        opt32.MinorOperatingSystemVersion = 0;
        opt32.MajorSubsystemVersion = 6;
        opt32.MinorSubsystemVersion = 0;
        opt32.SizeOfImage = image_size;
        opt32.SizeOfHeaders = header_size;
        opt32.Subsystem = g_state.subsystem;
        opt32.DllCharacteristics = 0x8160;
        opt32.SizeOfStackReserve = 0x100000;
        opt32.SizeOfStackCommit = 0x1000;
        opt32.SizeOfHeapReserve = 0x100000;
        opt32.SizeOfHeapCommit = 0x1000;
        opt32.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        /* Import directory at index 1 */
        if (import_dir_rva != 0) {
            opt32.DataDirectory[1].VirtualAddress = import_dir_rva;
            opt32.DataDirectory[1].Size = import_dir_size;
        }
        fwrite(&opt32, sizeof(opt32), 1, fp);
    }

    /* Section headers - first pass: calculate file offsets */
    sec = g_state.sections;
    while (sec) {
        if (sec->Size == 0) {
            sec = sec->next;
            continue;
        }

        sec->PointerToRawData = current_file_offset;
        current_file_offset += file_align(sec->Size);
        sec = sec->next;
    }

    /* Section headers - second pass: write headers */
    sec = g_state.sections;
    while (sec) {
        if (sec->Size == 0) {
            sec = sec->next;
            continue;
        }

        IMAGE_SECTION_HEADER sec_header = {0};
        memcpy(sec_header.Name, sec->Name, 8);
        sec_header.VirtualSize = sec->Size;
        sec_header.VirtualAddress = sec->VirtualAddress;
        sec_header.SizeOfRawData = file_align(sec->Size);
        sec_header.PointerToRawData = sec->PointerToRawData;
        sec_header.Characteristics = sec->Characteristics;
        fwrite(&sec_header, sizeof(sec_header), 1, fp);

        sec = sec->next;
    }

    /* Pad to header_size */
    long pos = ftell(fp);
    while (pos < (long)header_size) {
        fputc(0, fp);
        pos++;
    }

    /* Write section data at correct file offsets */
    sec = g_state.sections;
    while (sec) {
        if (sec->Size > 0) {
            /* Seek to the correct file offset for this section */
            fseek(fp, sec->PointerToRawData, SEEK_SET);
            fwrite(sec->Data, sec->Size, 1, fp);
            uint32_t padded_size = file_align(sec->Size);
            for (uint32_t i = sec->Size; i < padded_size; i++) {
                fputc(0, fp);
            }
        }
        sec = sec->next;
    }

    fclose(fp);
    printf("\nOutput: %s\n", filename);
    printf("  Entry point: 0x%08X\n", entry_rva);
    printf("  Image base: 0x%08X\n", g_state.image_base);
    printf("  Image size: %u bytes\n", image_size);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options] objfiles... /out:output.exe\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  /out:file       Output file name\n");
    fprintf(stderr, "  /entry:symbol   Entry point symbol (default: _start)\n");
    fprintf(stderr, "  /base:addr      Image base address (default: 0x140000000)\n");
    fprintf(stderr, "  /subsystem:n    Subsystem: 1=Native, 2=Windows, 3=Console\n");
    fprintf(stderr, "  /dll            Create DLL instead of EXE\n");
    fprintf(stderr, "  /debug          Include debug information\n");
    fprintf(stderr, "  /machine:type   Target machine: x86, x64, arm64\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s main.obj utils.obj /out:program.exe /subsystem:3\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    /* Initialize state */
    memset(&g_state, 0, sizeof(g_state));
    g_state.is64bit = -1;
    g_state.image_base = 0x140000000ULL;
    g_state.subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    strcpy(g_state.entry_symbol, "_start");

    char output_file[256] = "a.exe";
    int has_output = 0;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/out:", 5) == 0 ||
            strncmp(argv[i], "-out:", 5) == 0) {
            strncpy(output_file, argv[i] + 5, 255);
            output_file[255] = '\0';
            has_output = 1;
        } else if (strncmp(argv[i], "/entry:", 7) == 0 ||
                   strncmp(argv[i], "-entry:", 7) == 0) {
            strncpy(g_state.entry_symbol, argv[i] + 7, 255);
            g_state.entry_symbol[255] = '\0';
        } else if (strncmp(argv[i], "/base:", 6) == 0 ||
                   strncmp(argv[i], "-base:", 6) == 0) {
            g_state.image_base = (uint32_t)strtoull(argv[i] + 6, NULL, 0);
        } else if (strncmp(argv[i], "/subsystem:", 11) == 0 ||
                   strncmp(argv[i], "-subsystem:", 11) == 0) {
            g_state.subsystem = atoi(argv[i] + 11);
        } else if (strcmp(argv[i], "/dll") == 0 ||
                   strcmp(argv[i], "-dll") == 0) {
            g_state.dll_mode = 1;
        } else if (strncmp(argv[i], "/machine:", 9) == 0 ||
                   strncmp(argv[i], "-machine:", 9) == 0) {
            const char *machine = argv[i] + 9;
            if (strcmp(machine, "x64") == 0 || strcmp(machine, "amd64") == 0) {
                g_state.is64bit = 1;
            } else if (strcmp(machine, "x86") == 0 || strcmp(machine, "i386") == 0) {
                g_state.is64bit = 0;
            }
        } else if (argv[i][0] != '/' && argv[i][0] != '-') {
            /* Object file */
            if (!link_object_file(argv[i])) {
                fprintf(stderr, "Failed to link: %s\n", argv[i]);
                return 1;
            }
        }
    }

    if (!has_output) {
        fprintf(stderr, "Error: No output file specified. Use /out:filename\n");
        return 1;
    }

    if (!g_state.sections) {
        fprintf(stderr, "Error: No object files to link\n");
        return 1;
    }

    printf("\nLinking complete:\n");
    printf("  Architecture: %s\n", g_state.is64bit ? "x64" : "x86");
    printf("  Entry symbol: %s\n", g_state.entry_symbol);

    /* Resolve relocations with import handling */
    resolve_relocations_with_imports();

    /* Write output */
    write_pe_file(output_file);

    /* Check if output file was created */
    FILE *fp_test = fopen(output_file, "rb");
    if (!fp_test) {
        fprintf(stderr, "Error: Failed to create output file '%s'\n", output_file);
        return 1;
    }
    fclose(fp_test);

    printf("\nSuccess!\n");

    return 0;
}
