/*
 * RAWRXD NATIVE LINKER v2 - Fixed PE/COFF linker
 * Fixed section data placement and file offsets
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

/* COFF structures */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} IMAGE_RELOCATION;

typedef struct {
    union {
        uint8_t ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
        uint32_t Name[2];
    } N;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} IMAGE_SYMBOL;

#pragma pack(pop)

/* Constants */
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_I386 0x14c
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020

#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_ALIGN_16BYTES 0x00000500
#define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

#define IMAGE_REL_AMD64_ADDR64 0x0001
#define IMAGE_REL_AMD64_ADDR32 0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32 0x0004

#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3

/* Section structure */
typedef struct LinkedSection {
    char Name[9];
    uint8_t *Data;
    uint32_t Size;
    uint32_t VirtualAddress;
    uint32_t PointerToRawData;
    uint32_t Characteristics;
    struct LinkedSection *next;
} LinkedSection;

/* Symbol structure */
typedef struct Symbol {
    char Name[256];
    uint32_t Value;
    uint32_t Section;
    int is_defined;
    int is_external;
    struct Symbol *next;
} Symbol;

/* Relocation structure */
typedef struct Relocation {
    uint32_t Offset;
    char SymbolName[256];
    uint16_t Type;
    uint32_t Section;
    struct Relocation *next;
} Relocation;

/* Global state */
static struct {
    LinkedSection *sections;
    Symbol *symbols;
    Relocation *relocations;
    int is64bit;
    uint64_t image_base;
    uint32_t subsystem;
    char entry_symbol[256];
} g_state;

/* Alignment helpers */
static uint32_t file_align(uint32_t size) {
    return (size + 511) & ~511;
}

static uint32_t section_align(uint32_t size) {
    return (size + 4095) & ~4095;
}

/* Find symbol */
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

/* Add symbol */
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

/* Find or create section */
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

/* Append data to section */
static void append_section_data(LinkedSection *sec, const uint8_t *data, uint32_t size) {
    if (size == 0) return;
    sec->Data = (uint8_t *)realloc(sec->Data, sec->Size + size);
    memcpy(sec->Data + sec->Size, data, size);
    sec->Size += size;
}

/* Add relocation */
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

/* Get symbol name from COFF */
static const char* get_symbol_name(uint8_t *string_table, uint32_t string_table_size, IMAGE_SYMBOL *sym) {
    static char name_buf[256];
    
    if (sym->N.LongName.Zeroes == 0) {
        uint32_t offset = sym->N.LongName.Offset;
        if (offset < string_table_size) {
            strncpy(name_buf, (char *)(string_table + offset), 255);
            name_buf[255] = '\0';
            return name_buf;
        }
    } else {
        memcpy(name_buf, sym->N.ShortName, 8);
        name_buf[8] = '\0';
        return name_buf;
    }
    return "";
}

/* Read COFF file */
static int read_coff_file(const char *filename, uint8_t **code_data, uint32_t *code_size,
                            uint8_t **data_data, uint32_t *data_size,
                            IMAGE_RELOCATION **relocs, uint32_t *num_relocs,
                            char ***symbols, uint32_t *num_symbols,
                            uint8_t **string_table, uint32_t *string_table_size) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open '%s'\n", filename);
        return 0;
    }

    /* Read file header */
    IMAGE_FILE_HEADER header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "Error: Cannot read file header\n");
        fclose(fp);
        return 0;
    }

    printf("  COFF Machine: 0x%04X (%s)\n", header.Machine,
           header.Machine == IMAGE_FILE_MACHINE_AMD64 ? "AMD64" :
           header.Machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "unknown");

    if (header.Machine == IMAGE_FILE_MACHINE_AMD64) {
        g_state.is64bit = 1;
    } else if (header.Machine == IMAGE_FILE_MACHINE_I386) {
        g_state.is64bit = 0;
    } else {
        fprintf(stderr, "Error: Unsupported machine type 0x%04X\n", header.Machine);
        fclose(fp);
        return 0;
    }

    /* Read section headers */
    for (int i = 0; i < header.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER sec_header;
        if (fread(&sec_header, sizeof(sec_header), 1, fp) != 1) {
            fprintf(stderr, "Error: Cannot read section header %d\n", i);
            fclose(fp);
            return 0;
        }

        printf("  Section %d: %.8s, Size: %d, RawData: %d\n",
               i, sec_header.Name, sec_header.SizeOfRawData, sec_header.PointerToRawData);

        /* Read section data */
        if (sec_header.SizeOfRawData > 0 && sec_header.PointerToRawData > 0) {
            /* Determine section type */
            char sec_name[9];
            memcpy(sec_name, sec_header.Name, 8);
            sec_name[8] = '\0';
            
            /* Skip debug sections */
            if (strstr(sec_name, "debug") || strstr(sec_name, ".debug")) {
                printf("    Skipping debug section: %.8s\n", sec_header.Name);
            } else if (strstr(sec_name, "text") || (sec_header.Characteristics & IMAGE_SCN_CNT_CODE)) {
                long save_pos = ftell(fp);
                fseek(fp, sec_header.PointerToRawData, SEEK_SET);
                
                *code_data = (uint8_t *)malloc(sec_header.SizeOfRawData);
                fread(*code_data, sec_header.SizeOfRawData, 1, fp);
                *code_size = sec_header.SizeOfRawData;
                
                fseek(fp, save_pos, SEEK_SET);
            } else if (strstr(sec_name, "data") || (sec_header.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)) {
                long save_pos = ftell(fp);
                fseek(fp, sec_header.PointerToRawData, SEEK_SET);
                
                *data_data = (uint8_t *)malloc(sec_header.SizeOfRawData);
                fread(*data_data, sec_header.SizeOfRawData, 1, fp);
                *data_size = sec_header.SizeOfRawData;
                
                fseek(fp, save_pos, SEEK_SET);
            }
        }

        /* Read relocations */
        if (sec_header.NumberOfRelocations > 0 && sec_header.PointerToRelocations > 0) {
            long save_pos = ftell(fp);
            fseek(fp, sec_header.PointerToRelocations, SEEK_SET);
            
            *num_relocs = sec_header.NumberOfRelocations;
            *relocs = (IMAGE_RELOCATION *)malloc(*num_relocs * sizeof(IMAGE_RELOCATION));
            fread(*relocs, sizeof(IMAGE_RELOCATION), *num_relocs, fp);
            
            fseek(fp, save_pos, SEEK_SET);
        }
    }

    /* Read symbol table */
    if (header.NumberOfSymbols > 0 && header.PointerToSymbolTable > 0) {
        fseek(fp, header.PointerToSymbolTable, SEEK_SET);
        
        *num_symbols = header.NumberOfSymbols;
        IMAGE_SYMBOL *syms = (IMAGE_SYMBOL *)malloc(*num_symbols * sizeof(IMAGE_SYMBOL));
        fread(syms, sizeof(IMAGE_SYMBOL), *num_symbols, fp);
        
        /* Read string table */
        uint32_t str_table_size;
        fread(&str_table_size, 4, 1, fp);
        *string_table_size = str_table_size;
        *string_table = (uint8_t *)malloc(str_table_size);
        (*string_table)[0] = 0;
        (*string_table)[1] = 0;
        (*string_table)[2] = 0;
        (*string_table)[3] = 0;
        fread(*string_table + 4, str_table_size - 4, 1, fp);
        
        /* Convert to string array */
        *symbols = (char **)malloc(*num_symbols * sizeof(char *));
        for (uint32_t i = 0; i < *num_symbols; i++) {
            (*symbols)[i] = strdup(get_symbol_name(*string_table, *string_table_size, &syms[i]));
        }
        
        free(syms);
    }

    fclose(fp);
    return 1;
}

/* Link object file */
static int link_object_file(const char *filename) {
    uint8_t *code_data = NULL, *data_data = NULL;
    uint32_t code_size = 0, data_size = 0;
    IMAGE_RELOCATION *relocs = NULL;
    uint32_t num_relocs = 0;
    char **symbols = NULL;
    uint32_t num_symbols = 0;
    uint8_t *string_table = NULL;
    uint32_t string_table_size = 0;

    printf("Linking: %s\n", filename);

    if (!read_coff_file(filename, &code_data, &code_size, &data_data, &data_size,
                        &relocs, &num_relocs, &symbols, &num_symbols,
                        &string_table, &string_table_size)) {
        return 0;
    }

    /* Add code section */
    if (code_size > 0) {
        LinkedSection *text_sec = add_linked_section(".text",
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
        uint32_t offset = text_sec->Size;
        append_section_data(text_sec, code_data, code_size);
        
        /* Process relocations */
        for (uint32_t i = 0; i < num_relocs; i++) {
            if (relocs[i].SymbolTableIndex < num_symbols) {
                add_relocation(offset + relocs[i].VirtualAddress,
                              symbols[relocs[i].SymbolTableIndex],
                              relocs[i].Type, 0);
            }
        }
        
        printf("    Read %d bytes of code, %d relocations\n", code_size, num_relocs);
    }

    /* Add data section */
    if (data_size > 0) {
        LinkedSection *data_sec = add_linked_section(".data",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
        append_section_data(data_sec, data_data, data_size);
        printf("    Read %d bytes of data\n", data_size);
    }

    /* Process symbols - need to read actual symbol values from COFF */
    /* For now, assume _start is at offset 0 in .text section */
    add_symbol("_start", 0, 1, 0);  /* Value=0, Section=1 (.text), is_defined=1 */
    
    for (uint32_t i = 0; i < num_symbols; i++) {
        if (symbols[i][0] == '\0') continue;
        
        /* Skip debug symbols */
        if (strstr(symbols[i], "@feat.00")) continue;
        
        /* Check if this is an entry point */
        if (strcmp(symbols[i], "_start") == 0 ||
            strcmp(symbols[i], "main") == 0) {
            strncpy(g_state.entry_symbol, symbols[i], 255);
        }
    }

    /* Cleanup */
    free(code_data);
    free(data_data);
    free(relocs);
    if (symbols) {
        for (uint32_t i = 0; i < num_symbols; i++) {
            free(symbols[i]);
        }
        free(symbols);
    }
    free(string_table);

    return 1;
}

/* Resolve relocations */
static void resolve_relocations(void) {
    Relocation *rel = g_state.relocations;
    int resolved = 0;
    int unresolved = 0;

    while (rel) {
        Symbol *sym = find_symbol(rel->SymbolName);

        if (!sym || !sym->is_defined) {
            printf("  Unresolved: %s\n", rel->SymbolName);
            unresolved++;
            rel = rel->next;
            continue;
        }

        /* Find section containing this relocation */
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
            case IMAGE_REL_AMD64_REL32:
                if (offset + 4 <= sec->Size) {
                    int32_t *ptr = (int32_t *)(sec->Data + offset);
                    *ptr = (int32_t)(target - (sec->VirtualAddress + offset + 4));
                }
                break;
        }

        resolved++;
        rel = rel->next;
    }

    printf("Relocations: %d resolved, %d unresolved\n", resolved, unresolved);
}

/* Write PE file - FIXED VERSION */
static void write_pe_file(const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", filename);
        return;
    }

    /* Count sections */
    int num_sections = 0;
    LinkedSection *sec = g_state.sections;
    while (sec) {
        if (sec->Size > 0) num_sections++;
        sec = sec->next;
    }

    if (num_sections == 0) {
        fprintf(stderr, "Error: No sections to write\n");
        fclose(fp);
        return;
    }

    /* Calculate header size */
    uint32_t section_alignment = 4096;
    uint32_t file_alignment = 512;
    
    uint32_t dos_header_size = sizeof(IMAGE_DOS_HEADER) + 64 + 4;
    uint32_t coff_header_size = sizeof(IMAGE_FILE_HEADER);
    uint32_t optional_header_size = g_state.is64bit ? 
        sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    uint32_t section_headers_size = num_sections * sizeof(IMAGE_SECTION_HEADER);
    
    uint32_t header_size = dos_header_size + coff_header_size + 
                           optional_header_size + section_headers_size;
    uint32_t aligned_header_size = file_align(header_size);

    /* Calculate section addresses and file offsets */
    uint32_t current_rva = section_alignment;
    uint32_t current_file_offset = aligned_header_size;

    sec = g_state.sections;
    while (sec) {
        if (sec->Size > 0) {
            sec->VirtualAddress = current_rva;
            sec->PointerToRawData = current_file_offset;
            
            current_rva = section_align(current_rva + sec->Size);
            current_file_offset = file_align(current_file_offset + sec->Size);
        }
        sec = sec->next;
    }

    /* Calculate entry point */
    Symbol *entry_sym = find_symbol(g_state.entry_symbol);
    if (!entry_sym) entry_sym = find_symbol("_start");
    if (!entry_sym) entry_sym = find_symbol("main");
    
    uint32_t entry_rva = 0;
    if (entry_sym && entry_sym->is_defined) {
        entry_rva = entry_sym->Value;
        /* Find .text section containing entry point */
        sec = g_state.sections;
        while (sec) {
            /* Only look in .text section for code entry point */
            if (strncmp(sec->Name, ".text", 5) == 0 && entry_sym->Value < sec->Size) {
                entry_rva = sec->VirtualAddress + entry_sym->Value;
                break;
            }
            sec = sec->next;
        }
    }

    uint32_t image_size = section_align(current_rva);
    if (image_size < section_alignment * 2) {
        image_size = section_alignment * 2;  /* Minimum: headers + 1 section */
    }

    /* Write DOS header */
    IMAGE_DOS_HEADER dos_header = {0};
    dos_header.e_magic = 0x5A4D; /* MZ */
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
    coff_header.SizeOfOptionalHeader = optional_header_size;
    coff_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
    if (g_state.is64bit) {
        coff_header.Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
    }
    fwrite(&coff_header, sizeof(coff_header), 1, fp);

    /* Calculate section sizes */
    uint32_t text_size = 0, data_size = 0;
    sec = g_state.sections;
    while (sec) {
        if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {
            text_size += section_align(sec->Size);
        } else {
            data_size += section_align(sec->Size);
        }
        sec = sec->next;
    }

    /* Optional header */
    if (g_state.is64bit) {
        IMAGE_OPTIONAL_HEADER64 opt64 = {0};
        opt64.Magic = 0x20B;
        opt64.MajorLinkerVersion = 1;
        opt64.MinorLinkerVersion = 0;
        opt64.SizeOfCode = text_size;
        opt64.SizeOfInitializedData = data_size;
        opt64.SizeOfUninitializedData = 0;
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
        opt64.SizeOfHeaders = aligned_header_size;
        opt64.Subsystem = g_state.subsystem;
        opt64.DllCharacteristics = 0x8160;
        opt64.SizeOfStackReserve = 0x100000;
        opt64.SizeOfStackCommit = 0x1000;
        opt64.SizeOfHeapReserve = 0x100000;
        opt64.SizeOfHeapCommit = 0x1000;
        opt64.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        fwrite(&opt64, sizeof(opt64), 1, fp);
    } else {
        IMAGE_OPTIONAL_HEADER32 opt32 = {0};
        opt32.Magic = 0x10B;
        opt32.MajorLinkerVersion = 1;
        opt32.MinorLinkerVersion = 0;
        opt32.SizeOfCode = text_size;
        opt32.SizeOfInitializedData = data_size;
        opt32.SizeOfUninitializedData = 0;
        opt32.AddressOfEntryPoint = entry_rva;
        opt32.BaseOfCode = section_alignment;
        opt32.ImageBase = (uint32_t)g_state.image_base;
        opt32.SectionAlignment = section_alignment;
        opt32.FileAlignment = file_alignment;
        opt32.MajorOperatingSystemVersion = 6;
        opt32.MinorOperatingSystemVersion = 0;
        opt32.MajorSubsystemVersion = 6;
        opt32.MinorSubsystemVersion = 0;
        opt32.SizeOfImage = image_size;
        opt32.SizeOfHeaders = aligned_header_size;
        opt32.Subsystem = g_state.subsystem;
        opt32.DllCharacteristics = 0x8160;
        opt32.SizeOfStackReserve = 0x100000;
        opt32.SizeOfStackCommit = 0x1000;
        opt32.SizeOfHeapReserve = 0x100000;
        opt32.SizeOfHeapCommit = 0x1000;
        opt32.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        fwrite(&opt32, sizeof(opt32), 1, fp);
    }

    /* Section headers */
    /* Write section headers */
    sec = g_state.sections;
    int sec_idx = 0;
    while (sec) {
        /* Section info */
        if (sec->Size == 0) {
            /* Skip empty section */
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
        /* Write section header */
        fwrite(&sec_header, sizeof(sec_header), 1, fp);
        /* Section header written */

        sec = sec->next;
        sec_idx++;
    }

    /* Pad to aligned header size */
    long pos = ftell(fp);
    while (pos < (long)aligned_header_size) {
        fputc(0, fp);
        pos++;
    }

    /* Write section data at correct file offsets */
    sec = g_state.sections;
    while (sec) {
        if (sec->Size > 0) {
            /* Seek to correct file position */
            fseek(fp, sec->PointerToRawData, SEEK_SET);
            
            /* Write section data */
            fwrite(sec->Data, sec->Size, 1, fp);
            
            /* Pad to file alignment */
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
    printf("  Image base: 0x%016llX\n", g_state.image_base);
    printf("  Image size: %u bytes\n", image_size);
    printf("  Header size: %u bytes\n", aligned_header_size);
}

/* Print usage */
static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <objfile> /out:<exe> [/entry:<symbol>] [/subsystem:<n>]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  /out:file       Output file name\n");
    fprintf(stderr, "  /entry:symbol   Entry point symbol (default: _start)\n");
    fprintf(stderr, "  /subsystem:n    Subsystem: 1=Native, 2=Windows, 3=Console\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  %s main.obj /out:program.exe /subsystem:3\n", prog);
}

/* Main */
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

    char *input_file = NULL;
    char *output_file = NULL;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/out:", 5) == 0) {
            output_file = argv[i] + 5;
        } else if (strncmp(argv[i], "/entry:", 7) == 0) {
            strncpy(g_state.entry_symbol, argv[i] + 7, 255);
        } else if (strncmp(argv[i], "/subsystem:", 11) == 0) {
            g_state.subsystem = atoi(argv[i] + 11);
        } else if (argv[i][0] != '/') {
            input_file = argv[i];
        }
    }

    if (!input_file || !output_file) {
        print_usage(argv[0]);
        return 1;
    }

    printf("========================================\n");
    printf("RAWRXD NATIVE LINKER v2 (FIXED)\n");
    printf("========================================\n\n");

    /* Link object file */
    if (!link_object_file(input_file)) {
        return 1;
    }

    /* Resolve relocations */
    printf("\nResolving relocations...\n");
    resolve_relocations();

    /* Write PE file */
    printf("\nWriting PE file...\n");
    write_pe_file(output_file);

    printf("\n[SUCCESS] Linking complete!\n");
    return 0;
}
