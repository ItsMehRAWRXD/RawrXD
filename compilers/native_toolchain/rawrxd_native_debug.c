/*
 * RAWRXD NATIVE DEBUG SYMBOL WRITER
 * Creates debug information for executables
 * Alternative to Microsoft PDB format - uses DWARF-like or CodeView format
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>

#pragma pack(push, 1)

/* CodeView debug format structures */
#define CV_SIGNATURE_C13 0x53445352  /* 'RSDS' */

/* GUID structure */
typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID;

/* Debug directory entry in PE */
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
} IMAGE_DEBUG_DIRECTORY;

/* Debug types */
#define IMAGE_DEBUG_TYPE_UNKNOWN     0
#define IMAGE_DEBUG_TYPE_COFF        1
#define IMAGE_DEBUG_TYPE_CODEVIEW    2
#define IMAGE_DEBUG_TYPE_FPO         3
#define IMAGE_DEBUG_TYPE_MISC        4
#define IMAGE_DEBUG_TYPE_EXCEPTION   5
#define IMAGE_DEBUG_TYPE_FIXUP       6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC 7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC 8
#define IMAGE_DEBUG_TYPE_BORLAND     9
#define IMAGE_DEBUG_TYPE_RESERVED10  10
#define IMAGE_DEBUG_TYPE_CLSID       11
#define IMAGE_DEBUG_TYPE_VC_FEATURE  12
#define IMAGE_DEBUG_TYPE_POGO        13
#define IMAGE_DEBUG_TYPE_ILTCG       14
#define IMAGE_DEBUG_TYPE_MPX         15
#define IMAGE_DEBUG_TYPE_REPRO       16
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20

/* CodeView PDB 7.0 header */
typedef struct {
    uint32_t cvSignature;
    GUID signature;
    uint32_t age;
    char pdbFileName[1];  /* Variable length */
} CV_INFO_PDB70;

/* Line number info */
typedef struct {
    uint32_t offset;
    uint16_t line_number;
    uint16_t file_index;
} LineNumberEntry;

/* Source file info */
typedef struct SourceFile {
    char path[512];
    uint32_t file_index;
    LineNumberEntry* lines;
    uint32_t line_count;
    uint32_t line_capacity;
    struct SourceFile* next;
} SourceFile;

/* Symbol info */
typedef struct SymbolInfo {
    char name[256];
    uint32_t rva;
    uint32_t size;
    uint16_t section;
    uint8_t type;  /* 0=func, 1=data, 2=label */
    struct SymbolInfo* next;
} SymbolInfo;

/* Debug state */
typedef struct {
    char exe_file[256];
    char pdb_file[256];
    char exe_dir[512];
    SourceFile* files;
    SymbolInfo* symbols;
    uint32_t image_base;
    uint32_t timestamp;
    int is64bit;
} DebugState;

static DebugState g_state;

#pragma pack(pop)

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static void generate_guid(GUID* guid) {
    srand((unsigned)time(NULL));
    guid->Data1 = ((uint32_t)rand() << 16) | (uint32_t)rand();
    guid->Data2 = (uint16_t)rand();
    guid->Data3 = (uint16_t)rand();
    for (int i = 0; i < 8; i++) {
        guid->Data4[i] = (uint8_t)(rand() & 0xFF);
    }
    /* Set version bits */
    guid->Data3 = (guid->Data3 & 0x0FFF) | 0x4000;
    guid->Data4[0] = (guid->Data4[0] & 0x3F) | 0x80;
}

static const char* get_filename(const char* path) {
    const char* last = path;
    const char* p = path;
    while (*p) {
        if (*p == '\\' || *p == '/') last = p + 1;
        p++;
    }
    return last;
}

static void get_directory(const char* path, char* dir, size_t size) {
    strncpy(dir, path, size);
    dir[size - 1] = '\0';
    char* last = NULL;
    char* p = dir;
    while (*p) {
        if (*p == '\\' || *p == '/') last = p;
        p++;
    }
    if (last) *last = '\0';
}

/* ============================================================================
 * SOURCE FILE MANAGEMENT
 * ============================================================================ */

static SourceFile* find_or_create_file(const char* path) {
    SourceFile* file = g_state.files;
    while (file) {
        if (strcmp(file->path, path) == 0) return file;
        file = file->next;
    }

    file = (SourceFile*)calloc(1, sizeof(SourceFile));
    strncpy(file->path, path, 511);
    file->file_index = 0;
    file->line_capacity = 100;
    file->lines = (LineNumberEntry*)calloc(file->line_capacity, sizeof(LineNumberEntry));
    file->next = g_state.files;
    g_state.files = file;
    return file;
}

static void add_line_number(const char* file_path, uint32_t offset, uint16_t line) {
    SourceFile* file = find_or_create_file(file_path);
    
    if (file->line_count >= file->line_capacity) {
        file->line_capacity *= 2;
        file->lines = (LineNumberEntry*)realloc(file->lines, 
            file->line_capacity * sizeof(LineNumberEntry));
    }
    
    file->lines[file->line_count].offset = offset;
    file->lines[file->line_count].line_number = line;
    file->lines[file->line_count].file_index = file->file_index;
    file->line_count++;
}

static void add_symbol(const char* name, uint32_t rva, uint32_t size, uint16_t section, uint8_t type) {
    SymbolInfo* sym = (SymbolInfo*)calloc(1, sizeof(SymbolInfo));
    strncpy(sym->name, name, 255);
    sym->rva = rva;
    sym->size = size;
    sym->section = section;
    sym->type = type;
    sym->next = g_state.symbols;
    g_state.symbols = sym;
}

/* ============================================================================
 * PDB FILE GENERATION (Simplified format)
 * ============================================================================ */

/* RawrXD Debug Format (RDF) - Custom debug format */
#define RDF_SIGNATURE 0x46445252  /* 'RDF\0' */
#define RDF_VERSION_MAJOR 1
#define RDF_VERSION_MINOR 0

typedef struct {
    uint32_t signature;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t timestamp;
    uint32_t image_base;
    uint32_t symbol_count;
    uint32_t file_count;
    uint32_t string_table_size;
    uint32_t flags;
    GUID guid;
} RDF_HEADER;

typedef struct {
    uint32_t name_offset;  /* Offset into string table */
    uint32_t rva;
    uint32_t size;
    uint16_t section;
    uint8_t type;
    uint8_t reserved;
} RDF_SYMBOL;

typedef struct {
    uint32_t path_offset;  /* Offset into string table */
    uint32_t line_count;
    uint32_t line_offset;  /* Offset to line number array */
} RDF_FILE;

typedef struct {
    uint32_t offset;
    uint16_t line_number;
    uint16_t column;
} RDF_LINE;

static int write_pdb_file(const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create PDB '%s'\n", filename);
        return 0;
    }

    /* Count symbols and files */
    uint32_t symbol_count = 0;
    SymbolInfo* sym = g_state.symbols;
    while (sym) { symbol_count++; sym = sym->next; }
    
    uint32_t file_count = 0;
    uint32_t total_lines = 0;
    SourceFile* file = g_state.files;
    while (file) { 
        file_count++; 
        total_lines += file->line_count;
        file = file->next; 
    }

    /* Build string table */
    uint32_t string_table_size = 1;  /* Start with null terminator */
    sym = g_state.symbols;
    while (sym) { 
        string_table_size += strlen(sym->name) + 1; 
        sym = sym->next; 
    }
    file = g_state.files;
    while (file) { 
        string_table_size += strlen(file->path) + 1; 
        file = file->next; 
    }

    /* Calculate offsets */
    uint32_t header_size = sizeof(RDF_HEADER);
    uint32_t symbol_table_offset = header_size;
    uint32_t file_table_offset = symbol_table_offset + symbol_count * sizeof(RDF_SYMBOL);
    uint32_t line_table_offset = file_table_offset + file_count * sizeof(RDF_FILE);
    uint32_t string_table_offset = line_table_offset + total_lines * sizeof(RDF_LINE);
    uint32_t total_size = string_table_offset + string_table_size;

    /* Write header */
    RDF_HEADER header = {0};
    header.signature = RDF_SIGNATURE;
    header.version_major = RDF_VERSION_MAJOR;
    header.version_minor = RDF_VERSION_MINOR;
    header.timestamp = g_state.timestamp;
    header.image_base = g_state.image_base;
    header.symbol_count = symbol_count;
    header.file_count = file_count;
    header.string_table_size = string_table_size;
    header.flags = g_state.is64bit ? 1 : 0;
    generate_guid(&header.guid);
    fwrite(&header, sizeof(header), 1, fp);

    /* Write symbol table */
    uint32_t string_offset = 1;  /* Skip first null byte */
    sym = g_state.symbols;
    while (sym) {
        RDF_SYMBOL rsym = {0};
        rsym.name_offset = string_offset;
        rsym.rva = sym->rva;
        rsym.size = sym->size;
        rsym.section = sym->section;
        rsym.type = sym->type;
        fwrite(&rsym, sizeof(rsym), 1, fp);
        string_offset += strlen(sym->name) + 1;
        sym = sym->next;
    }

    /* Write file table */
    uint32_t line_offset = 0;
    file = g_state.files;
    while (file) {
        RDF_FILE rfile = {0};
        rfile.path_offset = string_offset;
        rfile.line_count = file->line_count;
        rfile.line_offset = line_offset;
        fwrite(&rfile, sizeof(rfile), 1, fp);
        string_offset += strlen(file->path) + 1;
        line_offset += file->line_count;
        file = file->next;
    }

    /* Write line number tables */
    file = g_state.files;
    while (file) {
        for (uint32_t i = 0; i < file->line_count; i++) {
            RDF_LINE line = {0};
            line.offset = file->lines[i].offset;
            line.line_number = file->lines[i].line_number;
            line.column = 0;
            fwrite(&line, sizeof(line), 1, fp);
        }
        file = file->next;
    }

    /* Write string table */
    fputc('\0', fp);  /* First null byte */
    sym = g_state.symbols;
    while (sym) {
        fwrite(sym->name, strlen(sym->name) + 1, 1, fp);
        sym = sym->next;
    }
    file = g_state.files;
    while (file) {
        fwrite(file->path, strlen(file->path) + 1, 1, fp);
        file = file->next;
    }

    fclose(fp);
    
    printf("PDB file created: %s\n", filename);
    printf("  Symbols: %u\n", symbol_count);
    printf("  Source files: %u\n", file_count);
    printf("  Line numbers: %u\n", total_lines);
    printf("  Size: %u bytes\n", total_size);
    
    return 1;
}

/* ============================================================================
 * DEBUG DIRECTORY INJECTION
 * ============================================================================ */

static int inject_debug_directory(const char* exe_file, const char* pdb_file) {
    /* This would modify the PE file to add a debug directory entry */
    /* For now, we just create the PDB file separately */
    printf("Debug directory injection: %s -> %s\n", exe_file, pdb_file);
    printf("  (PE modification not implemented - PDB created separately)\n");
    return 1;
}

/* ============================================================================
 * MAP FILE GENERATION
 * ============================================================================ */

static int write_map_file(const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create MAP '%s'\n", filename);
        return 0;
    }

    fprintf(fp, " %s\n\n", get_filename(g_state.exe_file));
    fprintf(fp, " Timestamp is %08X\n", g_state.timestamp);
    fprintf(fp, " Preferred load address is %08X\n\n", g_state.image_base);

    /* Write symbols */
    fprintf(fp, " Address         Publics by Value              Rva+Base       Lib:Object\n\n");
    
    SymbolInfo* sym = g_state.symbols;
    while (sym) {
        fprintf(fp, " %04X:%08X       %-30s %08X\n",
                sym->section,
                sym->rva,
                sym->name,
                g_state.image_base + sym->rva);
        sym = sym->next;
    }

    /* Write line numbers */
    fprintf(fp, "\nLine numbers for %s\n\n", get_filename(g_state.exe_file));
    
    SourceFile* file = g_state.files;
    while (file) {
        fprintf(fp, "%s\n", file->path);
        for (uint32_t i = 0; i < file->line_count; i++) {
            fprintf(fp, "    %u %08X\n", 
                    file->lines[i].line_number,
                    file->lines[i].offset);
        }
        file = file->next;
    }

    fclose(fp);
    printf("MAP file created: %s\n", filename);
    return 1;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] /exe:executable.exe\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  /exe:file           Executable file to generate debug info for\n");
    fprintf(stderr, "  /out:pdbfile        Output PDB file (default: exe_name.pdb)\n");
    fprintf(stderr, "  /map:mapfile        Output MAP file\n");
    fprintf(stderr, "  /base:addr          Image base address\n");
    fprintf(stderr, "  /64                 Target is 64-bit\n");
    fprintf(stderr, "\nDebug Info Commands:\n");
    fprintf(stderr, "  /addsym:name,rva    Add symbol (can be used multiple times)\n");
    fprintf(stderr, "  /addline:file,line,offset  Add line number\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s /exe:myapp.exe /out:myapp.pdb\n", prog);
    fprintf(stderr, "  %s /exe:myapp.exe /map:myapp.map\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /* Defaults */
    g_state.timestamp = (uint32_t)time(NULL);
    g_state.image_base = 0x00400000;
    g_state.is64bit = 0;

    char* exe_file = NULL;
    char pdb_file[256] = {0};
    char map_file[256] = {0};

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "/exe:", 5) == 0 || strncmp(argv[i], "-exe:", 5) == 0) {
            exe_file = argv[i] + 5;
            strncpy(g_state.exe_file, exe_file, 255);
        } else if (strncmp(argv[i], "/out:", 5) == 0 || strncmp(argv[i], "-out:", 5) == 0) {
            strncpy(pdb_file, argv[i] + 5, 255);
        } else if (strncmp(argv[i], "/map:", 5) == 0 || strncmp(argv[i], "-map:", 5) == 0) {
            strncpy(map_file, argv[i] + 5, 255);
        } else if (strncmp(argv[i], "/base:", 6) == 0) {
            g_state.image_base = (uint32_t)strtoul(argv[i] + 6, NULL, 0);
        } else if (strcmp(argv[i], "/64") == 0) {
            g_state.is64bit = 1;
        } else if (strncmp(argv[i], "/addsym:", 8) == 0) {
            /* Parse symbol: name,rva */
            char buf[512];
            strncpy(buf, argv[i] + 8, 511);
            char* comma = strchr(buf, ',');
            if (comma) {
                *comma = '\0';
                uint32_t rva = (uint32_t)strtoul(comma + 1, NULL, 0);
                add_symbol(buf, rva, 0, 1, 0);
            }
        } else if (strncmp(argv[i], "/addline:", 9) == 0) {
            /* Parse line: file,line,offset */
            char buf[512];
            strncpy(buf, argv[i] + 9, 511);
            char* comma1 = strchr(buf, ',');
            if (comma1) {
                *comma1 = '\0';
                char* comma2 = strchr(comma1 + 1, ',');
                if (comma2) {
                    *comma2 = '\0';
                    uint16_t line = (uint16_t)atoi(comma1 + 1);
                    uint32_t offset = (uint32_t)strtoul(comma2 + 1, NULL, 0);
                    add_line_number(buf, offset, line);
                }
            }
        }
    }

    if (!exe_file) {
        fprintf(stderr, "Error: No executable file specified. Use /exe:filename\n");
        return 1;
    }

    /* Generate default output filenames */
    if (!pdb_file[0]) {
        strncpy(pdb_file, exe_file, 255);
        char* dot = strrchr(pdb_file, '.');
        if (dot) strcpy(dot, ".pdb");
        else strcat(pdb_file, ".pdb");
    }

    if (!map_file[0]) {
        strncpy(map_file, exe_file, 255);
        char* dot = strrchr(map_file, '.');
        if (dot) strcpy(dot, ".map");
        else strcat(map_file, ".map");
    }

    /* Generate debug files */
    if (!write_pdb_file(pdb_file)) {
        return 1;
    }

    if (!write_map_file(map_file)) {
        return 1;
    }

    printf("\nSuccess! Debug information generated.\n");
    return 0;
}
