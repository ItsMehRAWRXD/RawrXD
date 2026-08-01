/*
 * PE32+ writer — DOS stub, PE/COFF headers, optional header, .text, .idata.
 * Fixed: correct header offsets, file alignment, valid import table layout.
 */
#include "pe_writer.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

/* File alignment: on-disk section start offsets (PointerToRawData). Can be 0x200, 0x400, etc. */
#define FILE_ALIGN   0x400   /* 1024 bytes */
/* Section alignment: RVAs (VirtualAddress, DataDirectory, ILT/IAT/hint_name). Must be 4KB for loader. */
#define SEC_ALIGN    0x1000  /* 4 KB */
#define IMAGE_BASE   0x140000000ULL
#define TEXT_RVA     0x1000u
#define IDATA_RVA    0x2000u

#define ALIGN_UP(val, align) (((val) + (align) - 1) & ~((align) - 1))

/* Section characteristics */
#define IMAGE_SCN_CNT_CODE             0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_MEM_EXECUTE          0x20000000
#define IMAGE_SCN_MEM_READ             0x40000000
#define IMAGE_SCN_MEM_WRITE            0x80000000

/* DOS stub: 64 bytes, e_lfanew at 0x3C = 0x40 so PE is at offset 64 */
static const uint8_t dos_stub[64] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00  /* e_lfanew = 0x40 */
};

#pragma pack(push, 1)
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PeCoffHeader;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
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
    struct { uint32_t VirtualAddress; uint32_t Size; } DataDirectory[16];
} PeOptionalHeader64;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLineNumbers;
    uint32_t Characteristics;
} PeSectionHeader;
#pragma pack(pop)

static void w16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)(v >> 8); }
static void w32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF); p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF); p[3] = (uint8_t)(v >> 24);
}

typedef struct {
    char* dll_name;
    char* func_name;
} ImportEntry;

struct PeWriter {
    uint32_t entry_rva;
    uint8_t* text_data;
    uint32_t text_size;
    uint32_t text_cap;
    uint8_t* rdata_data;
    uint32_t rdata_size;
    uint32_t rdata_cap;
    char*    import_dll;   /* Legacy single import */
    char*    import_func;  /* Legacy single import */
    ImportEntry* imports;  /* Multiple imports array */
    int      import_count;
    int      import_cap;
};

PeWriter* pe_writer_create(void) {
    PeWriter* pw = (PeWriter*)calloc(1, sizeof(PeWriter));
    if (!pw) return NULL;
    pw->text_cap = 4096;
    pw->text_data = (uint8_t*)malloc(pw->text_cap);
    if (!pw->text_data) { free(pw); return NULL; }
    return pw;
}

void pe_writer_destroy(PeWriter* pw) {
    if (!pw) return;
    free(pw->text_data);
    free(pw->rdata_data);
    free(pw->import_dll);
    free(pw->import_func);
    if (pw->imports) {
        for (int i = 0; i < pw->import_count; i++) {
            free(pw->imports[i].dll_name);
            free(pw->imports[i].func_name);
        }
        free(pw->imports);
    }
    free(pw);
}

void pe_writer_set_entry(PeWriter* pw, uint32_t entry_rva) { pw->entry_rva = entry_rva; }

void pe_writer_add_text(PeWriter* pw, const uint8_t* data, uint32_t size) {
    if (size == 0) return;
    while (pw->text_size + size > pw->text_cap) {
        pw->text_cap *= 2;
        uint8_t* n = (uint8_t*)realloc(pw->text_data, pw->text_cap);
        if (!n) return;
        pw->text_data = n;
    }
    if (data) memcpy(pw->text_data + pw->text_size, data, size);
    pw->text_size += size;
}

uint32_t pe_writer_add_rdata(PeWriter* pw, const uint8_t* data, uint32_t size) {
    if (size == 0) return 0;
    if (!pw->rdata_data) {
        pw->rdata_cap = 4096;
        pw->rdata_data = (uint8_t*)malloc(pw->rdata_cap);
        if (!pw->rdata_data) return 0;
    }
    while (pw->rdata_size + size > pw->rdata_cap) {
        pw->rdata_cap *= 2;
        uint8_t* n = (uint8_t*)realloc(pw->rdata_data, pw->rdata_cap);
        if (!n) return 0;
        pw->rdata_data = n;
    }
    uint32_t rva = pw->rdata_size; /* Offset within .rdata */
    if (data) memcpy(pw->rdata_data + pw->rdata_size, data, size);
    pw->rdata_size += size;
    return rva;
}

void pe_writer_set_import(PeWriter* pw, const char* dll_name, const char* func_name) {
    free(pw->import_dll);
    free(pw->import_func);
    pw->import_dll = dll_name ? strdup(dll_name) : NULL;
    pw->import_func = func_name ? strdup(func_name) : NULL;
}

int pe_writer_add_import(PeWriter* pw, const char* dll_name, const char* func_name) {
    if (!pw || !dll_name || !func_name) return -1;
    
    /* Grow array if needed */
    if (pw->import_count >= pw->import_cap) {
        int new_cap = pw->import_cap ? pw->import_cap * 2 : 4;
        ImportEntry* new_arr = (ImportEntry*)realloc(pw->imports, new_cap * sizeof(ImportEntry));
        if (!new_arr) return -1;
        pw->imports = new_arr;
        pw->import_cap = new_cap;
    }
    
    /* Add the import */
    pw->imports[pw->import_count].dll_name = strdup(dll_name);
    pw->imports[pw->import_count].func_name = strdup(func_name);
    if (!pw->imports[pw->import_count].dll_name || !pw->imports[pw->import_count].func_name) {
        free(pw->imports[pw->import_count].dll_name);
        free(pw->imports[pw->import_count].func_name);
        return -1;
    }
    
    return pw->import_count++;
}

uint32_t pe_writer_emit(PeWriter* pw, uint8_t** out) {
    if (!pw || !out) return 0;

    const uint32_t dos_size = 64;
    const uint32_t pe_sig_off = dos_size;                    /* 0x40 */
    const uint32_t coff_off = pe_sig_off + 4;                /* 0x44 */
    const uint32_t opt_hdr_size = 240;
    const uint32_t opt_off = coff_off + sizeof(PeCoffHeader); /* 0x58 */
    
    /* Check if we need imports - use new imports array or legacy single import */
    int num_imports = pw->import_count;
    if (num_imports == 0 && pw->import_dll != NULL && pw->import_func != NULL) {
        num_imports = 1;  /* Legacy single import */
    }
    int has_imports = num_imports > 0;
    
    uint32_t num_sections = has_imports ? 2 : 1;
    const uint32_t sect_tbl_off = opt_off + opt_hdr_size;    /* 0x148 */
    const uint32_t sect_tbl_size = num_sections * sizeof(PeSectionHeader);
    const uint32_t headers_end = sect_tbl_off + sect_tbl_size;
    /* File offsets: use FILE_ALIGN so on-disk layout can be 1KB-aligned. */
    const uint32_t headers_raw = ALIGN_UP(headers_end, FILE_ALIGN);

    uint32_t text_size = pw->text_size;
    if (text_size == 0) text_size = 1;
    uint32_t text_size_file = ALIGN_UP(text_size, FILE_ALIGN);
    /* RVAs and virtual sizes: MUST use SEC_ALIGN (4KB). Loader expects 4KB-aligned RVAs. */
    uint32_t text_size_virt = ALIGN_UP(text_size, SEC_ALIGN);

    /* Calculate .idata size based on number of imports */
    /* IDT: 20 bytes per DLL + 20 null entry */
    /* ILT: 8 bytes per import + 8 null terminator */
    /* IAT: 8 bytes per import + 8 null terminator */
    /* Hint/Name: 2 bytes hint + strlen(name)+1 per import */
    /* DLL name: strlen(dll)+1 (one per DLL, assuming all from same DLL) */
    uint32_t idat_content_size = 0;
    uint32_t idt_size = 0, ilt_size = 0, iat_size = 0, hint_name_size = 0, dll_name_size = 0;
    uint32_t idat_size_file = 0, idat_size_virt = 0, idat_rva = 0;
    uint32_t idt_rva = 0, ilt_rva = 0, iat_rva = 0;
    uint32_t hint_name_rva = 0, dll_name_rva = 0;
    uint32_t idat_raw_off = 0;
    
    if (has_imports) {
        /* Get first import for DLL name (assuming all from same DLL) */
        const char* first_dll = pw->import_count > 0 ? pw->imports[0].dll_name : pw->import_dll;
        
        /* Calculate sizes */
        idt_size = 20 + 20;  /* One IDT entry + null terminator */
        ilt_size = (num_imports + 1) * 8;  /* One entry per import + null */
        iat_size = (num_imports + 1) * 8;  /* One entry per import + null */
        
        /* Hint/Name table - each entry is 2-byte hint + name + null, aligned to 2 bytes */
        hint_name_size = 0;
        for (int i = 0; i < num_imports; i++) {
            const char* func_name = pw->import_count > 0 ? pw->imports[i].func_name : pw->import_func;
            uint32_t entry_size = 2 + (uint32_t)strlen(func_name) + 1;  /* hint + name + null */
            /* Each entry must be aligned to 2 bytes */
            if (entry_size % 2 != 0) entry_size++;
            hint_name_size += entry_size;
        }
        
        /* DLL name */
        dll_name_size = (uint32_t)strlen(first_dll) + 1;
        if (dll_name_size % 2 != 0) dll_name_size++;  /* Pad to even */
        
        /* Total .idata size */
        idat_content_size = idt_size + ilt_size + iat_size + hint_name_size + dll_name_size;
        
        idat_size_file = ALIGN_UP(idat_content_size, FILE_ALIGN);
        idat_size_virt = ALIGN_UP(idat_content_size, SEC_ALIGN);
        /* Critical: idat_rva must be section-aligned (e.g. 0x2000), NOT file offset (e.g. 0x800). */
        idat_rva = TEXT_RVA + text_size_virt;
        idt_rva = idat_rva;
        ilt_rva = idat_rva + idt_size;
        iat_rva = idat_rva + idt_size + ilt_size;
        hint_name_rva = idat_rva + idt_size + ilt_size + iat_size;
        dll_name_rva = idat_rva + idt_size + ilt_size + iat_size + hint_name_size;
    }

    uint32_t text_raw_off = headers_raw;
    if (has_imports) {
        idat_raw_off = text_raw_off + text_size_file;
    }
    /* DataDirectory[1].VirtualAddress and section VirtualAddress must be idat_rva (RVA), never idat_raw_off. */
    /* SizeOfImage: must include all sections' virtual size, aligned to SectionAlignment */
    uint32_t size_of_image = has_imports ? (idat_rva + idat_size_virt) : (TEXT_RVA + text_size_virt);
    size_of_image = ALIGN_UP(size_of_image, SEC_ALIGN);
    /* Entry point: must be non-zero and within .text (main sets entry_rva=0 => first byte of .text) */
    uint32_t entry_rva = TEXT_RVA + pw->entry_rva;
    if (entry_rva == 0) entry_rva = TEXT_RVA;

    uint32_t total = has_imports ? (idat_raw_off + idat_size_file) : (text_raw_off + text_size_file);
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) return 0;
    memset(buf, 0, total);

    /* 1. DOS stub */
    memcpy(buf, dos_stub, dos_size);

    /* 2. PE signature */
    buf[pe_sig_off] = 'P'; buf[pe_sig_off+1] = 'E'; buf[pe_sig_off+2] = 0; buf[pe_sig_off+3] = 0;

    /* 3. COFF header */
    PeCoffHeader* coff = (PeCoffHeader*)(buf + coff_off);
    coff->Machine = IMAGE_FILE_MACHINE_AMD64;
    coff->NumberOfSections = (uint16_t)num_sections;
    coff->TimeDateStamp = (uint32_t)time(NULL);
    coff->PointerToSymbolTable = 0;
    coff->NumberOfSymbols = 0;
    coff->SizeOfOptionalHeader = (uint16_t)opt_hdr_size;
    coff->Characteristics = 0x22; /* EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE */

    /* 4. Optional header (PE32+) */
    PeOptionalHeader64* opt = (PeOptionalHeader64*)(buf + opt_off);
    fprintf(stderr, "[DEBUG] opt_off = 0x%X, sizeof(PeOptionalHeader64) = %zu\n", opt_off, sizeof(PeOptionalHeader64));
    fprintf(stderr, "[DEBUG] Setting opt fields at %p\n", (void*)opt);
    opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    opt->MajorLinkerVersion = 1;
    opt->MinorLinkerVersion = 0;
    opt->SizeOfCode = text_size_virt;
    opt->SizeOfInitializedData = idat_size_virt;
    opt->SizeOfUninitializedData = 0;
    opt->AddressOfEntryPoint = entry_rva;
    fprintf(stderr, "[DEBUG] Before BaseOfCode: opt->AddressOfEntryPoint = 0x%X\n", opt->AddressOfEntryPoint);
    opt->BaseOfCode = TEXT_RVA;
    fprintf(stderr, "[DEBUG] After BaseOfCode: opt->BaseOfCode = 0x%X\n", opt->BaseOfCode);
    opt->ImageBase = IMAGE_BASE;
    fprintf(stderr, "[DEBUG] After ImageBase: opt->ImageBase = 0x%llX\n", (unsigned long long)opt->ImageBase);
    opt->SectionAlignment = SEC_ALIGN;
    opt->FileAlignment = FILE_ALIGN;
    fprintf(stderr, "[DEBUG] After FileAlignment: opt->SectionAlignment = 0x%X, opt->FileAlignment = 0x%X\n", opt->SectionAlignment, opt->FileAlignment);
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 0;
    opt->MajorImageVersion = 0;
    opt->MinorImageVersion = 0;
    /* Subsystem version must be >= 5.1 for Win64 loader acceptance */
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 0;
    opt->Win32VersionValue = 0;
    opt->SizeOfImage = size_of_image;
    opt->SizeOfHeaders = headers_raw;
    opt->CheckSum = 0;
    opt->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt->DllCharacteristics = 0x8160;
    opt->SizeOfStackReserve = 0x100000;  /* 1 MB */
    opt->SizeOfStackCommit = 0x10000;    /* 64 KB initial commit (avoids overflow in CRT/stub) */
    if (opt->SizeOfStackReserve < 0x10000)
        opt->SizeOfStackReserve = 0x100000;  /* enforce minimum 1 MB to avoid 0xC00000FD */
    opt->SizeOfHeapReserve = 0x100000;
    opt->SizeOfHeapCommit = 0x1000;
    opt->LoaderFlags = 0;
    opt->NumberOfRvaAndSizes = 16;
    opt->DataDirectory[0].VirtualAddress = 0;
    opt->DataDirectory[0].Size = 0;
    if (has_imports) {
        opt->DataDirectory[1].VirtualAddress = idt_rva;
        opt->DataDirectory[1].Size = idt_size;
        /* IAT directory (12): some loaders use this to know where to patch */
        opt->DataDirectory[12].VirtualAddress = iat_rva;
        opt->DataDirectory[12].Size = iat_size;  /* Size includes all entries + null terminator */
    }
    for (int i = 2; i < 16; i++) {
        if (i == 12) continue;
        opt->DataDirectory[i].VirtualAddress = 0;
        opt->DataDirectory[i].Size = 0;
    }

    /* 5. Section table */
    PeSectionHeader* sh_text = (PeSectionHeader*)(buf + sect_tbl_off);
    memcpy(sh_text->Name, ".text", 6);
    sh_text->VirtualSize = text_size;
    sh_text->VirtualAddress = TEXT_RVA;
    sh_text->SizeOfRawData = text_size_file;
    sh_text->PointerToRawData = text_raw_off;
    sh_text->PointerToRelocations = 0;
    sh_text->PointerToLineNumbers = 0;
    sh_text->NumberOfRelocations = 0;
    sh_text->NumberOfLineNumbers = 0;
    sh_text->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXEC;

    if (has_imports) {
        PeSectionHeader* sh_idata = (PeSectionHeader*)(buf + sect_tbl_off + sizeof(PeSectionHeader));
        memcpy(sh_idata->Name, ".idata", 7);
        sh_idata->VirtualSize = idat_content_size;
        sh_idata->VirtualAddress = idat_rva;
        sh_idata->SizeOfRawData = idat_size_file;
        sh_idata->PointerToRawData = idat_raw_off;
        sh_idata->PointerToRelocations = 0;
        sh_idata->PointerToLineNumbers = 0;
        sh_idata->NumberOfRelocations = 0;
        sh_idata->NumberOfLineNumbers = 0;
        sh_idata->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    }

    /* 6. .text section data */
    memcpy(buf + text_raw_off, pw->text_data, text_size);
    /* padding to file alignment is already zero from memset */

    /* 7. .idata section: IDT, ILT, IAT, Hint/Name, DLL name */
    if (has_imports) {
        uint32_t idat_off = idat_raw_off;
        uint32_t hint_name_cur_rva = hint_name_rva;

        /* IDT entry 1 */
        w32(buf + idat_off, ilt_rva);     idat_off += 4;  /* OriginalFirstThunk */
        w32(buf + idat_off, 0);           idat_off += 4;  /* TimeDateStamp */
        w32(buf + idat_off, 0);           idat_off += 4;  /* ForwarderChain */
        w32(buf + idat_off, dll_name_rva); idat_off += 4; /* Name */
        w32(buf + idat_off, iat_rva);    idat_off += 4;  /* FirstThunk */
        /* IDT null entry */
        w32(buf + idat_off, 0); idat_off += 4;
        w32(buf + idat_off, 0); idat_off += 4;
        w32(buf + idat_off, 0); idat_off += 4;
        w32(buf + idat_off, 0); idat_off += 4;
        w32(buf + idat_off, 0); idat_off += 4;

        /* ILT: 64-bit RVA to Hint/Name for each import, then 64-bit null terminator */
        for (int i = 0; i < num_imports; i++) {
            w32(buf + idat_off, hint_name_cur_rva); idat_off += 4;
            w32(buf + idat_off, 0);                   idat_off += 4;
            /* Advance hint_name_cur_rva for next entry (same calculation as hint_name_size) */
            const char* func_name = pw->import_count > 0 ? pw->imports[i].func_name : pw->import_func;
            uint32_t entry_size = 2 + (uint32_t)strlen(func_name) + 1;
            if (entry_size % 2 != 0) entry_size++;
            hint_name_cur_rva += entry_size;
        }
        /* ILT null terminator */
        w32(buf + idat_off, 0); idat_off += 4;
        w32(buf + idat_off, 0); idat_off += 4;

        /* IAT: Pre-filled with hint/name RVAs for each import, then 64-bit null terminator */
        hint_name_cur_rva = hint_name_rva;
        for (int i = 0; i < num_imports; i++) {
            w32(buf + idat_off, hint_name_cur_rva); idat_off += 4;
            w32(buf + idat_off, 0);                   idat_off += 4;
            const char* func_name = pw->import_count > 0 ? pw->imports[i].func_name : pw->import_func;
            uint32_t entry_size = 2 + (uint32_t)strlen(func_name) + 1;
            if (entry_size % 2 != 0) entry_size++;
            hint_name_cur_rva += entry_size;
        }
        /* IAT null terminator */
        w32(buf + idat_off, 0); idat_off += 4;
        w32(buf + idat_off, 0); idat_off += 4;

        /* Hint/Name table: 2-byte hint + "FuncName\0" for each import, aligned to 2 bytes */
        idat_off = idat_raw_off + idt_size + ilt_size + iat_size;
        fprintf(stderr, "[DEBUG] hint_name table starts at file offset 0x%X\n", idat_off);
        fprintf(stderr, "[DEBUG] Calculated sizes: idt_size=%u, ilt_size=%u, iat_size=%u, hint_name_size=%u\n",
                idt_size, ilt_size, iat_size, hint_name_size);
        for (int i = 0; i < num_imports; i++) {
            const char* func_name = pw->import_count > 0 ? pw->imports[i].func_name : pw->import_func;
            size_t flen = strlen(func_name);
            uint32_t total_entry_size = 2 + (uint32_t)flen + 1;
            fprintf(stderr, "[DEBUG] Import %d: '%s', len=%zu, total_entry_size=%u\n", i, func_name, flen, total_entry_size);
            fprintf(stderr, "[DEBUG]   Writing hint (2 bytes) at offset 0x%X\n", idat_off);
            w16(buf + idat_off, 0);  /* Hint */
            idat_off += 2;
            fprintf(stderr, "[DEBUG]   Writing name (%zu bytes) at offset 0x%X: '", flen + 1, idat_off);
            for (size_t j = 0; j < flen; j++) {
                fprintf(stderr, "%c", func_name[j]);
            }
            fprintf(stderr, "'\n");
            memcpy(buf + idat_off, func_name, flen + 1);  /* Include null terminator */
            idat_off += (uint32_t)flen + 1;
            /* Pad to 2-byte alignment for next entry */
            if (total_entry_size % 2 != 0) {
                fprintf(stderr, "[DEBUG]   Adding padding byte at offset 0x%X\n", idat_off);
                buf[idat_off] = 0;
                idat_off++;
            }
            fprintf(stderr, "[DEBUG]   Next entry will start at offset 0x%X\n", idat_off);
        }
        fprintf(stderr, "[DEBUG] hint_name table ends at file offset 0x%X\n", idat_off);

        /* DLL name at dll_name_offset (lowercase for loader compatibility) */
        idat_off = idat_raw_off + idt_size + ilt_size + iat_size + hint_name_size;
        const char* dll_name = pw->import_count > 0 ? pw->imports[0].dll_name : pw->import_dll;
        if (dll_name) {
            size_t dlen = strlen(dll_name);
            for (size_t i = 0; i < dlen; i++) {
                char c = dll_name[i];
                buf[idat_off + i] = (uint8_t)(c >= 'A' && c <= 'Z' ? c + 32 : c);
            }
            buf[idat_off + dlen] = 0;
        }
    }

    *out = buf;
    return total;
}
