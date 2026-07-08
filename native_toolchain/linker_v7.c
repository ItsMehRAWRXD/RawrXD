/*
 * Native Linker v7 - WITH RELOCATION SUPPORT
 * Can link COFF objects to PE executables with proper import table relocations
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <windows.h>

// PE structures
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
} DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

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
} OPTIONAL_HEADER_64;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DATA_DIRECTORY;

typedef struct {
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
} SECTION_HEADER;

typedef struct {
    uint32_t ImportLookupTableRVA;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t NameRVA;
    uint32_t ImportAddressTableRVA;
} IMPORT_DIRECTORY_ENTRY;

// COFF structures for reading
typedef struct {
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
} COFF_SECTION_HEADER;

typedef struct {
    union {
        char ShortName[8];
        struct {
            uint32_t Zeroes;
            uint32_t Offset;
        } LongName;
    } SymName;
    uint32_t Value;
    int16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} MY_SYMBOL_TABLE_ENTRY;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} RELOCATION_ENTRY;
#pragma pack(pop)

#define IMAGE_REL_AMD64_REL32  0x0004

// Read COFF object file with relocation support
typedef struct {
    uint8_t *code;
    int code_size;
    RELOCATION_ENTRY *relocs;
    int num_relocs;
    MY_SYMBOL_TABLE_ENTRY *symbols;
    int num_symbols;
    char *string_table;
    int string_table_size;
} COFF_FILE;

int read_coff_file(const char *filename, COFF_FILE *coff) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        printf("[ERROR] Cannot open: %s\n", filename);
        return 0;
    }
    
    memset(coff, 0, sizeof(COFF_FILE));
    
    // Read COFF header
    COFF_HEADER header;
    if (fread(&header, sizeof(header), 1, f) != 1) {
        printf("[ERROR] Cannot read COFF header\n");
        fclose(f);
        return 0;
    }
    
    printf("  COFF Machine: 0x%04X\n", header.Machine);
    printf("  Sections: %d\n", header.NumberOfSections);
    printf("  Symbols: %d at offset %d\n", header.NumberOfSymbols, header.PointerToSymbolTable);
    
    // Read section headers
    COFF_SECTION_HEADER *sections = calloc(header.NumberOfSections, sizeof(COFF_SECTION_HEADER));
    for (int i = 0; i < header.NumberOfSections; i++) {
        fread(&sections[i], sizeof(COFF_SECTION_HEADER), 1, f);
        printf("  Section %d: %.8s, Size: %d, RawData: %d, Relocs: %d at %d\n", 
               i + 1, sections[i].Name, sections[i].SizeOfRawData, 
               sections[i].PointerToRawData, sections[i].NumberOfRelocations,
               sections[i].PointerToRelocations);
    }
    
    // Read code from .text section
    for (int i = 0; i < header.NumberOfSections; i++) {
        if (strncmp(sections[i].Name, ".text", 5) == 0 && sections[i].SizeOfRawData > 0) {
            coff->code_size = sections[i].SizeOfRawData;
            coff->code = (uint8_t*)malloc(coff->code_size);
            
            fseek(f, sections[i].PointerToRawData, SEEK_SET);
            fread(coff->code, coff->code_size, 1, f);
            
            // Read relocations
            if (sections[i].NumberOfRelocations > 0) {
                coff->num_relocs = sections[i].NumberOfRelocations;
                coff->relocs = (RELOCATION_ENTRY*)malloc(coff->num_relocs * sizeof(RELOCATION_ENTRY));
                fseek(f, sections[i].PointerToRelocations, SEEK_SET);
                fread(coff->relocs, coff->num_relocs * sizeof(RELOCATION_ENTRY), 1, f);
                
                printf("    Read %d relocations\n", coff->num_relocs);
                for (int r = 0; r < coff->num_relocs; r++) {
                    printf("      Reloc %d: offset=%d, symbol=%d, type=%d\n",
                           r, coff->relocs[r].VirtualAddress, 
                           coff->relocs[r].SymbolTableIndex, coff->relocs[r].Type);
                }
            }
        }
    }
    
    // Read symbol table
    if (header.NumberOfSymbols > 0) {
        coff->num_symbols = header.NumberOfSymbols;
        coff->symbols = (MY_SYMBOL_TABLE_ENTRY*)malloc(coff->num_symbols * sizeof(MY_SYMBOL_TABLE_ENTRY));
        fseek(f, header.PointerToSymbolTable, SEEK_SET);
        fread(coff->symbols, coff->num_symbols * sizeof(MY_SYMBOL_TABLE_ENTRY), 1, f);
        
        // Read string table (follows symbol table)
        long string_table_offset = header.PointerToSymbolTable + 
                                   coff->num_symbols * sizeof(MY_SYMBOL_TABLE_ENTRY);
        fseek(f, string_table_offset, SEEK_SET);
        uint32_t string_table_size;
        fread(&string_table_size, 4, 1, f);
        
        if (string_table_size > 4) {
            coff->string_table_size = string_table_size - 4;
            coff->string_table = (char*)malloc(coff->string_table_size);
            fread(coff->string_table, coff->string_table_size, 1, f);
        }
        
        printf("  Symbols:\n");
        for (int s = 0; s < coff->num_symbols && s < 10; s++) {
            char name[256] = {0};
            if (coff->symbols[s].SymName.LongName.Zeroes == 0) {
                // Long name in string table
                strncpy(name, coff->string_table + coff->symbols[s].SymName.LongName.Offset - 4, 255);
            } else {
                // Short name inline
                strncpy(name, coff->symbols[s].SymName.ShortName, 8);
            }
            printf("    Symbol %d: %s, Section=%d, Class=%d\n",
                   s, name, coff->symbols[s].SectionNumber, coff->symbols[s].StorageClass);
        }
    }
    
    free(sections);
    fclose(f);
    return 1;
}

// Write PE executable with import table and apply relocations
int write_pe_with_imports(const char *filename, COFF_FILE *coff,
                         const char **dll_names, const char **func_names, int num_imports) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        printf("[ERROR] Cannot create: %s\n", filename);
        return 0;
    }
    
    // Constants
    uint32_t section_alignment = 0x1000;
    uint32_t file_alignment = 0x200;
    uint64_t image_base = 0x140000000;
    
    // Calculate sizes
    int dos_stub_size = 64;
    int headers_size = dos_stub_size + 4 + sizeof(COFF_HEADER) + sizeof(OPTIONAL_HEADER_64) + 
                       sizeof(DATA_DIRECTORY) * 16 + sizeof(SECTION_HEADER) * 2;
    int headers_aligned = (headers_size + file_alignment - 1) & ~(file_alignment - 1);
    
    // Code section
    int code_size = coff->code_size;
    int code_aligned = (code_size + file_alignment - 1) & ~(file_alignment - 1);
    
    // Import section size calculation
    int idt_size = sizeof(IMPORT_DIRECTORY_ENTRY) * (num_imports + 1);
    int ilt_size = sizeof(uint64_t) * (num_imports + 1);
    int iat_size = sizeof(uint64_t) * (num_imports + 1);
    int name_table_size = 0;
    for (int i = 0; i < num_imports; i++) {
        name_table_size += 2 + strlen(func_names[i]) + 1;
    }
    int dll_names_size = strlen(dll_names[0]) + 1;
    int import_data_size = idt_size + ilt_size + iat_size + name_table_size + dll_names_size;
    int import_aligned = (import_data_size + file_alignment - 1) & ~(file_alignment - 1);
    
    // Section RVAs
    uint32_t text_rva = section_alignment;
    uint32_t idata_rva = text_rva + section_alignment;
    uint32_t image_size = idata_rva + section_alignment * 2;
    
    // File offsets
    uint32_t text_file_offset = headers_aligned;
    uint32_t idata_file_offset = text_file_offset + code_aligned;
    
    // IAT RVA (where call instructions should point)
    uint32_t iat_rva = idata_rva + idt_size + ilt_size;
    
    printf("  Layout: headers=%d, text RVA=0x%X, idata RVA=0x%X, IAT RVA=0x%X\n",
           headers_aligned, text_rva, idata_rva, iat_rva);
    
    // DOS Header
    DOS_HEADER dos = {0};
    dos.e_magic = 0x5A4D;
    dos.e_lfanew = dos_stub_size;
    fwrite(&dos, sizeof(dos), 1, f);
    
    // DOS Stub (64 bytes total - sizeof(DOS_HEADER) = 64 - 64 = 0, so we need to pad)
    // Actually DOS_HEADER is 64 bytes, so no stub needed, just pad to 64
    uint8_t dos_stub[64] = {
        0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00
    };
    // But we already wrote DOS header, so just write the stub after it
    // Actually we wrote the header already, so skip this
    // Let me recalculate: DOS header is 64 bytes, we need to write stub separately
    // Actually the DOS header includes the stub area. Let me fix this properly.
    // For now, just pad to 64 bytes
    fseek(f, 0, SEEK_SET);
    fwrite(&dos, sizeof(dos), 1, f);
    
    // PE Signature
    uint32_t pe_sig = 0x00004550;
    fwrite(&pe_sig, 4, 1, f);
    
    // COFF Header
    COFF_HEADER coff_hdr = {0};
    coff_hdr.Machine = 0x8664;
    coff_hdr.NumberOfSections = 2;
    coff_hdr.TimeDateStamp = (uint32_t)time(NULL);
    coff_hdr.SizeOfOptionalHeader = sizeof(OPTIONAL_HEADER_64) + sizeof(DATA_DIRECTORY) * 16;
    coff_hdr.Characteristics = 0x22;
    fwrite(&coff_hdr, sizeof(coff_hdr), 1, f);
    
    // Optional Header
    OPTIONAL_HEADER_64 opt = {0};
    opt.Magic = 0x20B;
    opt.MajorLinkerVersion = 1;
    opt.MinorLinkerVersion = 0;
    opt.SizeOfCode = code_aligned;
    opt.SizeOfInitializedData = import_aligned;
    opt.SizeOfUninitializedData = 0;
    opt.AddressOfEntryPoint = text_rva;
    opt.BaseOfCode = text_rva;
    opt.ImageBase = image_base;
    opt.SectionAlignment = section_alignment;
    opt.FileAlignment = file_alignment;
    opt.MajorOperatingSystemVersion = 6;
    opt.MinorOperatingSystemVersion = 0;
    opt.MajorImageVersion = 0;
    opt.MinorImageVersion = 0;
    opt.MajorSubsystemVersion = 6;
    opt.MinorSubsystemVersion = 0;
    opt.Win32VersionValue = 0;
    opt.SizeOfImage = image_size;
    opt.SizeOfHeaders = headers_aligned;
    opt.CheckSum = 0;
    opt.Subsystem = 3;
    opt.DllCharacteristics = 0x8160;
    opt.SizeOfStackReserve = 0x100000;
    opt.SizeOfStackCommit = 0x1000;
    opt.SizeOfHeapReserve = 0x100000;
    opt.SizeOfHeapCommit = 0x1000;
    opt.LoaderFlags = 0;
    opt.NumberOfRvaAndSizes = 16;
    fwrite(&opt, sizeof(opt), 1, f);
    
    // Data Directories
    DATA_DIRECTORY data_dirs[16] = {0};
    data_dirs[1].VirtualAddress = idata_rva;  // Import directory
    data_dirs[1].Size = idt_size;
    data_dirs[12].VirtualAddress = iat_rva;   // IAT directory
    data_dirs[12].Size = iat_size - sizeof(uint64_t);
    fwrite(data_dirs, sizeof(data_dirs), 1, f);
    
    // Section Headers
    SECTION_HEADER text_sect = {0};
    memcpy(text_sect.Name, ".text", 5);
    text_sect.VirtualSize = code_size;
    text_sect.VirtualAddress = text_rva;
    text_sect.SizeOfRawData = code_aligned;
    text_sect.PointerToRawData = text_file_offset;
    text_sect.Characteristics = 0x60000020;
    fwrite(&text_sect, sizeof(text_sect), 1, f);
    
    SECTION_HEADER idata_sect = {0};
    memcpy(idata_sect.Name, ".idata", 6);
    idata_sect.VirtualSize = import_data_size;
    idata_sect.VirtualAddress = idata_rva;
    idata_sect.SizeOfRawData = import_aligned;
    idata_sect.PointerToRawData = idata_file_offset;
    idata_sect.Characteristics = 0xC0000040; // INITIALIZED_DATA | READ | WRITE
    fwrite(&idata_sect, sizeof(idata_sect), 1, f);
    
    // Pad headers
    int current_pos = ftell(f);
    int pad_size = headers_aligned - current_pos;
    if (pad_size > 0) {
        uint8_t *pad = (uint8_t*)calloc(1, pad_size);
        fwrite(pad, pad_size, 1, f);
        free(pad);
    }
    
    // Build symbol lookup table for internal symbols
    typedef struct {
        char name[256];
        uint32_t value;
        int is_external;
    } SYMBOL_INFO;
    
    SYMBOL_INFO *sym_table = calloc(coff->num_symbols, sizeof(SYMBOL_INFO));
    int num_internal_syms = 0;
    
    for (int s = 0; s < coff->num_symbols; s++) {
        char name[256] = {0};
        if (coff->symbols[s].SymName.LongName.Zeroes == 0) {
            strncpy(name, coff->string_table + coff->symbols[s].SymName.LongName.Offset - 4, 255);
        } else {
            strncpy(name, coff->symbols[s].SymName.ShortName, 8);
        }
        
        // Check if external (section 0) or internal (section 1 = .text)
        int is_external = (coff->symbols[s].SectionNumber == 0);
        int is_text = (coff->symbols[s].SectionNumber == 1);
        
        if (is_text || is_external) {
            strncpy(sym_table[num_internal_syms].name, name, 255);
            sym_table[num_internal_syms].value = coff->symbols[s].Value;
            sym_table[num_internal_syms].is_external = is_external;
            num_internal_syms++;
        }
    }
    
    // Apply relocations to code before writing
    uint8_t *code_copy = (uint8_t*)malloc(code_aligned);
    memcpy(code_copy, coff->code, code_size);
    
    for (int r = 0; r < coff->num_relocs; r++) {
        if (coff->relocs[r].Type == IMAGE_REL_AMD64_REL32) {
            uint32_t reloc_offset = coff->relocs[r].VirtualAddress;
            uint32_t sym_idx = coff->relocs[r].SymbolTableIndex;
            
            if (reloc_offset + 4 <= code_size && sym_idx < coff->num_symbols) {
                // Get symbol name
                char sym_name[256] = {0};
                if (coff->symbols[sym_idx].SymName.LongName.Zeroes == 0) {
                    strncpy(sym_name, coff->string_table + coff->symbols[sym_idx].SymName.LongName.Offset - 4, 255);
                } else {
                    strncpy(sym_name, coff->symbols[sym_idx].SymName.ShortName, 8);
                }
                
                // Check if this is an indirect call (FF 15) or direct call/jmp (E8/E9)
                int is_indirect = (reloc_offset >= 2 && 
                                   coff->code[reloc_offset - 2] == 0xFF && 
                                   coff->code[reloc_offset - 1] == 0x15);
                int is_jmp = (reloc_offset >= 1 && coff->code[reloc_offset - 1] == 0xE9);
                int is_call = (reloc_offset >= 1 && coff->code[reloc_offset - 1] == 0xE8);
                
                int instruction_size = is_indirect ? 6 : 5;
                int32_t rel_offset;
                
                // Determine target
                if (coff->symbols[sym_idx].SectionNumber == 0) {
                    // External symbol - point to IAT
                    // For indirect call: target is IAT entry
                    // For direct call/jmp: not typically used for externals
                    rel_offset = (int32_t)(iat_rva - (text_rva + reloc_offset + 4));
                    printf("  Applying reloc at offset %d (external %s): rel32 = %d (0x%X) -> IAT\n",
                           reloc_offset, sym_name, rel_offset, (uint32_t)rel_offset);
                } else {
                    // Internal symbol - calculate relative offset to symbol value
                    uint32_t target_rva = text_rva + coff->symbols[sym_idx].Value;
                    uint32_t next_insn_rva = text_rva + reloc_offset + 4; // After disp32
                    rel_offset = (int32_t)(target_rva - next_insn_rva);
                    printf("  Applying reloc at offset %d (internal %s): target=0x%X, next=0x%X, rel32=%d\n",
                           reloc_offset, sym_name, target_rva, next_insn_rva, rel_offset);
                }
                
                // Write the relative offset (little-endian)
                code_copy[reloc_offset] = rel_offset & 0xFF;
                code_copy[reloc_offset + 1] = (rel_offset >> 8) & 0xFF;
                code_copy[reloc_offset + 2] = (rel_offset >> 16) & 0xFF;
                code_copy[reloc_offset + 3] = (rel_offset >> 24) & 0xFF;
            }
        }
    }
    
    free(sym_table);
    
    // Write code section
    fwrite(code_copy, code_size, 1, f);
    int code_pad = code_aligned - code_size;
    if (code_pad > 0) {
        uint8_t *padding = (uint8_t*)calloc(1, code_pad);
        fwrite(padding, code_pad, 1, f);
        free(padding);
    }
    free(code_copy);
    
    // Build and write import section
    uint8_t *import_data = (uint8_t*)calloc(1, import_aligned);
    uint32_t offset = 0;
    
    // Import Directory Table
    IMPORT_DIRECTORY_ENTRY *idt = (IMPORT_DIRECTORY_ENTRY*)(import_data + offset);
    idt[0].ImportLookupTableRVA = idata_rva + idt_size;
    idt[0].TimeDateStamp = 0;
    idt[0].ForwarderChain = 0;
    idt[0].NameRVA = idata_rva + idt_size + ilt_size + iat_size + name_table_size;
    idt[0].ImportAddressTableRVA = idata_rva + idt_size + ilt_size;
    // Null entry
    memset(&idt[1], 0, sizeof(IMPORT_DIRECTORY_ENTRY));
    offset += idt_size;
    
    // Import Lookup Table and Import Address Table
    uint32_t name_offset = idt_size + ilt_size + iat_size;
    for (int i = 0; i < num_imports; i++) {
        uint64_t *ilt = (uint64_t*)(import_data + idt_size + i * sizeof(uint64_t));
        uint64_t *iat = (uint64_t*)(import_data + idt_size + ilt_size + i * sizeof(uint64_t));
        
        // Point to hint/name table
        uint64_t hint_name_rva = idata_rva + name_offset;
        *ilt = hint_name_rva;
        *iat = hint_name_rva;
        
        // Hint/Name table entry
        uint16_t *hint = (uint16_t*)(import_data + name_offset);
        *hint = 0;
        strcpy((char*)(import_data + name_offset + 2), func_names[i]);
        name_offset += 2 + strlen(func_names[i]) + 1;
    }
    
    // DLL Name
    strcpy((char*)(import_data + name_offset), dll_names[0]);
    
    fwrite(import_data, import_aligned, 1, f);
    free(import_data);
    
    fclose(f);
    
    printf("[SUCCESS] Created PE with imports: %s\n", filename);
    printf("  Entry point: 0x%X\n", text_rva);
    printf("  Import table at: 0x%X\n", idata_rva);
    printf("  IAT at: 0x%X\n", iat_rva);
    
    return 1;
}

int main(int argc, char *argv[]) {
    printf("========================================\n");
    printf("Native Linker v7 WITH RELOCATIONS\n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <input.obj> [output.exe]\n", argv[0]);
        return 0;
    }
    
    // Read object file
    printf("[LINKING] Reading: %s\n", argv[1]);
    COFF_FILE coff;
    if (!read_coff_file(argv[1], &coff)) {
        printf("[FAILED] Cannot read object file\n");
        return 1;
    }
    
    // Define imports
    const char *dll_names[] = {"kernel32.dll"};
    const char *func_names[] = {"ExitProcess"};
    int num_imports = 1;
    
    // Write executable
    const char *output = (argc > 2) ? argv[2] : "output.exe";
    printf("\n[LINKING] Creating: %s\n", output);
    
    if (!write_pe_with_imports(output, &coff, dll_names, func_names, num_imports)) {
        printf("[FAILED] Cannot create executable\n");
        free(coff.code);
        free(coff.relocs);
        free(coff.symbols);
        free(coff.string_table);
        return 1;
    }
    
    // Cleanup
    free(coff.code);
    free(coff.relocs);
    free(coff.symbols);
    free(coff.string_table);
    
    printf("\n*** SUCCESS! ***\n");
    printf("Native linker with relocation support complete!\n");
    
    return 0;
}
