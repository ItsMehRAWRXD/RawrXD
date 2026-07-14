// Working PE Linker - Zero Dependencies
// Links COFF object files to PE executables

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

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
} dos_header_t;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} coff_file_header_t;

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
    // Data directory entries follow
} optional_header_64_t;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} data_directory_t;

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
} section_header_t;

typedef struct {
    uint16_t reloc_type;
    uint16_t reloc_offset;
} reloc_entry_t;

#pragma pack(pop)

// Constants
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_ALIGN_16BYTES 0x00000500
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#define IMAGE_REL_AMD64_ADDR64 1
#define IMAGE_REL_AMD64_ADDR32 2
#define IMAGE_REL_AMD64_REL32 4

// COFF structures (from object file) - must match assembler output
#pragma pack(push, 1)
typedef struct {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t raw_data_size;
    uint32_t raw_data_offset;
    uint32_t relocations_offset;
    uint32_t line_numbers_offset;
    uint16_t num_relocations;
    uint16_t num_line_numbers;
    uint32_t characteristics;
} coff_section_t;

typedef struct {
    uint32_t virtual_addr;
    uint32_t symbol_index;
    uint16_t type;
} coff_reloc_t;

typedef struct {
    char name[8];
    uint32_t value;
    int16_t section;
    uint16_t type;
    uint8_t storage_class;
    uint8_t num_aux;
} coff_symbol_t;
#pragma pack(pop)

// Object file
typedef struct {
    coff_file_header_t header;
    coff_section_t *sections;
    uint8_t **section_data;
    coff_reloc_t **relocs;
    coff_symbol_t *symbols;
    char *string_table;
    size_t string_table_size;
} obj_file_t;

// Read COFF object file
static int read_obj_file(const char *filename, obj_file_t *obj) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open object file");
        return -1;
    }
    
    // Read header
    size_t header_size = sizeof(coff_file_header_t);
    printf("Reading COFF header (%zu bytes)...\n", header_size);
    
    if (fread(&obj->header, header_size, 1, fp) != 1) {
        fprintf(stderr, "Failed to read COFF header\n");
        fclose(fp);
        return -1;
    }
    
    printf("Machine type: 0x%X\n", obj->header.Machine);
    printf("Number of sections: %u\n", obj->header.NumberOfSections);
    printf("Number of symbols: %u\n", obj->header.NumberOfSymbols);
    
    // Check if this is a COFF object file or PE executable
    // COFF object files start directly with the header
    // PE executables have "PE\0\0" signature at offset 0x3C
    // If Machine is 0, this might be a PE file - check for signature
    if (obj->header.Machine == 0) {
        // Check for PE signature at offset 0x3C
        fseek(fp, 0x3C, SEEK_SET);
        uint32_t pe_offset;
        if (fread(&pe_offset, sizeof(pe_offset), 1, fp) == 1 && pe_offset != 0) {
            fseek(fp, pe_offset, SEEK_SET);
            uint32_t pe_sig;
            if (fread(&pe_sig, sizeof(pe_sig), 1, fp) == 1 && pe_sig == 0x00004550) {
                fprintf(stderr, "Error: This is a PE executable, not a COFF object file\n");
                fclose(fp);
                return -1;
            }
        }
        // Reset to beginning and try reading again
        fseek(fp, 0, SEEK_SET);
        if (fread(&obj->header, header_size, 1, fp) != 1) {
            fprintf(stderr, "Failed to read COFF header\n");
            fclose(fp);
            return -1;
        }
    }
    
    // Verify machine type
    if (obj->header.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fprintf(stderr, "Unsupported machine type: 0x%X (expected 0x%X)\n", 
                obj->header.Machine, IMAGE_FILE_MACHINE_AMD64);
        fclose(fp);
        return -1;
    }
    
    printf("Object file: %u sections, %u symbols\n", 
           obj->header.NumberOfSections, obj->header.NumberOfSymbols);
    
    // Read section headers
    obj->sections = calloc(obj->header.NumberOfSections, sizeof(coff_section_t));
    obj->section_data = calloc(obj->header.NumberOfSections, sizeof(uint8_t*));
    obj->relocs = calloc(obj->header.NumberOfSections, sizeof(coff_reloc_t*));
    
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        if (fread(&obj->sections[i], sizeof(coff_section_t), 1, fp) != 1) {
            fprintf(stderr, "Failed to read section header %d\n", i);
            fclose(fp);
            return -1;
        }
        
        printf("  Section %d: %.8s, size=%u, chars=0x%X\n", 
               i, obj->sections[i].name, obj->sections[i].raw_data_size, 
               obj->sections[i].characteristics);
    }
    
    // Read section data
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        if (obj->sections[i].raw_data_size > 0) {
            fseek(fp, obj->sections[i].raw_data_offset, SEEK_SET);
            obj->section_data[i] = malloc(obj->sections[i].raw_data_size);
            fread(obj->section_data[i], 1, obj->sections[i].raw_data_size, fp);
        }
        
        // Read relocations
        if (obj->sections[i].num_relocations > 0) {
            fseek(fp, obj->sections[i].relocations_offset, SEEK_SET);
            obj->relocs[i] = calloc(obj->sections[i].num_relocations, sizeof(coff_reloc_t));
            fread(obj->relocs[i], sizeof(coff_reloc_t), obj->sections[i].num_relocations, fp);
        }
    }
    
    // Read symbol table
    if (obj->header.NumberOfSymbols > 0) {
        fseek(fp, obj->header.PointerToSymbolTable, SEEK_SET);
        obj->symbols = calloc(obj->header.NumberOfSymbols, sizeof(coff_symbol_t));
        fread(obj->symbols, sizeof(coff_symbol_t), obj->header.NumberOfSymbols, fp);
        
        // Read string table
        long sym_end = obj->header.PointerToSymbolTable + 
                       (obj->header.NumberOfSymbols * sizeof(coff_symbol_t));
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        
        if (file_size > sym_end) {
            obj->string_table_size = file_size - sym_end;
            obj->string_table = malloc(obj->string_table_size);
            fseek(fp, sym_end, SEEK_SET);
            fread(obj->string_table, 1, obj->string_table_size, fp);
        }
    }
    
    fclose(fp);
    return 0;
}

// Free object file
static void free_obj_file(obj_file_t *obj) {
    if (!obj) return;
    
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        free(obj->section_data[i]);
        free(obj->relocs[i]);
    }
    free(obj->sections);
    free(obj->section_data);
    free(obj->relocs);
    free(obj->symbols);
    free(obj->string_table);
    memset(obj, 0, sizeof(*obj));
}

// Get symbol name
static const char* get_symbol_name(coff_symbol_t *sym, char *string_table) {
    // Check if using long name (first 4 bytes are zero)
    uint32_t *name_ptr = (uint32_t*)sym->name;
    if (name_ptr[0] == 0) {
        // Long name in string table
        uint32_t offset = name_ptr[1];
        return string_table + offset;
    }
    // Short name embedded
    static char name_buf[9];
    memcpy(name_buf, sym->name, 8);
    name_buf[8] = '\0';
    return name_buf;
}

// Write PE executable
static int write_pe(const char *filename, obj_file_t *obj) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Failed to create output file");
        return -1;
    }
    
    // Calculate sizes
    uint32_t dos_header_size = sizeof(dos_header_t);
    uint32_t pe_signature_size = 4;
    uint32_t coff_header_size = sizeof(coff_file_header_t);
    uint32_t optional_header_size = sizeof(optional_header_64_t) + (16 * sizeof(data_directory_t));
    uint32_t section_header_size = sizeof(section_header_t) * obj->header.NumberOfSections;
    
    // Align headers to FileAlignment (512)
    uint32_t headers_size = dos_header_size + pe_signature_size + coff_header_size + 
                           optional_header_size + section_header_size;
    uint32_t headers_aligned = (headers_size + 511) & ~511;
    
    // Calculate section offsets
    uint32_t current_offset = headers_aligned;
    uint32_t *section_offsets = calloc(obj->header.NumberOfSections, sizeof(uint32_t));
    uint32_t *section_sizes = calloc(obj->header.NumberOfSections, sizeof(uint32_t));
    
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        section_offsets[i] = current_offset;
        section_sizes[i] = (obj->sections[i].raw_data_size + 511) & ~511;
        current_offset += section_sizes[i];
    }
    
    // Virtual addresses (SectionAlignment = 4096)
    uint64_t image_base = 0x140000000ULL;  // Default for x64 EXE
    uint32_t *virtual_addrs = calloc(obj->header.NumberOfSections, sizeof(uint32_t));
    uint32_t current_va = 0x1000;  // First section at RVA 0x1000
    
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        virtual_addrs[i] = current_va;
        uint32_t va_size = (obj->sections[i].virtual_size + 4095) & ~4095;
        if (va_size == 0) va_size = 4096;
        current_va += va_size;
    }
    
    uint32_t image_size = current_va;
    
    // Find entry point
    uint32_t entry_point = 0;
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        if (obj->sections[i].characteristics & IMAGE_SCN_CNT_CODE) {
            entry_point = virtual_addrs[i];
            break;
        }
    }
    
    // Write DOS header
    dos_header_t dos_header = {0};
    dos_header.e_magic = IMAGE_DOS_SIGNATURE;
    dos_header.e_lfanew = dos_header_size;
    fwrite(&dos_header, sizeof(dos_header), 1, fp);
    
    // Write PE signature
    uint32_t pe_sig = IMAGE_NT_SIGNATURE;
    fwrite(&pe_sig, sizeof(pe_sig), 1, fp);
    
    // Write COFF header
    coff_file_header_t coff_header = {0};
    coff_header.Machine = IMAGE_FILE_MACHINE_AMD64;
    coff_header.NumberOfSections = obj->header.NumberOfSections;
    coff_header.TimeDateStamp = 0;
    coff_header.PointerToSymbolTable = 0;
    coff_header.NumberOfSymbols = 0;
    coff_header.SizeOfOptionalHeader = optional_header_size;
    coff_header.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    fwrite(&coff_header, sizeof(coff_header), 1, fp);
    
    // Write optional header
    optional_header_64_t opt_header = {0};
    opt_header.Magic = 0x20B;  // PE32+ (64-bit)
    opt_header.MajorLinkerVersion = 1;
    opt_header.MinorLinkerVersion = 0;
    opt_header.SizeOfCode = section_sizes[0];  // Simplified
    opt_header.AddressOfEntryPoint = entry_point;
    opt_header.BaseOfCode = virtual_addrs[0];
    opt_header.ImageBase = image_base;
    opt_header.SectionAlignment = 4096;
    opt_header.FileAlignment = 512;
    opt_header.MajorOperatingSystemVersion = 6;
    opt_header.MinorOperatingSystemVersion = 0;
    opt_header.MajorSubsystemVersion = 6;
    opt_header.MinorSubsystemVersion = 0;
    opt_header.SizeOfImage = image_size;
    opt_header.SizeOfHeaders = headers_aligned;
    opt_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt_header.DllCharacteristics = 0;
    opt_header.SizeOfStackReserve = 0x100000;
    opt_header.SizeOfStackCommit = 0x1000;
    opt_header.SizeOfHeapReserve = 0x100000;
    opt_header.SizeOfHeapCommit = 0x1000;
    opt_header.NumberOfRvaAndSizes = 16;
    fwrite(&opt_header, sizeof(opt_header), 1, fp);
    
    // Write data directories (all zeros)
    data_directory_t data_dirs[16] = {0};
    fwrite(data_dirs, sizeof(data_dirs), 1, fp);
    
    // Write section headers
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        section_header_t sect = {0};
        memcpy(sect.Name, obj->sections[i].name, 8);
        sect.VirtualSize = obj->sections[i].virtual_size;
        sect.VirtualAddress = virtual_addrs[i];
        sect.SizeOfRawData = section_sizes[i];
        sect.PointerToRawData = section_offsets[i];
        sect.PointerToRelocations = 0;
        sect.PointerToLinenumbers = 0;
        sect.NumberOfRelocations = 0;
        sect.NumberOfLinenumbers = 0;
        sect.Characteristics = obj->sections[i].characteristics;
        fwrite(&sect, sizeof(sect), 1, fp);
    }
    
    // Pad headers
    uint32_t padding = headers_aligned - headers_size;
    for (uint32_t i = 0; i < padding; i++) {
        fputc(0, fp);
    }
    
    // Write section data
    for (int i = 0; i < obj->header.NumberOfSections; i++) {
        if (obj->sections[i].raw_data_size > 0 && obj->section_data[i]) {
            fwrite(obj->section_data[i], 1, obj->sections[i].raw_data_size, fp);
        }
        // Pad to 512 bytes
        uint32_t pad = section_sizes[i] - obj->sections[i].raw_data_size;
        for (uint32_t j = 0; j < pad; j++) {
            fputc(0, fp);
        }
    }
    
    fclose(fp);
    
    free(section_offsets);
    free(section_sizes);
    free(virtual_addrs);
    
    printf("PE executable written: %s\n", filename);
    printf("  Image base: 0x%llX\n", (unsigned long long)image_base);
    printf("  Entry point RVA: 0x%X\n", entry_point);
    printf("  Image size: %u bytes\n", image_size);
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Working PE Linker - Zero Dependencies\n");
        printf("Usage: %s <input.obj> <output.exe>\n", argv[0]);
        printf("\nLinks COFF object files to PE executables\n");
        printf("Supports x64 object files only\n");
        return 1;
    }
    
    obj_file_t obj = {0};
    
    // Read object file
    if (read_obj_file(argv[1], &obj) < 0) {
        return 1;
    }
    
    // Write PE executable
    if (write_pe(argv[2], &obj) < 0) {
        free_obj_file(&obj);
        return 1;
    }
    
    free_obj_file(&obj);
    printf("\nLink complete.\n");
    return 0;
}
