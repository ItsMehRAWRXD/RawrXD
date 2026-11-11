// pe_generator.c - Create a valid PE executable
// This generates a working x64 PE file

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

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
    uint64_t DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

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

#pragma pack(pop)

// x64 code: mov rax, 42; ret
unsigned char code[] = {
    0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00,  // mov rax, 42
    0xC3                                         // ret
};

int main(int argc, char** argv) {
    const char* output_file = (argc > 1) ? argv[1] : "output.exe";
    
    FILE* f = fopen(output_file, "wb");
    if (!f) {
        printf("Error: Cannot create %s\n", output_file);
        return 1;
    }
    
    // Calculate sizes
    uint32_t dos_header_size = sizeof(IMAGE_DOS_HEADER);
    uint32_t pe_header_size = 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64);
    uint32_t section_header_size = sizeof(IMAGE_SECTION_HEADER);
    uint32_t headers_size = dos_header_size + pe_header_size + section_header_size;
    uint32_t file_alignment = 512;
    uint32_t section_alignment = 4096;
    
    // Align headers to file alignment
    uint32_t headers_aligned = (headers_size + file_alignment - 1) & ~(file_alignment - 1);
    
    // Align code to file alignment
    uint32_t code_size = sizeof(code);
    uint32_t code_aligned = (code_size + file_alignment - 1) & ~(file_alignment - 1);
    
    // DOS Header
    IMAGE_DOS_HEADER dos_header = {0};
    dos_header.e_magic = 0x5A4D;  // "MZ"
    dos_header.e_cblp = 0x90;
    dos_header.e_cp = 0x03;
    dos_header.e_cparhdr = 0x04;
    dos_header.e_maxalloc = 0xFFFF;
    dos_header.e_sp = 0xB8;
    dos_header.e_lfarlc = 0x40;
    dos_header.e_lfanew = dos_header_size;
    
    // Write DOS header
    fwrite(&dos_header, sizeof(dos_header), 1, f);
    
    // DOS stub (just padding to reach PE header)
    unsigned char dos_stub[64] = {0};
    dos_stub[0] = 0x0E;  // push cs
    dos_stub[1] = 0x1F;  // pop ds
    dos_stub[2] = 0xBA;  // mov dx, offset message
    dos_stub[3] = 0x0E;
    dos_stub[4] = 0x00;
    dos_stub[5] = 0xB4;  // mov ah, 9
    dos_stub[6] = 0x09;
    dos_stub[7] = 0xCD;  // int 21h
    dos_stub[8] = 0x21;
    dos_stub[9] = 0xB8;  // mov ax, 4C01h
    dos_stub[10] = 0x01;
    dos_stub[11] = 0x4C;
    dos_stub[12] = 0xCD;  // int 21h
    dos_stub[13] = 0x21;
    fwrite(dos_stub, 1, dos_header_size - sizeof(dos_header), f);
    
    // PE Signature
    uint32_t pe_sig = 0x00004550;
    fwrite(&pe_sig, sizeof(pe_sig), 1, f);
    
    // COFF File Header
    IMAGE_FILE_HEADER file_header = {0};
    file_header.Machine = 0x8664;  // AMD64
    file_header.NumberOfSections = 1;
    file_header.TimeDateStamp = 0;
    file_header.PointerToSymbolTable = 0;
    file_header.NumberOfSymbols = 0;
    file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file_header.Characteristics = 0x2F;  // Executable image, large address aware, stripped, line nums stripped, local syms stripped
    fwrite(&file_header, sizeof(file_header), 1, f);
    
    // Optional Header
    IMAGE_OPTIONAL_HEADER64 opt_header = {0};
    opt_header.Magic = 0x20B;  // PE32+
    opt_header.MajorLinkerVersion = 1;
    opt_header.MinorLinkerVersion = 0;
    opt_header.SizeOfCode = code_aligned;
    opt_header.SizeOfInitializedData = 0;
    opt_header.SizeOfUninitializedData = 0;
    opt_header.AddressOfEntryPoint = section_alignment;  // Entry point RVA
    opt_header.BaseOfCode = section_alignment;
    opt_header.ImageBase = 0x140000000ULL;  // Default for x64
    opt_header.SectionAlignment = section_alignment;
    opt_header.FileAlignment = file_alignment;
    opt_header.MajorOperatingSystemVersion = 6;
    opt_header.MinorOperatingSystemVersion = 0;
    opt_header.MajorImageVersion = 0;
    opt_header.MinorImageVersion = 0;
    opt_header.MajorSubsystemVersion = 6;
    opt_header.MinorSubsystemVersion = 0;
    opt_header.Win32VersionValue = 0;
    opt_header.SizeOfImage = section_alignment * 2;  // Headers + one section
    opt_header.SizeOfHeaders = headers_aligned;
    opt_header.CheckSum = 0;
    opt_header.Subsystem = 3;  // IMAGE_SUBSYSTEM_WINDOWS_CUI
    opt_header.DllCharacteristics = 0x60;  // HIGH_ENTROPY_VA | DYNAMIC_BASE
    opt_header.SizeOfStackReserve = 0x100000;
    opt_header.SizeOfStackCommit = 0x1000;
    opt_header.SizeOfHeapReserve = 0x100000;
    opt_header.SizeOfHeapCommit = 0x1000;
    opt_header.LoaderFlags = 0;
    opt_header.NumberOfRvaAndSizes = 16;
    fwrite(&opt_header, sizeof(opt_header), 1, f);
    
    // Section Header
    IMAGE_SECTION_HEADER sect_header = {0};
    memcpy(sect_header.Name, ".text", 5);
    sect_header.VirtualSize = code_size;
    sect_header.VirtualAddress = section_alignment;
    sect_header.SizeOfRawData = code_aligned;
    sect_header.PointerToRawData = headers_aligned;
    sect_header.PointerToRelocations = 0;
    sect_header.PointerToLinenumbers = 0;
    sect_header.NumberOfRelocations = 0;
    sect_header.NumberOfLinenumbers = 0;
    sect_header.Characteristics = 0x60000020;  // CODE | EXECUTE | READ
    fwrite(&sect_header, sizeof(sect_header), 1, f);
    
    // Pad to file alignment
    uint32_t pad_size = headers_aligned - headers_size;
    unsigned char* pad = calloc(1, pad_size);
    fwrite(pad, 1, pad_size, f);
    free(pad);
    
    // Write code section
    fwrite(code, 1, code_size, f);
    
    // Pad code to file alignment
    uint32_t code_pad = code_aligned - code_size;
    unsigned char* code_padding = calloc(1, code_pad);
    fwrite(code_padding, 1, code_pad, f);
    free(code_padding);
    
    fclose(f);
    
    printf("Created %s\n", output_file);
    printf("  Headers: %u bytes (aligned to %u)\n", headers_size, headers_aligned);
    printf("  Code: %u bytes (aligned to %u)\n", code_size, code_aligned);
    printf("  Total: %u bytes\n", headers_aligned + code_aligned);
    printf("  Entry point: RVA 0x%X\n", section_alignment);
    printf("  Expected exit code: 42\n");
    
    return 0;
}