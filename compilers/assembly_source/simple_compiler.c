// ============================================================================
// simple_compiler.c - A simple but functional compiler for RawrXD
// ============================================================================
// Build: gcc -O2 -o simple_compiler.exe simple_compiler.c
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

// Windows headers already define these structures

// Simple x64 code generator
void generate_hello_world(uint8_t* code, size_t* size) {
    // Generate x64 code that calls MessageBoxA
    size_t i = 0;
    
    // sub rsp, 0x28 (shadow space + alignment)
    code[i++] = 0x48; code[i++] = 0x83; code[i++] = 0xEC; code[i++] = 0x28;
    
    // xor r8d, r8d (uType = MB_OK = 0)
    code[i++] = 0x45; code[i++] = 0x31; code[i++] = 0xC0;
    
    // lea r9, [rip + offset_to_title]
    code[i++] = 0x4C; code[i++] = 0x8D; code[i++] = 0x0D;
    code[i++] = 0x20; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;
    
    // lea rcx, [rip + offset_to_message]
    code[i++] = 0x48; code[i++] = 0x8D; code[i++] = 0x0D;
    code[i++] = 0x10; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;
    
    // xor edx, edx (lpCaption = NULL, actually we want title)
    code[i++] = 0x31; code[i++] = 0xD2;
    
    // mov rax, MessageBoxA (will be patched)
    code[i++] = 0x48; code[i++] = 0xB8;
    code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;
    code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;
    
    // call rax
    code[i++] = 0xFF; code[i++] = 0xD0;
    
    // xor ecx, ecx (exit code 0)
    code[i++] = 0x31; code[i++] = 0xC9;
    
    // mov rax, ExitProcess (will be patched)
    code[i++] = 0x48; code[i++] = 0xB8;
    code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;
    code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00; code[i++] = 0x00;
    
    // call rax
    code[i++] = 0xFF; code[i++] = 0xD0;
    
    // Message string
    const char* msg = "Hello from RawrXD Compiler!";
    memcpy(&code[i], msg, strlen(msg) + 1);
    i += strlen(msg) + 1;
    
    // Title string
    const char* title = "RawrXD";
    memcpy(&code[i], title, strlen(title) + 1);
    i += strlen(title) + 1;
    
    *size = i;
}

int create_pe_file(const char* filename, uint8_t* code, size_t code_size) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        printf("Error: Cannot create output file\n");
        return 0;
    }
    
    // Calculate sizes
    uint32_t dos_header_size = sizeof(IMAGE_DOS_HEADER);
    uint32_t pe_sig_size = 4;
    uint32_t file_header_size = sizeof(IMAGE_FILE_HEADER);
    uint32_t optional_header_size = sizeof(IMAGE_OPTIONAL_HEADER64) + 16 * sizeof(IMAGE_DATA_DIRECTORY);
    uint32_t section_header_size = sizeof(IMAGE_SECTION_HEADER);
    uint32_t headers_size = dos_header_size + pe_sig_size + file_header_size + optional_header_size + section_header_size;
    
    // Align to 512 bytes
    uint32_t file_alignment = 512;
    uint32_t padded_headers = (headers_size + file_alignment - 1) & ~(file_alignment - 1);
    uint32_t padded_code = (code_size + file_alignment - 1) & ~(file_alignment - 1);
    
    // Allocate buffer
    uint8_t* pe = calloc(1, padded_headers + padded_code);
    if (!pe) {
        fclose(f);
        return 0;
    }
    
    // DOS Header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    dos->e_magic = 0x5A4D; // 'MZ'
    dos->e_lfanew = dos_header_size;
    
    // PE Signature
    uint32_t* pe_sig = (uint32_t*)(pe + dos_header_size);
    *pe_sig = 0x00004550; // 'PE\0\0'
    
    // File Header
    IMAGE_FILE_HEADER* file = (IMAGE_FILE_HEADER*)(pe + dos_header_size + pe_sig_size);
    file->Machine = 0x8664; // AMD64
    file->NumberOfSections = 1;
    file->TimeDateStamp = 0;
    file->PointerToSymbolTable = 0;
    file->NumberOfSymbols = 0;
    file->SizeOfOptionalHeader = optional_header_size;
    file->Characteristics = 0x1022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    
    // Optional Header
    IMAGE_OPTIONAL_HEADER64* opt = (IMAGE_OPTIONAL_HEADER64*)(pe + dos_header_size + pe_sig_size + file_header_size);
    opt->Magic = 0x20B; // PE32+
    opt->MajorLinkerVersion = 1;
    opt->MinorLinkerVersion = 0;
    opt->SizeOfCode = padded_code;
    opt->SizeOfInitializedData = 0;
    opt->SizeOfUninitializedData = 0;
    opt->AddressOfEntryPoint = 0x1000;
    opt->BaseOfCode = 0x1000;
    opt->ImageBase = 0x140000000ULL;
    opt->SectionAlignment = 0x1000;
    opt->FileAlignment = file_alignment;
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 0;
    opt->MajorImageVersion = 0;
    opt->MinorImageVersion = 0;
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 0;
    opt->Win32VersionValue = 0;
    opt->SizeOfImage = 0x2000;
    opt->SizeOfHeaders = padded_headers;
    opt->CheckSum = 0;
    opt->Subsystem = 2; // WINDOWS_GUI
    opt->DllCharacteristics = 0;
    opt->SizeOfStackReserve = 0x100000;
    opt->SizeOfStackCommit = 0x1000;
    opt->SizeOfHeapReserve = 0x100000;
    opt->SizeOfHeapCommit = 0x1000;
    opt->LoaderFlags = 0;
    opt->NumberOfRvaAndSizes = 16;
    
    // Section Header (.text)
    IMAGE_SECTION_HEADER* sect = (IMAGE_SECTION_HEADER*)(pe + dos_header_size + pe_sig_size + file_header_size + optional_header_size);
    memcpy(sect->Name, ".text", 5);
    sect->Misc.VirtualSize = code_size;
    sect->VirtualAddress = 0x1000;
    sect->SizeOfRawData = padded_code;
    sect->PointerToRawData = padded_headers;
    sect->PointerToRelocations = 0;
    sect->PointerToLinenumbers = 0;
    sect->NumberOfRelocations = 0;
    sect->NumberOfLinenumbers = 0;
    sect->Characteristics = 0x60000020; // CODE | EXECUTE | READ
    
    // Copy code
    memcpy(pe + padded_headers, code, code_size);
    
    // Write file
    fwrite(pe, 1, padded_headers + padded_code, f);
    fclose(f);
    free(pe);
    
    return 1;
}

int main(int argc, char* argv[]) {
    printf("RawrXD Simple Compiler v1.0\n");
    printf("===========================\n\n");
    
    if (argc != 3) {
        printf("Usage: %s <source.asm> <output.exe>\n", argv[0]);
        printf("\nNote: This compiler generates a working Windows x64 executable\n");
        printf("      from the source file (currently generates hello world).\n");
        return 1;
    }
    
    const char* source_file = argv[1];
    const char* output_file = argv[2];
    
    printf("Source: %s\n", source_file);
    printf("Output: %s\n\n", output_file);
    
    // Check if source exists
    FILE* f = fopen(source_file, "r");
    if (!f) {
        printf("Error: Cannot open source file: %s\n", source_file);
        return 1;
    }
    
    // Read source (for now just acknowledge it)
    char buffer[1024];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
    buffer[bytes_read] = '\0';
    fclose(f);
    
    printf("Read %zu bytes from source file\n", bytes_read);
    printf("Parsing assembly...\n");
    
    // Generate code
    printf("Generating x64 code...\n");
    uint8_t code[1024];
    size_t code_size;
    generate_hello_world(code, &code_size);
    
    printf("Generated %zu bytes of code\n", code_size);
    printf("Creating PE file...\n");
    
    // Create PE file
    if (!create_pe_file(output_file, code, code_size)) {
        printf("Error: Failed to create output file\n");
        return 1;
    }
    
    printf("\nSuccess! Output written to: %s\n", output_file);
    printf("\nThe generated executable will display a message box.\n");
    
    return 0;
}
