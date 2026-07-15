//=============================================================================
// binary_patch_pipeline.c - Binary Patching Pipeline using Native Toolchain
// Part of RawrXD Native Toolchain - RE Integration
// Complete workflow: Analyze → Disassemble → Modify → Reassemble → Verify
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include <time.h>

#define PATCH_PIPELINE_VERSION "1.0.0"
#define MAX_PATH_LENGTH 512
#define MAX_PATCH_SIZE 4096
#define MAX_SECTIONS 64

//=============================================================================
// PE Structures
//=============================================================================

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
} COFF_FILE_HEADER;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DATA_DIRECTORY;

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
    DATA_DIRECTORY DataDirectory[16];
} OPTIONAL_HEADER_64;

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

#pragma pack(pop)

//=============================================================================
// Patch Types
//=============================================================================

typedef enum {
    PATCH_TYPE_RAW,           // Raw byte replacement
    PATCH_TYPE_ASM,           // Assembly code replacement
    PATCH_TYPE_JUMP,          // Insert jump to new code
    PATCH_TYPE_CALL,          // Insert call to new code
    PATCH_TYPE_NOP,           // NOP out instructions
    PATCH_TYPE_IMPORT         // Add/modify import
} PatchType;

typedef struct {
    PatchType type;
    uint64_t target_rva;      // Target RVA in original binary
    uint64_t target_size;     // Size of region to patch
    
    // Patch data
    uint8_t* new_bytes;
    size_t new_byte_count;
    char* new_asm;            // Assembly code (if PATCH_TYPE_ASM)
    
    // Metadata
    char description[256];
    int verified;             // Verification flag
} BinaryPatch;

typedef struct {
    BinaryPatch* patches;
    int count;
    int capacity;
} PatchList;

typedef struct {
    // Original binary info
    char original_path[MAX_PATH_LENGTH];
    uint8_t* original_data;
    size_t original_size;
    uint64_t image_base;
    
    // PE headers
    DOS_HEADER* dos_header;
    COFF_FILE_HEADER* coff_header;
    OPTIONAL_HEADER_64* optional_header;
    SECTION_HEADER* sections;
    int section_count;
    
    // Patch info
    PatchList* patches;
    
    // Output
    char output_path[MAX_PATH_LENGTH];
    uint8_t* output_data;
    size_t output_size;
} BinaryPatchContext;

//=============================================================================
// PE Parser
//=============================================================================

BinaryPatchContext* patch_context_create(void) {
    BinaryPatchContext* ctx = (BinaryPatchContext*)calloc(1, sizeof(BinaryPatchContext));
    if (!ctx) return NULL;
    
    ctx->patches = (PatchList*)calloc(1, sizeof(PatchList));
    if (!ctx->patches) {
        free(ctx);
        return NULL;
    }
    
    ctx->patches->capacity = 16;
    ctx->patches->patches = (BinaryPatch*)calloc(ctx->patches->capacity, sizeof(BinaryPatch));
    if (!ctx->patches->patches) {
        free(ctx->patches);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void patch_context_destroy(BinaryPatchContext* ctx) {
    if (ctx) {
        if (ctx->original_data) free(ctx->original_data);
        if (ctx->output_data) free(ctx->output_data);
        if (ctx->patches) {
            for (int i = 0; i < ctx->patches->count; i++) {
                if (ctx->patches->patches[i].new_bytes) {
                    free(ctx->patches->patches[i].new_bytes);
                }
                if (ctx->patches->patches[i].new_asm) {
                    free(ctx->patches->patches[i].new_asm);
                }
            }
            free(ctx->patches->patches);
            free(ctx->patches);
        }
        free(ctx);
    }
}

int load_pe_binary(BinaryPatchContext* ctx, const char* path) {
    printf("[INFO] Loading PE binary: %s\n", path);
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        printf("[ERROR] Cannot open file: %s\n", path);
        return 0;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    ctx->original_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    // Allocate and read
    ctx->original_data = (uint8_t*)malloc(ctx->original_size);
    if (!ctx->original_data) {
        printf("[ERROR] Failed to allocate memory for binary\n");
        fclose(f);
        return 0;
    }
    
    fread(ctx->original_data, 1, ctx->original_size, f);
    fclose(f);
    
    strncpy(ctx->original_path, path, MAX_PATH_LENGTH - 1);
    
    // Parse PE headers
    ctx->dos_header = (DOS_HEADER*)ctx->original_data;
    if (ctx->dos_header->e_magic != 0x5A4D) {  // "MZ"
        printf("[ERROR] Invalid DOS signature (not a PE file)\n");
        return 0;
    }
    
    uint32_t pe_offset = ctx->dos_header->e_lfanew;
    uint32_t* pe_sig = (uint32_t*)(ctx->original_data + pe_offset);
    if (*pe_sig != 0x00004550) {  // "PE\0\0"
        printf("[ERROR] Invalid PE signature\n");
        return 0;
    }
    
    ctx->coff_header = (COFF_FILE_HEADER*)(ctx->original_data + pe_offset + 4);
    ctx->optional_header = (OPTIONAL_HEADER_64*)(ctx->original_data + pe_offset + 4 + sizeof(COFF_FILE_HEADER));
    ctx->sections = (SECTION_HEADER*)(ctx->original_data + pe_offset + 4 + sizeof(COFF_FILE_HEADER) + ctx->coff_header->SizeOfOptionalHeader);
    ctx->section_count = ctx->coff_header->NumberOfSections;
    ctx->image_base = ctx->optional_header->ImageBase;
    
    printf("[INFO] PE loaded successfully:\n");
    printf("  Machine: 0x%04X\n", ctx->coff_header->Machine);
    printf("  Sections: %d\n", ctx->section_count);
    printf("  Image Base: 0x%llX\n", ctx->image_base);
    printf("  Entry Point: 0x%08X\n", ctx->optional_header->AddressOfEntryPoint);
    
    return 1;
}

// Find section containing RVA
SECTION_HEADER* find_section_by_rva(BinaryPatchContext* ctx, uint64_t rva) {
    for (int i = 0; i < ctx->section_count; i++) {
        SECTION_HEADER* sect = &ctx->sections[i];
        if (rva >= sect->VirtualAddress && 
            rva < sect->VirtualAddress + sect->VirtualSize) {
            return sect;
        }
    }
    return NULL;
}

// Convert RVA to file offset
uint32_t rva_to_file_offset(BinaryPatchContext* ctx, uint64_t rva) {
    SECTION_HEADER* sect = find_section_by_rva(ctx, rva);
    if (!sect) return 0;
    
    return sect->PointerToRawData + (rva - sect->VirtualAddress);
}

//=============================================================================
// Patch Management
//=============================================================================

int add_patch_raw(BinaryPatchContext* ctx, uint64_t rva, const uint8_t* bytes, size_t count, const char* desc) {
    if (ctx->patches->count >= ctx->patches->capacity) {
        int new_cap = ctx->patches->capacity * 2;
        BinaryPatch* new_patches = (BinaryPatch*)realloc(ctx->patches->patches, new_cap * sizeof(BinaryPatch));
        if (!new_patches) return 0;
        ctx->patches->patches = new_patches;
        ctx->patches->capacity = new_cap;
    }
    
    BinaryPatch* patch = &ctx->patches->patches[ctx->patches->count];
    memset(patch, 0, sizeof(BinaryPatch));
    
    patch->type = PATCH_TYPE_RAW;
    patch->target_rva = rva;
    patch->target_size = count;
    patch->new_bytes = (uint8_t*)malloc(count);
    memcpy(patch->new_bytes, bytes, count);
    patch->new_byte_count = count;
    strncpy(patch->description, desc ? desc : "Raw patch", 255);
    
    ctx->patches->count++;
    return 1;
}

int add_patch_asm(BinaryPatchContext* ctx, uint64_t rva, const char* asm_code, const char* desc) {
    if (ctx->patches->count >= ctx->patches->capacity) {
        int new_cap = ctx->patches->capacity * 2;
        BinaryPatch* new_patches = (BinaryPatch*)realloc(ctx->patches->patches, new_cap * sizeof(BinaryPatch));
        if (!new_patches) return 0;
        ctx->patches->patches = new_patches;
        ctx->patches->capacity = new_cap;
    }
    
    BinaryPatch* patch = &ctx->patches->patches[ctx->patches->count];
    memset(patch, 0, sizeof(BinaryPatch));
    
    patch->type = PATCH_TYPE_ASM;
    patch->target_rva = rva;
    patch->new_asm = _strdup(asm_code);
    strncpy(patch->description, desc ? desc : "ASM patch", 255);
    
    ctx->patches->count++;
    return 1;
}

int add_patch_nop(BinaryPatchContext* ctx, uint64_t rva, size_t count, const char* desc) {
    uint8_t* nops = (uint8_t*)malloc(count);
    memset(nops, 0x90, count);  // NOP = 0x90
    int result = add_patch_raw(ctx, rva, nops, count, desc ? desc : "NOP patch");
    free(nops);
    return result;
}

//=============================================================================
// Assembly Assembly (using native toolchain)
//=============================================================================

// Assemble patch code using native assembler
int assemble_patch_code(const char* asm_code, uint8_t** out_bytes, size_t* out_size) {
    // Write assembly to temp file
    char temp_asm[MAX_PATH_LENGTH];
    char temp_obj[MAX_PATH_LENGTH];
    
    GetTempPathA(MAX_PATH_LENGTH, temp_asm);
    strcat(temp_asm, "patch_temp.asm");
    GetTempPathA(MAX_PATH_LENGTH, temp_obj);
    strcat(temp_obj, "patch_temp.obj");
    
    FILE* f = fopen(temp_asm, "w");
    if (!f) return 0;
    
    // Write minimal assembly wrapper
    fprintf(f, ".code\n");
    fprintf(f, "patch_code:\n");
    fprintf(f, "%s\n", asm_code);
    fprintf(f, "ret\n");
    fprintf(f, "end\n");
    fclose(f);
    
    // Assemble using native assembler
    char command[MAX_PATH_LENGTH * 4];
    snprintf(command, sizeof(command), "minimal_assembler.exe \"%s\" \"%s\" 2>&1",
             temp_asm, temp_obj);
    
    int exit_code = system(command);
    
    // Clean up temp asm
    DeleteFileA(temp_asm);
    
    if (exit_code != 0) {
        DeleteFileA(temp_obj);
        return 0;
    }
    
    // Read object file and extract code
    // For now, simplified: read the object file directly
    FILE* obj = fopen(temp_obj, "rb");
    if (!obj) {
        DeleteFileA(temp_obj);
        return 0;
    }
    
    fseek(obj, 0, SEEK_END);
    *out_size = ftell(obj);
    fseek(obj, 0, SEEK_SET);
    
    *out_bytes = (uint8_t*)malloc(*out_size);
    fread(*out_bytes, 1, *out_size, obj);
    fclose(obj);
    
    DeleteFileA(temp_obj);
    
    return 1;
}

//=============================================================================
// Patch Application
//=============================================================================

int apply_patches(BinaryPatchContext* ctx) {
    printf("\n[INFO] Applying %d patches...\n", ctx->patches->count);
    
    // Copy original to output
    ctx->output_size = ctx->original_size;
    ctx->output_data = (uint8_t*)malloc(ctx->output_size);
    memcpy(ctx->output_data, ctx->original_data, ctx->original_size);
    
    int success_count = 0;
    int fail_count = 0;
    
    for (int i = 0; i < ctx->patches->count; i++) {
        BinaryPatch* patch = &ctx->patches->patches[i];
        
        printf("  [%d/%d] %s @ RVA 0x%llX: ", i + 1, ctx->patches->count, 
               patch->description, patch->target_rva);
        
        // Handle ASM patches
        if (patch->type == PATCH_TYPE_ASM && patch->new_asm) {
            if (!assemble_patch_code(patch->new_asm, &patch->new_bytes, &patch->new_byte_count)) {
                printf("FAILED (assembly)\n");
                fail_count++;
                continue;
            }
        }
        
        // Find file offset
        uint32_t file_offset = rva_to_file_offset(ctx, patch->target_rva);
        if (file_offset == 0) {
            printf("FAILED (invalid RVA)\n");
            fail_count++;
            continue;
        }
        
        // Check bounds
        if (file_offset + patch->new_byte_count > ctx->output_size) {
            printf("FAILED (out of bounds)\n");
            fail_count++;
            continue;
        }
        
        // Apply patch
        memcpy(ctx->output_data + file_offset, patch->new_bytes, patch->new_byte_count);
        patch->verified = 1;
        success_count++;
        
        printf("OK (%zu bytes)\n", patch->new_byte_count);
    }
    
    printf("\n[RESULT] Applied: %d, Failed: %d\n", success_count, fail_count);
    return fail_count == 0;
}

//=============================================================================
// Output Generation
//=============================================================================

int save_patched_binary(BinaryPatchContext* ctx, const char* output_path) {
    printf("[INFO] Saving patched binary: %s\n", output_path);
    
    FILE* f = fopen(output_path, "wb");
    if (!f) {
        printf("[ERROR] Cannot create output file\n");
        return 0;
    }
    
    fwrite(ctx->output_data, 1, ctx->output_size, f);
    fclose(f);
    
    strncpy(ctx->output_path, output_path, MAX_PATH_LENGTH - 1);
    
    printf("[SUCCESS] Saved %zu bytes\n", ctx->output_size);
    return 1;
}

//=============================================================================
// Verification
//=============================================================================

int verify_patch(BinaryPatchContext* ctx, int patch_index) {
    if (patch_index < 0 || patch_index >= ctx->patches->count) return 0;
    
    BinaryPatch* patch = &ctx->patches->patches[patch_index];
    uint32_t file_offset = rva_to_file_offset(ctx, patch->target_rva);
    
    if (file_offset == 0) return 0;
    
    // Compare bytes
    int match = (memcmp(ctx->output_data + file_offset, patch->new_bytes, patch->new_byte_count) == 0);
    patch->verified = match;
    
    return match;
}

//=============================================================================
// Command Line Interface
//=============================================================================

void print_usage(const char* prog) {
    printf("Binary Patch Pipeline v%s\n", PATCH_PIPELINE_VERSION);
    printf("Usage: %s [command] [options]\n", prog);
    printf("\nCommands:\n");
    printf("  /patch <binary> <output>    Apply patches to binary\n");
    printf("  /add-raw <rva> <bytes>      Add raw byte patch\n");
    printf("  /add-asm <rva> <code>       Add assembly patch\n");
    printf("  /add-nop <rva> <count>       Add NOP patch\n");
    printf("  /verify                     Verify applied patches\n");
    printf("  /list                       List pending patches\n");
    printf("\nExamples:\n");
    printf("  %s /patch original.exe patched.exe\n", prog);
    printf("  %s /add-raw 0x1234 \"90 90 90\" /patch in.exe out.exe\n", prog);
    printf("  %s /add-asm 0x1000 \"xor rax, rax\\ninc rax\" /patch in.exe out.exe\n", prog);
}

// Parse hex string to bytes
int parse_hex_bytes(const char* hex_str, uint8_t* bytes, int max_bytes) {
    int count = 0;
    const char* p = hex_str;
    
    while (*p && count < max_bytes) {
        // Skip whitespace
        while (*p && isspace(*p)) p++;
        if (!*p) break;
        
        // Parse hex byte
        char hex[3] = {p[0], p[1] ? p[1] : '0', '\0'};
        bytes[count++] = (uint8_t)strtoul(hex, NULL, 16);
        p += 2;
    }
    
    return count;
}

int main(int argc, char* argv[]) {
    printf("=============================================================================\n");
    printf("  Binary Patch Pipeline v%s\n", PATCH_PIPELINE_VERSION);
    printf("  RawrXD Native Toolchain - RE Integration\n");
    printf("=============================================================================\n\n");
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    BinaryPatchContext* ctx = patch_context_create();
    if (!ctx) {
        printf("[ERROR] Failed to create patch context\n");
        return 1;
    }
    
    const char* input_file = NULL;
    const char* output_file = NULL;
    int do_patch = 0;
    int do_verify = 0;
    int do_list = 0;
    
    // Parse commands
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "/patch") == 0 && i + 2 < argc) {
            input_file = argv[++i];
            output_file = argv[++i];
            do_patch = 1;
        } else if (strcmp(argv[i], "/add-raw") == 0 && i + 2 < argc) {
            uint64_t rva = strtoull(argv[++i], NULL, 0);
            const char* hex_bytes = argv[++i];
            uint8_t bytes[256];
            int count = parse_hex_bytes(hex_bytes, bytes, 256);
            if (count > 0) {
                add_patch_raw(ctx, rva, bytes, count, "Raw byte patch");
                printf("[ADDED] Raw patch @ 0x%llX (%d bytes)\n", rva, count);
            }
        } else if (strcmp(argv[i], "/add-asm") == 0 && i + 2 < argc) {
            uint64_t rva = strtoull(argv[++i], NULL, 0);
            const char* asm_code = argv[++i];
            add_patch_asm(ctx, rva, asm_code, "Assembly patch");
            printf("[ADDED] ASM patch @ 0x%llX\n", rva);
        } else if (strcmp(argv[i], "/add-nop") == 0 && i + 2 < argc) {
            uint64_t rva = strtoull(argv[++i], NULL, 0);
            size_t count = strtoull(argv[++i], NULL, 0);
            add_patch_nop(ctx, rva, count, "NOP patch");
            printf("[ADDED] NOP patch @ 0x%llX (%zu bytes)\n", rva, count);
        } else if (strcmp(argv[i], "/verify") == 0) {
            do_verify = 1;
        } else if (strcmp(argv[i], "/list") == 0) {
            do_list = 1;
        }
    }
    
    // List patches
    if (do_list || ctx->patches->count > 0) {
        printf("\n[PENDING PATCHES: %d]\n", ctx->patches->count);
        for (int i = 0; i < ctx->patches->count; i++) {
            BinaryPatch* p = &ctx->patches->patches[i];
            printf("  [%d] %s @ RVA 0x%llX (%zu bytes)\n", 
                   i + 1, p->description, p->target_rva, p->new_byte_count);
        }
        printf("\n");
    }
    
    // Apply patches
    if (do_patch && input_file && output_file) {
        if (!load_pe_binary(ctx, input_file)) {
            patch_context_destroy(ctx);
            return 1;
        }
        
        if (!apply_patches(ctx)) {
            printf("[WARNING] Some patches failed to apply\n");
        }
        
        if (!save_patched_binary(ctx, output_file)) {
            patch_context_destroy(ctx);
            return 1;
        }
        
        // Verify if requested
        if (do_verify) {
            printf("\n[VERIFICATION]\n");
            int verified = 0;
            for (int i = 0; i < ctx->patches->count; i++) {
                if (verify_patch(ctx, i)) {
                    verified++;
                    printf("  [%d] VERIFIED\n", i + 1);
                } else {
                    printf("  [%d] MISMATCH\n", i + 1);
                }
            }
            printf("\n[RESULT] Verified: %d/%d\n", verified, ctx->patches->count);
        }
    }
    
    patch_context_destroy(ctx);
    return 0;
}
