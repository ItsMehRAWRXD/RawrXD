// PE Analyzer - Production-ready PE header diagnostic tool
// Analyzes PE headers to identify issues causing "This app can't run" errors

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PE_ANALYZER_VERSION "1.0.0"
#define MAX_SECTIONS 96
#define MAX_IMPORTS 1024

typedef struct {
    BOOL isValid;
    BOOL is64Bit;
    BOOL isPE32Plus;
    WORD machineType;
    WORD subsystem;
    DWORD entryPoint;
    ULONGLONG imageBase;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    WORD numSections;
    DWORD checksum;
    WORD dllCharacteristics;
    BOOL hasImports;
    BOOL hasExports;
    BOOL hasRelocations;
    BOOL hasTLS;
    BOOL hasExceptionTable;
    char errors[4096];
    char warnings[4096];
} PEAnalysisResult;

void LogError(PEAnalysisResult* result, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = strlen(result->errors);
    vsnprintf(result->errors + len, sizeof(result->errors) - len - 1, fmt, args);
    va_end(args);
}

void LogWarning(PEAnalysisResult* result, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    size_t len = strlen(result->warnings);
    vsnprintf(result->warnings + len, sizeof(result->warnings) - len - 1, fmt, args);
    va_end(args);
}

const char* GetMachineTypeName(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386: return "x86 (32-bit)";
        case IMAGE_FILE_MACHINE_AMD64: return "x64 (64-bit)";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        case IMAGE_FILE_MACHINE_ARM: return "ARM";
        case IMAGE_FILE_MACHINE_THUMB: return "Thumb";
        default: return "Unknown/Invalid";
    }
}

const char* GetSubsystemName(WORD subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows Console";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI Application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI Boot Driver";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "EFI Runtime Driver";
        case IMAGE_SUBSYSTEM_EFI_ROM: return "EFI ROM";
        case IMAGE_SUBSYSTEM_XBOX: return "Xbox";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "Boot Application";
        default: return "Unknown/Invalid";
    }
}

PEAnalysisResult AnalyzePEFile(const char* filename) {
    PEAnalysisResult result = {0};
    result.isValid = FALSE;
    result.errors[0] = '\0';
    result.warnings[0] = '\0';
    
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogError(&result, "Failed to open file: %s (Error: %lu)\n", filename, GetLastError());
        return result;
    }
    
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart < 64) {
        LogError(&result, "File too small to be a valid PE: %s\n", filename);
        CloseHandle(hFile);
        return result;
    }
    
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        LogError(&result, "Failed to create file mapping: %lu\n", GetLastError());
        CloseHandle(hFile);
        return result;
    }
    
    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        LogError(&result, "Failed to map view of file: %lu\n", GetLastError());
        CloseHandle(hMap);
        CloseHandle(hFile);
        return result;
    }
    
    // Check DOS header
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError(&result, "Invalid DOS signature: expected 0x%04X, got 0x%04X\n", 
                 IMAGE_DOS_SIGNATURE, dos->e_magic);
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return result;
    }
    
    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || 
        dos->e_lfanew > (DWORD)fileSize.QuadPart - sizeof(IMAGE_NT_HEADERS64)) {
        LogError(&result, "Invalid e_lfanew offset: %lu\n", dos->e_lfanew);
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return result;
    }
    
    // Check NT headers
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        LogError(&result, "Invalid NT signature: expected 0x%08X, got 0x%08X\n", 
                 IMAGE_NT_SIGNATURE, nt->Signature);
        UnmapViewOfFile(base);
        CloseHandle(hMap);
        CloseHandle(hFile);
        return result;
    }
    
    result.isValid = TRUE;
    result.machineType = nt->FileHeader.Machine;
    result.subsystem = nt->OptionalHeader.Subsystem;
    result.entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    result.imageBase = nt->OptionalHeader.ImageBase;
    result.sectionAlignment = nt->OptionalHeader.SectionAlignment;
    result.fileAlignment = nt->OptionalHeader.FileAlignment;
    result.numSections = nt->FileHeader.NumberOfSections;
    result.checksum = nt->OptionalHeader.CheckSum;
    result.dllCharacteristics = nt->OptionalHeader.DllCharacteristics;
    
    // Validate machine type
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 &&
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64) {
        LogError(&result, "CRITICAL: Unsupported machine type 0x%04X (%s)\n", 
                 nt->FileHeader.Machine, GetMachineTypeName(nt->FileHeader.Machine));
        LogError(&result, "  Windows will refuse to run this executable!\n");
    }
    
    // Check if 64-bit
    result.is64Bit = (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
                      nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64);
    
    // Validate optional header magic
    if (nt->OptionalHeader.Magic == 0x20B) {
        result.isPE32Plus = TRUE;
    } else if (nt->OptionalHeader.Magic == 0x10B) {
        result.isPE32Plus = FALSE;
        if (result.is64Bit) {
            LogError(&result, "CRITICAL: 64-bit machine type but PE32 (32-bit) header!\n");
            LogError(&result, "  This mismatch WILL cause crashes or blue screens!\n");
        }
    } else {
        LogError(&result, "CRITICAL: Unknown optional header magic: 0x%04X\n", 
                 nt->OptionalHeader.Magic);
        LogError(&result, "  Expected 0x10B (PE32) or 0x20B (PE32+)\n");
    }
    
    // Validate subsystem
    if (nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI &&
        nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI &&
        nt->OptionalHeader.Subsystem != IMAGE_SUBSYSTEM_EFI_APPLICATION) {
        LogWarning(&result, "WARNING: Unusual subsystem: %s (0x%04X)\n", 
                   GetSubsystemName(nt->OptionalHeader.Subsystem), nt->OptionalHeader.Subsystem);
    }
    
    // Check entry point
    if (nt->OptionalHeader.AddressOfEntryPoint == 0) {
        LogError(&result, "CRITICAL: Entry point is NULL!\n");
        LogError(&result, "  Executable has no starting address!\n");
    }
    
    // Check alignments
    if (nt->OptionalHeader.SectionAlignment == 0) {
        LogError(&result, "CRITICAL: Section alignment is zero!\n");
    } else if (nt->OptionalHeader.SectionAlignment < nt->OptionalHeader.FileAlignment) {
        LogError(&result, "CRITICAL: Section alignment < file alignment!\n");
    }
    
    if (nt->OptionalHeader.FileAlignment == 0) {
        LogError(&result, "CRITICAL: File alignment is zero!\n");
    } else if ((nt->OptionalHeader.FileAlignment & (nt->OptionalHeader.FileAlignment - 1)) != 0) {
        LogError(&result, "CRITICAL: File alignment is not power of 2!\n");
    }
    
    // Check number of sections
    if (nt->FileHeader.NumberOfSections == 0) {
        LogError(&result, "CRITICAL: No sections in executable!\n");
    } else if (nt->FileHeader.NumberOfSections > MAX_SECTIONS) {
        LogWarning(&result, "WARNING: Unusual number of sections: %d\n", nt->FileHeader.NumberOfSections);
    }
    
    // Check data directories
    IMAGE_DATA_DIRECTORY* dataDirs = nt->OptionalHeader.DataDirectory;
    
    // Imports
    if (dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
        result.hasImports = TRUE;
    }
    
    // Exports
    if (dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
        result.hasExports = TRUE;
    }
    
    // Relocations
    if (dataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
        result.hasRelocations = TRUE;
    }
    
    // TLS
    if (dataDirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0) {
        result.hasTLS = TRUE;
    }
    
    // Exception table
    if (dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0) {
        result.hasExceptionTable = TRUE;
    }
    
    // Validate section headers
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections && i < MAX_SECTIONS; i++) {
        if (sections[i].VirtualAddress == 0 && sections[i].SizeOfRawData > 0) {
            LogWarning(&result, "WARNING: Section %d has zero VA but non-zero size\n", i);
        }
        
        if (sections[i].PointerToRawData == 0 && sections[i].SizeOfRawData > 0) {
            LogWarning(&result, "WARNING: Section %d has zero file offset but non-zero size\n", i);
        }
        
        // Check for executable code in data section
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(sections[i].Characteristics & IMAGE_SCN_CNT_CODE)) {
            LogWarning(&result, "WARNING: Section %.8s has execute permission but not marked as code\n",
                      sections[i].Name);
        }
    }
    
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    return result;
}

void PrintAnalysisReport(const char* filename, const PEAnalysisResult* result) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║           PE ANALYSIS REPORT - %s\n", PE_ANALYZER_VERSION);
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("File: %s\n", filename);
    printf("Status: %s\n", result->isValid ? "VALID PE FILE" : "INVALID/CORRUPT");
    printf("\n");
    
    if (!result->isValid) {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║ ❌ ERRORS - File cannot be analyzed\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        printf("%s\n", result->errors);
        return;
    }
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║ FILE HEADER\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("  Machine Type:     0x%04X (%s) %s\n", 
           result->machineType, 
           GetMachineTypeName(result->machineType),
           result->machineType == IMAGE_FILE_MACHINE_AMD64 ? "✓" : "⚠");
    printf("  Number of Sections: %d\n", result->numSections);
    printf("  Timestamp:        %s", ctime(&(time_t){time(NULL)}));
    printf("\n");
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║ OPTIONAL HEADER\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("  Magic:            0x%04X (%s) %s\n",
           result->isPE32Plus ? 0x20B : 0x10B,
           result->isPE32Plus ? "PE32+ (64-bit)" : "PE32 (32-bit)",
           result->isPE32Plus == result->is64Bit ? "✓" : "❌ MISMATCH!");
    printf("  Entry Point:      0x%08X\n", result->entryPoint);
    printf("  Image Base:       0x%016llX\n", result->imageBase);
    printf("  Subsystem:        %s\n", GetSubsystemName(result->subsystem));
    printf("  Section Align:    0x%08X\n", result->sectionAlignment);
    printf("  File Align:       0x%08X\n", result->fileAlignment);
    printf("  Checksum:         0x%08X %s\n", result->checksum,
           result->checksum == 0 ? "⚠ (not validated)" : "✓");
    printf("\n");
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║ DATA DIRECTORIES\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("  Imports:    %s\n", result->hasImports ? "✓ Present" : "✗ None");
    printf("  Exports:    %s\n", result->hasExports ? "✓ Present" : "✗ None");
    printf("  Relocations:%s\n", result->hasRelocations ? "✓ Present" : "✗ None");
    printf("  TLS:        %s\n", result->hasTLS ? "✓ Present" : "✗ None");
    printf("  Exceptions: %s\n", result->hasExceptionTable ? "✓ Present" : "✗ None");
    printf("\n");
    
    if (strlen(result->errors) > 0) {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║ ❌ CRITICAL ERRORS\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        printf("%s", result->errors);
        printf("\n");
    }
    
    if (strlen(result->warnings) > 0) {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║ ⚠️  WARNINGS\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        printf("%s", result->warnings);
        printf("\n");
    }
    
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║ VERDICT: %s\n", 
           strlen(result->errors) > 0 ? "❌ WILL NOT RUN" : 
           (strlen(result->warnings) > 0 ? "⚠️  MAY HAVE ISSUES" : "✅ HEALTHY"));
    printf("╚════════════════════════════════════════════════════════════════╝\n");
}

int main(int argc, char** argv) {
    printf("PE Analyzer v%s - Production PE Header Diagnostic Tool\n", PE_ANALYZER_VERSION);
    printf("Copyright (c) 2025 RawrXD\n");
    printf("\n");
    
    if (argc < 2) {
        printf("Usage: %s <PE file> [PE file 2] ... [PE file N]\n", argv[0]);
        printf("\n");
        printf("Analyzes PE headers to identify issues causing:\n");
        printf("  - 'This app can't run on your PC' errors\n");
        printf("  - Blue screens (BSOD)\n");
        printf("  - Silent crashes\n");
        printf("\n");
        printf("Exit codes:\n");
        printf("  0 = All files analyzed successfully\n");
        printf("  1 = One or more files have critical errors\n");
        printf("  2 = Usage error\n");
        return 2;
    }
    
    int exitCode = 0;
    
    for (int i = 1; i < argc; i++) {
        PEAnalysisResult result = AnalyzePEFile(argv[i]);
        PrintAnalysisReport(argv[i], &result);
        
        if (!result.isValid || strlen(result.errors) > 0) {
            exitCode = 1;
        }
        
        if (i < argc - 1) {
            printf("\n");
            printf("═══════════════════════════════════════════════════════════════════\n");
            printf("\n");
        }
    }
    
    return exitCode;
}
