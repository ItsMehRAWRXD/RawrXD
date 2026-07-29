//=============================================================================
// GGUFDiagnostics.cpp - Runtime diagnostics implementation
//=============================================================================

#include "GGUFDiagnostics.hpp"
#include <cstdio>
#include <cstdlib>
#include <windows.h>

namespace Deep2 {

void GGUFDiagnosticResult::Print() const {
    printf("[GGUFDiagnostics] Results:\n");
    printf("  File exists:     %s\n", fileExists ? "PASS" : "FAIL");
    printf("  File readable:   %s\n", fileReadable ? "PASS" : "FAIL");
    printf("  Header valid:    %s\n", headerValid ? "PASS" : "FAIL");
    printf("  Metadata valid:  %s\n", metadataValid ? "PASS" : "FAIL");
    printf("  Tensors valid:   %s\n", tensorsValid ? "PASS" : "FAIL");
    printf("  Data loadable:   %s\n", dataLoadable ? "PASS" : "FAIL");
    printf("  File size:       %llu bytes\n", (unsigned long long)fileSize);
    printf("  Expected data:   %llu bytes\n", (unsigned long long)expectedDataSize);
    
    if (errorMessage[0]) {
        printf("  Error: %s\n", errorMessage);
    }
}

GGUFDiagnosticResult GGUFDiagnostics::RunFullDiagnostic(const char* filepath) {
    GGUFDiagnosticResult result;
    
    // Check 1: File exists
    result.fileExists = CheckFileExists(filepath);
    if (!result.fileExists) {
        snprintf(result.errorMessage, sizeof(result.errorMessage), 
                 "File not found: %s", filepath);
        return result;
    }
    
    // Check 2: File readable
    result.fileReadable = CheckFileReadable(filepath);
    if (!result.fileReadable) {
        snprintf(result.errorMessage, sizeof(result.errorMessage), 
                 "File not readable (permissions)");
        return result;
    }
    
    // Get file size
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER size;
        GetFileSizeEx(hFile, &size);
        result.fileSize = size.QuadPart;
        CloseHandle(hFile);
    }
    
    // Check 3: Header valid
    char headerError[256] = {0};
    result.headerValid = CheckHeaderValid(filepath, headerError);
    if (!result.headerValid) {
        snprintf(result.errorMessage, sizeof(result.errorMessage), 
                 "Header invalid: %s", headerError);
        return result;
    }
    
    // Check 4: Metadata valid
    char metaError[256] = {0};
    result.metadataValid = CheckMetadataValid(filepath, metaError);
    if (!result.metadataValid) {
        snprintf(result.errorMessage, sizeof(result.errorMessage), 
                 "Metadata invalid: %s", metaError);
        return result;
    }
    
    // Check 5: Tensors valid
    char tensorError[256] = {0};
    result.tensorsValid = CheckTensorsValid(filepath, tensorError);
    if (!result.tensorsValid) {
        snprintf(result.errorMessage, sizeof(result.errorMessage), 
                 "Tensors invalid: %s", tensorError);
        return result;
    }
    
    // Check 6: Try full load
    GGUFLoadOptions opts;
    opts.loadTensors = true;
    opts.verbose = false;
    
    GGUFLoadResult loadResult = GGUFLoader::Load(filepath, opts);
    result.dataLoadable = loadResult.success;
    
    if (loadResult.success) {
        result.expectedDataSize = loadResult.totalSize;
        
        // Validate memory ranges
        for (const auto& t : loadResult.tensors) {
            if (t.data && !ValidateMemoryRange(t.data, t.size)) {
                result.dataLoadable = false;
                snprintf(result.errorMessage, sizeof(result.errorMessage),
                         "Memory validation failed for tensor: %s", t.name.c_str());
                break;
            }
        }
    } else {
        snprintf(result.errorMessage, sizeof(result.errorMessage),
                 "Load failed: %s", loadResult.error);
    }
    
    return result;
}

bool GGUFDiagnostics::CheckFileExists(const char* filepath) {
    DWORD attrs = GetFileAttributesA(filepath);
    return (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY));
}

bool GGUFDiagnostics::CheckFileReadable(const char* filepath) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(hFile);
    return true;
}

bool GGUFDiagnostics::CheckHeaderValid(const char* filepath, char* error) {
    FILE* fp = fopen(filepath, "rb");
    if (!fp) {
        if (error) snprintf(error, 256, "Cannot open file");
        return false;
    }
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, fp) != 1) {
        if (error) snprintf(error, 256, "Cannot read magic");
        fclose(fp);
        return false;
    }
    
    if (magic != GGUF_MAGIC) {
        if (error) snprintf(error, 256, "Invalid magic: 0x%08X (expected 0x%08X)",
                            magic, GGUF_MAGIC);
        fclose(fp);
        return false;
    }
    
    uint32_t version;
    if (fread(&version, sizeof(version), 1, fp) != 1) {
        if (error) snprintf(error, 256, "Cannot read version");
        fclose(fp);
        return false;
    }
    
    if (version != 3) {
        if (error) snprintf(error, 256, "Unsupported version: %u (expected 3)", version);
        fclose(fp);
        return false;
    }
    
    fclose(fp);
    return true;
}

bool GGUFDiagnostics::CheckMetadataValid(const char* filepath, char* error) {
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = false;
    
    GGUFLoadResult result = GGUFLoader::Load(filepath, opts);
    if (!result.success) {
        if (error) strncpy(error, result.error, 256);
        return false;
    }
    
    // Check essential metadata
    if (result.metadata.hiddenSize == 0) {
        if (error) snprintf(error, 256, "Missing hidden_size");
        return false;
    }
    if (result.metadata.numLayers == 0) {
        if (error) snprintf(error, 256, "Missing num_layers");
        return false;
    }
    
    return true;
}

bool GGUFDiagnostics::CheckTensorsValid(const char* filepath, char* error) {
    GGUFLoadOptions opts;
    opts.loadTensors = false;
    opts.verbose = false;
    
    GGUFLoadResult result = GGUFLoader::Load(filepath, opts);
    if (!result.success) {
        if (error) strncpy(error, result.error, 256);
        return false;
    }
    
    if (result.tensors.empty()) {
        if (error) snprintf(error, 256, "No tensors found");
        return false;
    }
    
    // Check for duplicate names
    for (size_t i = 0; i < result.tensors.size(); ++i) {
        for (size_t j = i + 1; j < result.tensors.size(); ++j) {
            if (result.tensors[i].name == result.tensors[j].name) {
                if (error) snprintf(error, 256, "Duplicate tensor name: %s",
                                    result.tensors[i].name.c_str());
                return false;
            }
        }
    }
    
    return true;
}

bool GGUFDiagnostics::CheckAlignment(void* ptr, size_t alignment) {
    return ((uintptr_t)ptr % alignment) == 0;
}

bool GGUFDiagnostics::ValidateMemoryRange(const void* ptr, size_t size) {
    if (!ptr || size == 0) return false;
    
    // Try to read first and last byte
    volatile const uint8_t* start = (const uint8_t*)ptr;
    volatile const uint8_t* end = (const uint8_t*)ptr + size - 1;
    
    __try {
        uint8_t first = *start;
        uint8_t last = *end;
        (void)first;
        (void)last;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool GGUFDiagnostics::FixAlignmentIssues(GGUFLoadResult& result) {
    bool fixed = false;
    
    for (auto& t : result.tensors) {
        if (t.data && !CheckAlignment(t.data, 64)) {
            // Reallocate with proper alignment
            void* newData = _aligned_malloc(t.size, 64);
            if (newData) {
                memcpy(newData, t.data, t.size);
                _aligned_free(t.data);
                t.data = newData;
                fixed = true;
            }
        }
    }
    
    return fixed;
}

} // namespace Deep2
