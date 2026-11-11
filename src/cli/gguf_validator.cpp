// ============================================================================
// RawrXD GGUF Validator - Phase 6 Implementation
// ============================================================================

#include "gguf_validator.hpp"
#include <cstdio>
#include <cstring>
#include <windows.h>

namespace RawrXD {

// GGUF header structures (simplified)
#pragma pack(push, 1)
struct GGUFHeaderV2 {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};
#pragma pack(pop)

// Validation error strings
static const char* GetErrorString(GGUFValidationError error) {
    switch (error) {
        case GGUFValidationError::Success: return "Success";
        case GGUFValidationError::FileNotFound: return "File not found";
        case GGUFValidationError::FileNotReadable: return "File not readable";
        case GGUFValidationError::InvalidMagic: return "Invalid GGUF magic number";
        case GGUFValidationError::UnsupportedVersion: return "Unsupported GGUF version";
        case GGUFValidationError::CorruptedHeader: return "Corrupted header";
        case GGUFValidationError::MissingTensors: return "No tensors found";
        case GGUFValidationError::InvalidTensorMetadata: return "Invalid tensor metadata";
        case GGUFValidationError::ArchitectureMismatch: return "Architecture mismatch";
        case GGUFValidationError::InsufficientFileSize: return "File size insufficient";
        default: return "Unknown error";
    }
}

std::expected<bool, GGUFValidationError> GGUFValidator::QuickValidate(const std::string& filepath) {
    // Open file
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return std::unexpected(GGUFValidationError::FileNotFound);
    }
    
    // Read header (first 24 bytes for V2/V3)
    uint8_t header[32] = {0};
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, header, sizeof(header), &bytesRead, nullptr) || bytesRead < 24) {
        CloseHandle(hFile);
        return std::unexpected(GGUFValidationError::FileNotReadable);
    }
    
    CloseHandle(hFile);
    
    // Check magic
    if (!ValidateMagic(header, bytesRead)) {
        return std::unexpected(GGUFValidationError::InvalidMagic);
    }
    
    // Check version
    uint32_t version = *reinterpret_cast<const uint32_t*>(header + 4);
    if (!ValidateVersion(version)) {
        return std::unexpected(GGUFValidationError::UnsupportedVersion);
    }
    
    return true;
}

GGUFValidationResult GGUFValidator::FullValidate(const std::string& filepath) {
    GGUFValidationResult result;
    
    // Get file size
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(filepath.c_str(), GetFileExInfoStandard, &fad)) {
        result.error = GGUFValidationError::FileNotFound;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    LARGE_INTEGER fileSize;
    fileSize.LowPart = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    result.totalFileSize = fileSize.QuadPart;
    
    if (result.totalFileSize < 24) {
        result.error = GGUFValidationError::InsufficientFileSize;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    // Open and map file
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        result.error = GGUFValidationError::FileNotReadable;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        result.error = GGUFValidationError::FileNotReadable;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
    if (!data) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        result.error = GGUFValidationError::FileNotReadable;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    // Parse header
    result = ParseHeader(data, result.totalFileSize);
    
    // Cleanup
    UnmapViewOfFile(data);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return result;
}

GGUFValidationResult GGUFValidator::ValidateWithLimits(
    const std::string& filepath,
    uint64_t maxMetadataSize,
    uint64_t maxTensorCount) {
    
    GGUFValidationResult result = FullValidate(filepath);
    
    if (result.valid) {
        // Apply limits
        if (result.tensorCount > maxTensorCount) {
            result.valid = false;
            result.error = GGUFValidationError::InvalidTensorMetadata;
            result.errorMessage = "Tensor count exceeds limit";
        }
    }
    
    return result;
}

const char* GGUFValidator::ErrorToString(GGUFValidationError error) {
    return GetErrorString(error);
}

bool GGUFValidator::IsVersionSupported(uint32_t version) {
    return version >= GGUF_VERSION_MIN && version <= GGUF_VERSION_MAX;
}

bool GGUFValidator::ValidateMagic(const uint8_t* data, size_t len) {
    if (len < 4) return false;
    uint32_t magic = *reinterpret_cast<const uint32_t*>(data);
    return magic == GGUF_MAGIC;
}

bool GGUFValidator::ValidateVersion(uint32_t version) {
    return IsVersionSupported(version);
}

GGUFValidationResult GGUFValidator::ParseHeader(const uint8_t* data, size_t len) {
    GGUFValidationResult result;
    result.totalFileSize = len;
    
    // Check magic
    if (!ValidateMagic(data, len)) {
        result.error = GGUFValidationError::InvalidMagic;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    // Parse header
    const GGUFHeaderV2* header = reinterpret_cast<const GGUFHeaderV2*>(data);
    result.version = header->version;
    result.tensorCount = header->tensor_count;
    result.metadataKVCount = header->metadata_kv_count;
    
    // Validate version
    if (!ValidateVersion(result.version)) {
        result.error = GGUFValidationError::UnsupportedVersion;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    // Check for tensors
    if (result.tensorCount == 0) {
        result.error = GGUFValidationError::MissingTensors;
        result.errorMessage = GetErrorString(result.error);
        return result;
    }
    
    // Basic validation passed
    result.valid = true;
    result.error = GGUFValidationError::Success;
    result.errorMessage = "Valid GGUF file";
    
    // Calculate tensor data size (simplified)
    result.tensorDataSize = len - 256; // Approximate header size
    
    return result;
}

// ============================================================================
// Phase 6.6: Architecture Extraction and Compatibility
// ============================================================================

std::string GGUFValidator::ExtractArchitecture(const std::string& filepath) {
    // Open file and read metadata section
    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }
    
    // Map just the first 64KB to find metadata (architecture is always near start)
    HANDLE hMapping = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return "";
    }
    
    const uint8_t* data = reinterpret_cast<const uint8_t*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 65536));
    if (!data) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return "";
    }
    
    std::string arch = "llama"; // Default fallback for backward compatibility
    
    // Parse header to find metadata offset
    const uint8_t* ptr = data + 24; // Skip magic(4) + version(4) + tensor_count(8) + metadata_kv_count(8)
    
    // Scan for "general.architecture" key in first 64KB
    const char* searchKey = "general.architecture";
    const size_t searchLen = strlen(searchKey);
    
    for (size_t i = 0; i < 65536 - searchLen - 32; i++) {
        if (memcmp(data + i, searchKey, searchLen) == 0) {
            // Found the key, extract value (GGUF string: length(4) + data)
            const uint8_t* valPtr = data + i + searchLen;
            // Skip to value (type byte + length)
            valPtr += 1; // Skip type byte
            uint32_t strLen = *reinterpret_cast<const uint32_t*>(valPtr);
            valPtr += 4;
            
            if (strLen < 64 && valPtr + strLen < data + 65536) {
                arch = std::string(reinterpret_cast<const char*>(valPtr), strLen);
            }
            break;
        }
    }
    
    UnmapViewOfFile(data);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return arch;
}

bool GGUFValidator::ValidateArchitectureCompatibility(const std::string& incomingArch, const std::string& activeArch) {
    // Exact match required for safety
    // Future: Could support compatibility matrices (e.g., llama->llama2)
    return incomingArch == activeArch;
}

} // namespace RawrXD

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

int RawrXD_ValidateGGUFFile(const char* filepath) {
    if (!filepath || !filepath[0]) return 0;
    
    auto result = RawrXD::GGUFValidator::QuickValidate(filepath);
    return result.has_value() && result.value() ? 1 : 0;
}

const char* RawrXD_GetValidationError(const char* filepath) {
    if (!filepath || !filepath[0]) return "Invalid filepath";
    
    static thread_local char errorBuffer[256];
    
    auto result = RawrXD::GGUFValidator::QuickValidate(filepath);
    if (!result.has_value()) {
        strncpy(errorBuffer, RawrXD::GGUFValidator::ErrorToString(result.error()), sizeof(errorBuffer) - 1);
        errorBuffer[sizeof(errorBuffer) - 1] = '\0';
        return errorBuffer;
    }
    
    return "Valid";
}

// Phase 6.6: Extract architecture from GGUF
const char* RawrXD_ExtractGGUFArchitecture(const char* filepath) {
    if (!filepath || !filepath[0]) return "";
    
    static thread_local char archBuffer[64];
    
    std::string arch = RawrXD::GGUFValidator::ExtractArchitecture(filepath);
    strncpy(archBuffer, arch.c_str(), sizeof(archBuffer) - 1);
    archBuffer[sizeof(archBuffer) - 1] = '\0';
    
    return archBuffer;
}

} // extern "C"

#pragma comment(linker, "/EXPORT:RawrXD_ValidateGGUFFile")
#pragma comment(linker, "/EXPORT:RawrXD_GetValidationError")
#pragma comment(linker, "/EXPORT:RawrXD_ExtractGGUFArchitecture")
