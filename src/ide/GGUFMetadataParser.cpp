/*=============================================================================
 * GGUFMetadataParser.cpp
 * Implementation of audit-grade GGUF metadata extraction
 *===========================================================================*/

#include "GGUFMetadataParser.h"
#include <cstdio>
#include <cstdlib>

// SHA256 implementation for model verification
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

/*=============================================================================
 * GGUF Header Structures
 *===========================================================================*/
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensorCount;
    uint64_t metadataCount;
};
#pragma pack(pop)

/*=============================================================================
 * Helper Functions
 *===========================================================================*/
static bool ReadUint64(HANDLE hFile, uint64_t* outValue) {
    DWORD bytesRead;
    return ReadFile(hFile, outValue, sizeof(uint64_t), &bytesRead, nullptr) && 
           bytesRead == sizeof(uint64_t);
}

static bool ReadUint32(HANDLE hFile, uint32_t* outValue) {
    DWORD bytesRead;
    return ReadFile(hFile, outValue, sizeof(uint32_t), &bytesRead, nullptr) && 
           bytesRead == sizeof(uint32_t);
}

static bool ReadString(HANDLE hFile, char* outBuffer, size_t maxLen) {
    uint64_t strLen;
    if (!ReadUint64(hFile, &strLen)) return false;
    
    if (strLen >= maxLen) {
        // Skip the string if too long
        LARGE_INTEGER pos;
        pos.QuadPart = strLen;
        SetFilePointerEx(hFile, pos, nullptr, FILE_CURRENT);
        return false;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, outBuffer, (DWORD)strLen, &bytesRead, nullptr) || 
        bytesRead != strLen) {
        return false;
    }
    outBuffer[strLen] = '\0';
    return true;
}

static bool SkipString(HANDLE hFile) {
    uint64_t strLen;
    if (!ReadUint64(hFile, &strLen)) return false;
    
    LARGE_INTEGER pos;
    pos.QuadPart = strLen;
    return SetFilePointerEx(hFile, pos, nullptr, FILE_CURRENT) != 0;
}

static bool SkipValue(HANDLE hFile, GGUFType type) {
    switch (type) {
        case GGUFType::UINT8:
        case GGUFType::INT8:
        case GGUFType::BOOL: {
            uint8_t dummy;
            DWORD read;
            return ReadFile(hFile, &dummy, 1, &read, nullptr);
        }
        case GGUFType::UINT16:
        case GGUFType::INT16: {
            uint16_t dummy;
            DWORD read;
            return ReadFile(hFile, &dummy, 2, &read, nullptr) && read == 2;
        }
        case GGUFType::UINT32:
        case GGUFType::INT32:
        case GGUFType::FLOAT32: {
            uint32_t dummy;
            DWORD read;
            return ReadFile(hFile, &dummy, 4, &read, nullptr) && read == 4;
        }
        case GGUFType::UINT64:
        case GGUFType::INT64:
        case GGUFType::FLOAT64: {
            uint64_t dummy;
            return ReadUint64(hFile, &dummy);
        }
        case GGUFType::STRING:
            return SkipString(hFile);
        case GGUFType::ARRAY: {
            // Skip array type and count
            uint32_t arrType;
            if (!ReadUint32(hFile, &arrType)) return false;
            uint64_t arrCount;
            if (!ReadUint64(hFile, &arrCount)) return false;
            // Skip array elements
            for (uint64_t i = 0; i < arrCount; i++) {
                if (!SkipValue(hFile, (GGUFType)arrType)) return false;
            }
            return true;
        }
        default:
            return false;
    }
}

/*=============================================================================
 * Parse GGUF Metadata
 *===========================================================================*/
bool GGUF_ParseMetadata(const char* filePath, GGUFMetadata* outMetadata) {
    if (!filePath || !outMetadata) return false;
    
    ZeroMemory(outMetadata, sizeof(GGUFMetadata));
    strncpy_s(outMetadata->modelFile, sizeof(outMetadata->modelFile), 
              filePath, _TRUNCATE);
    
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, 
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        strncpy_s(outMetadata->errorMsg, sizeof(outMetadata->errorMsg), 
                  "Failed to open file", _TRUNCATE);
        return false;
    }
    
    // Read header
    GGUFHeader header;
    DWORD bytesRead;
    if (!ReadFile(hFile, &header, sizeof(header), &bytesRead, nullptr) ||
        bytesRead != sizeof(header)) {
        strncpy_s(outMetadata->errorMsg, sizeof(outMetadata->errorMsg), 
                  "Failed to read header", _TRUNCATE);
        CloseHandle(hFile);
        return false;
    }
    
    // Verify magic
    if (header.magic != GGUF_MAGIC) {
        strncpy_s(outMetadata->errorMsg, sizeof(outMetadata->errorMsg), 
                  "Invalid GGUF magic number", _TRUNCATE);
        CloseHandle(hFile);
        return false;
    }
    
    outMetadata->version = header.version;
    outMetadata->tensorCount = header.tensorCount;
    outMetadata->metadataCount = header.metadataCount;
    
    // Parse metadata key-value pairs
    for (uint64_t i = 0; i < header.metadataCount; i++) {
        char key[256];
        if (!ReadString(hFile, key, sizeof(key))) {
            // Try to skip and continue
            SkipString(hFile);
            uint32_t valType;
            if (!ReadUint32(hFile, &valType)) break;
            SkipValue(hFile, (GGUFType)valType);
            continue;
        }
        
        uint32_t valueType;
        if (!ReadUint32(hFile, &valueType)) break;
        
        // Extract known metadata fields
        if (_stricmp(key, "general.architecture") == 0 && 
            (GGUFType)valueType == GGUFType::STRING) {
            ReadString(hFile, outMetadata->architecture, 
                      sizeof(outMetadata->architecture));
        }
        else if (_stricmp(key, "general.name") == 0 && 
                 (GGUFType)valueType == GGUFType::STRING) {
            ReadString(hFile, outMetadata->modelName, 
                      sizeof(outMetadata->modelName));
        }
        else if ((strstr(key, "block_count") || strstr(key, "num_hidden_layers")) &&
                 (GGUFType)valueType == GGUFType::UINT32) {
            ReadUint32(hFile, &outMetadata->blockCount);
        }
        else if ((strstr(key, "context_length") || strstr(key, "max_position_embeddings")) &&
                 (GGUFType)valueType == GGUFType::UINT32) {
            ReadUint32(hFile, &outMetadata->contextLength);
        }
        else if ((strstr(key, "embedding_length") || strstr(key, "hidden_size")) &&
                 (GGUFType)valueType == GGUFType::UINT32) {
            ReadUint32(hFile, &outMetadata->embeddingLength);
        }
        else if ((strstr(key, "feed_forward_length") || strstr(key, "intermediate_size")) &&
                 (GGUFType)valueType == GGUFType::UINT32) {
            ReadUint32(hFile, &outMetadata->feedForwardLength);
        }
        else if ((strstr(key, "attention.head_count") || strstr(key, "num_attention_heads")) &&
                 (GGUFType)valueType == GGUFType::UINT32) {
            ReadUint32(hFile, &outMetadata->headCount);
        }
        else if ((strstr(key, "attention.head_count_kv") || strstr(key, "num_key_value_heads")) &&
                 (GGUFType)valueType == GGUFType::UINT32) {
            ReadUint32(hFile, &outMetadata->headCountKV);
        }
        else {
            // Skip unknown value
            SkipValue(hFile, (GGUFType)valueType);
        }
    }
    
    // Infer quantization from tensor types (simplified)
    // In a full implementation, we'd scan tensor info
    const char* filename = strrchr(filePath, '\\');
    if (!filename) filename = strrchr(filePath, '/');
    if (!filename) filename = filePath;
    else filename++;
    
    if (strstr(filename, "Q4_K_M")) {
        strcpy_s(outMetadata->quantization, sizeof(outMetadata->quantization), "Q4_K_M");
        outMetadata->quantizationVersion = 1;
    } else if (strstr(filename, "Q4_0")) {
        strcpy_s(outMetadata->quantization, sizeof(outMetadata->quantization), "Q4_0");
        outMetadata->quantizationVersion = 1;
    } else if (strstr(filename, "Q8_0")) {
        strcpy_s(outMetadata->quantization, sizeof(outMetadata->quantization), "Q8_0");
        outMetadata->quantizationVersion = 1;
    } else if (strstr(filename, "Q5_K_M")) {
        strcpy_s(outMetadata->quantization, sizeof(outMetadata->quantization), "Q5_K_M");
        outMetadata->quantizationVersion = 1;
    } else if (strstr(filename, "Q6_K")) {
        strcpy_s(outMetadata->quantization, sizeof(outMetadata->quantization), "Q6_K");
        outMetadata->quantizationVersion = 1;
    } else {
        strcpy_s(outMetadata->quantization, sizeof(outMetadata->quantization), "UNKNOWN");
    }
    
    outMetadata->valid = true;
    CloseHandle(hFile);
    return true;
}

bool GGUF_ParseMetadataW(const wchar_t* filePath, GGUFMetadata* outMetadata) {
    if (!filePath) return false;
    char narrowPath[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, filePath, -1, narrowPath, MAX_PATH, nullptr, nullptr);
    return GGUF_ParseMetadata(narrowPath, outMetadata);
}

/*=============================================================================
 * Format Metadata for Display
 *===========================================================================*/
void GGUF_FormatMetadata(const GGUFMetadata* metadata, char* outBuffer, size_t bufferSize) {
    if (!metadata || !outBuffer || bufferSize == 0) return;
    
    snprintf(outBuffer, bufferSize,
        "[ModelMetadata]\n"
        "  Architecture: %s\n"
        "  Layers: %u\n"
        "  Embedding: %u\n"
        "  Context: %u\n"
        "  Quantization: %s\n"
        "  TensorCount: %llu\n"
        "  GGUF Version: %u\n",
        metadata->architecture[0] ? metadata->architecture : "unknown",
        metadata->blockCount,
        metadata->embeddingLength,
        metadata->contextLength,
        metadata->quantization,
        (unsigned long long)metadata->tensorCount,
        metadata->version
    );
}

/*=============================================================================
 * SHA256 Hashing for Model Verification
 *===========================================================================*/
bool ComputeFileSHA256(const char* filePath, char* outHash, size_t hashBufferSize) {
    if (!filePath || !outHash || hashBufferSize < 65) return false;
    
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return false;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }
    
    // Read file in chunks
    BYTE buffer[8192];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }
    
    // Get hash
    BYTE hash[32];
    DWORD hashLen = sizeof(hash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        // Convert to hex string
        for (int i = 0; i < 32; i++) {
            sprintf_s(outHash + (i * 2), hashBufferSize - (i * 2), "%02x", hash[i]);
        }
        outHash[64] = '\0';
        result = TRUE;
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    
    return result != FALSE;
}

bool ComputeFileSHA256W(const wchar_t* filePath, char* outHash, size_t hashBufferSize) {
    if (!filePath) return false;
    char narrowPath[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, filePath, -1, narrowPath, MAX_PATH, nullptr, nullptr);
    return ComputeFileSHA256(narrowPath, outHash, hashBufferSize);
}
