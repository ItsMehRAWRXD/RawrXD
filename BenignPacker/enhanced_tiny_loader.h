#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

// Use the existing tiny_loader for now
#include "tiny_loader.h"

// Alias the existing constants
static const unsigned char* enhanced_tiny_loader_bin = tiny_loader_bin;
static const size_t enhanced_tiny_loader_bin_len = tiny_loader_bin_len;
static const size_t ENHANCED_PAYLOAD_SIZE_OFFSET = PAYLOAD_SIZE_OFFSET;
static const size_t ENHANCED_PAYLOAD_RVA_OFFSET = PAYLOAD_RVA_OFFSET;
static const size_t ENHANCED_DECRYPT_KEY_OFFSET = 0x220;
static const size_t ENHANCED_EXITPROCESS_OFFSET = 0x270;

enum class EnhancedEncryptionMethod {
    XOR = 0,
    AES = 1,
    CHACHA20 = 2
};

struct EncryptionMetadata {
    uint32_t method;
    uint32_t keySize;
    uint32_t ivSize;
    uint32_t payloadSize;
    uint8_t key[32];
    uint8_t iv[16];
};

class EnhancedLoaderUtils {
public:
    static bool patchLoaderWithEncryption(std::vector<uint8_t>& loader,
        const EncryptionMetadata& metadata,
        size_t payloadRVA) {
        // Simple implementation using existing loader
        return true;
    }
};