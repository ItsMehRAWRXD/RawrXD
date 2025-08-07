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
    CHACHA20 = 2,
    RC4 = 3,
    TRIPLE_AES_XOR_CHACHA = 4,
    RC4_CHACHA = 5
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
        size_t requiredSize = ENHANCED_DECRYPT_KEY_OFFSET + metadata.keySize + metadata.ivSize;
        if (loader.size() < requiredSize) {
            return false; // loader binary too small
        }

        auto writeLe32 = [&](size_t offset, uint32_t value) {
            loader[offset] = static_cast<uint8_t>(value & 0xFF);
            loader[offset + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
            loader[offset + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
            loader[offset + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
        };

        writeLe32(ENHANCED_PAYLOAD_SIZE_OFFSET, metadata.payloadSize);
        writeLe32(ENHANCED_PAYLOAD_RVA_OFFSET, static_cast<uint32_t>(payloadRVA));

        std::memcpy(loader.data() + ENHANCED_DECRYPT_KEY_OFFSET, metadata.key, metadata.keySize);
        std::memcpy(loader.data() + ENHANCED_DECRYPT_KEY_OFFSET + metadata.keySize, metadata.iv, metadata.ivSize);

        size_t methodOffset = ENHANCED_DECRYPT_KEY_OFFSET + metadata.keySize + metadata.ivSize;
        if (loader.size() >= methodOffset + 4) {
            writeLe32(methodOffset, metadata.method);
        }

        return true;
    }
};