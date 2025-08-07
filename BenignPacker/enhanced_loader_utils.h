#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

// Use the existing tiny_loader for now
#include "tiny_loader.h"

// Updated offsets for the fixed loader
static const unsigned char* enhanced_tiny_loader_bin = tiny_loader_bin;
static const size_t enhanced_tiny_loader_bin_len = tiny_loader_bin_len;

// These offsets are now properly aligned with our fixed PE
static const size_t ENHANCED_PAYLOAD_SIZE_OFFSET = PAYLOAD_EMBED_OFFSET;  // 0x400
static const size_t ENHANCED_PAYLOAD_RVA_OFFSET = PAYLOAD_EMBED_OFFSET + 4;  // 0x404
static const size_t ENHANCED_DECRYPT_KEY_OFFSET = 0x420;  // Space for decryption key
static const size_t ENHANCED_DECRYPT_IV_OFFSET = 0x440;   // Space for IV
static const size_t ENHANCED_CODE_PATCH_OFFSET = LOADER_CODE_OFFSET;  // 0x200

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
        
        // Ensure loader is large enough
        if (loader.size() < ENHANCED_DECRYPT_IV_OFFSET + 16) {
            loader.resize(ENHANCED_DECRYPT_IV_OFFSET + 16, 0);
        }
        
        // Patch the metadata
        *reinterpret_cast<uint32_t*>(&loader[ENHANCED_PAYLOAD_SIZE_OFFSET]) = metadata.payloadSize;
        *reinterpret_cast<uint32_t*>(&loader[ENHANCED_PAYLOAD_RVA_OFFSET]) = static_cast<uint32_t>(payloadRVA);
        
        // Copy encryption key and IV
        std::memcpy(&loader[ENHANCED_DECRYPT_KEY_OFFSET], metadata.key, 32);
        std::memcpy(&loader[ENHANCED_DECRYPT_IV_OFFSET], metadata.iv, 16);
        
        // Store encryption method
        loader[ENHANCED_DECRYPT_IV_OFFSET + 16] = static_cast<uint8_t>(metadata.method);
        
        return true;
    }
    
    // Generate decryption stub code that can be injected
    static std::vector<uint8_t> generateDecryptionStub(EnhancedEncryptionMethod method) {
        std::vector<uint8_t> stub;
        
        switch (method) {
        case EnhancedEncryptionMethod::XOR:
            // Simple XOR decryption loop
            stub = {
                0x31, 0xC0,                 // xor eax, eax
                0x8B, 0x0D, 0x00, 0x04, 0x40, 0x00,  // mov ecx, [payload_size]
                0x8B, 0x35, 0x04, 0x04, 0x40, 0x00,  // mov esi, [payload_rva]
                0x8D, 0x3E,                 // lea edi, [esi]
                // XOR loop would go here
                0xC3                        // ret
            };
            break;
            
        case EnhancedEncryptionMethod::AES:
        case EnhancedEncryptionMethod::CHACHA20:
            // More complex encryption would require Windows Crypto API calls
            stub = {0xC3};  // Just return for now
            break;
        }
        
        return stub;
    }
};