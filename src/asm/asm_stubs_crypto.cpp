// asm_stubs_crypto.cpp - Stub implementations for crypto ASM exports

#include <cstdint>
#include <cstddef>

extern "C" {

int asm_camellia256_auth_encrypt_file(const char* inputPath, const char* outputPath, 
                                       const void* key, const void* nonce) {
    (void)inputPath; (void)outputPath; (void)key; (void)nonce;
    return -1;  // Not implemented
}

int asm_camellia256_auth_decrypt_file(const char* inputPath, const char* outputPath,
                                       const void* key, const void* nonce) {
    (void)inputPath; (void)outputPath; (void)key; (void)nonce;
    return -1;  // Not implemented
}

} // extern "C"
