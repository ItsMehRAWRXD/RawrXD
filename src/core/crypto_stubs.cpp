// ============================================================================
// crypto_stubs.cpp - Stub implementations for crypto functions
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstddef>

extern "C" {

// Camellia-256 functions
bool asm_camellia256_auth_encrypt_file(const char* inPath, const char* outPath, const void* key) {
    (void)inPath;
    (void)outPath;
    (void)key;
    OutputDebugStringA("[Crypto] asm_camellia256_auth_encrypt_file stub called\n");
    return false;
}

bool asm_camellia256_auth_decrypt_file(const char* inPath, const char* outPath, const void* key) {
    (void)inPath;
    (void)outPath;
    (void)key;
    OutputDebugStringA("[Crypto] asm_camellia256_auth_decrypt_file stub called\n");
    return false;
}

} // extern "C"
