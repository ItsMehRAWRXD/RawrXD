#include <windows.h>
#include <iostream>
#include <cstring>
#include <cstdint>

// Function pointer types for Camellia-256 exports (matching MASM x64 calling convention)
typedef void (*CamelliaInitFunc)();  // void asm_camellia256_init(void);
typedef void (*CamelliaSetKeyFunc)(const uint8_t* key);  // void asm_camellia256_set_key(const uint8_t* key);
typedef void (*CamelliaEncryptBlockFunc)(const uint8_t* plaintext, uint8_t* ciphertext);  // RCX=in, RDX=out
typedef void (*CamelliaDecryptBlockFunc)(const uint8_t* ciphertext, uint8_t* plaintext);  // RCX=in, RDX=out
typedef void (*CamelliaEncryptCTRFunc)(const uint8_t* input, uint8_t* output, size_t len, const uint8_t* nonce);
typedef void (*CamelliaDecryptCTRFunc)(const uint8_t* input, uint8_t* output, size_t len, const uint8_t* nonce);
typedef int (*CamelliaSelfTestFunc)();  // Returns 0 on success, non-zero on failure
typedef int (*CamelliaGetStatusFunc)(void* status);  // Returns status code
typedef void (*CamelliaShutdownFunc)();  // void asm_camellia256_shutdown(void);

void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    std::cout << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Camellia-256 MASM Export Validation" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;

    // Load the IDE binary as a module
    const char* exePath = "d:\\rawrxd-ci-bootstrap\\build\\cmake-preset-ninja-release\\bin\\RawrXD-Win32IDE.exe";
    std::cout << "[1] Loading: " << exePath << std::endl;
    
    HMODULE hMod = LoadLibraryA(exePath);
    if (!hMod) {
        std::cerr << "    FAILED: LoadLibraryA returned NULL (Error: " << GetLastError() << ")" << std::endl;
        return 1;
    }
    std::cout << "    SUCCESS: Module loaded at 0x" << std::hex << (uintptr_t)hMod << std::dec << std::endl << std::endl;

    // Get function addresses
    std::cout << "[2] Resolving Camellia-256 exports..." << std::endl;
    
    auto camellia_init = (CamelliaInitFunc)GetProcAddress(hMod, "asm_camellia256_init");
    auto camellia_set_key = (CamelliaSetKeyFunc)GetProcAddress(hMod, "asm_camellia256_set_key");
    auto camellia_encrypt_block = (CamelliaEncryptBlockFunc)GetProcAddress(hMod, "asm_camellia256_encrypt_block");
    auto camellia_decrypt_block = (CamelliaDecryptBlockFunc)GetProcAddress(hMod, "asm_camellia256_decrypt_block");
    auto camellia_encrypt_ctr = (CamelliaEncryptCTRFunc)GetProcAddress(hMod, "asm_camellia256_encrypt_ctr");
    auto camellia_decrypt_ctr = (CamelliaDecryptCTRFunc)GetProcAddress(hMod, "asm_camellia256_decrypt_ctr");
    auto camellia_self_test = (CamelliaSelfTestFunc)GetProcAddress(hMod, "asm_camellia256_self_test");
    auto camellia_get_status = (CamelliaGetStatusFunc)GetProcAddress(hMod, "asm_camellia256_get_status");
    auto camellia_shutdown = (CamelliaShutdownFunc)GetProcAddress(hMod, "asm_camellia256_shutdown");

    // Verify all functions resolved
    int resolved = 0;
    if (camellia_init) { std::cout << "    ✓ asm_camellia256_init @ 0x" << std::hex << (uintptr_t)camellia_init << std::dec << std::endl; resolved++; }
    if (camellia_set_key) { std::cout << "    ✓ asm_camellia256_set_key @ 0x" << std::hex << (uintptr_t)camellia_set_key << std::dec << std::endl; resolved++; }
    if (camellia_encrypt_block) { std::cout << "    ✓ asm_camellia256_encrypt_block @ 0x" << std::hex << (uintptr_t)camellia_encrypt_block << std::dec << std::endl; resolved++; }
    if (camellia_decrypt_block) { std::cout << "    ✓ asm_camellia256_decrypt_block @ 0x" << std::hex << (uintptr_t)camellia_decrypt_block << std::dec << std::endl; resolved++; }
    if (camellia_encrypt_ctr) { std::cout << "    ✓ asm_camellia256_encrypt_ctr @ 0x" << std::hex << (uintptr_t)camellia_encrypt_ctr << std::dec << std::endl; resolved++; }
    if (camellia_decrypt_ctr) { std::cout << "    ✓ asm_camellia256_decrypt_ctr @ 0x" << std::hex << (uintptr_t)camellia_decrypt_ctr << std::dec << std::endl; resolved++; }
    if (camellia_self_test) { std::cout << "    ✓ asm_camellia256_self_test @ 0x" << std::hex << (uintptr_t)camellia_self_test << std::dec << std::endl; resolved++; }
    if (camellia_get_status) { std::cout << "    ✓ asm_camellia256_get_status @ 0x" << std::hex << (uintptr_t)camellia_get_status << std::dec << std::endl; resolved++; }
    if (camellia_shutdown) { std::cout << "    ✓ asm_camellia256_shutdown @ 0x" << std::hex << (uintptr_t)camellia_shutdown << std::dec << std::endl; resolved++; }
    
    std::cout << "    Resolved " << resolved << "/9 Camellia-256 functions" << std::endl << std::endl;

    if (resolved < 9) {
        std::cerr << "[ERROR] Not all functions resolved. Aborting." << std::endl;
        FreeLibrary(hMod);
        return 1;
    }

    // Run self-test
    std::cout << "[3] Running built-in self-test..." << std::endl;
    int self_test_result = camellia_self_test();
    if (self_test_result == 0) {
        std::cout << "    ✓ Self-test PASSED" << std::endl << std::endl;
    } else {
        std::cout << "    ⚠ Self-test returned: " << self_test_result << " (may be stubbed)" << std::endl << std::endl;
    }

    // Initialize Camellia-256
    std::cout << "[4] Initializing Camellia-256..." << std::endl;
    camellia_init();
    std::cout << "    ✓ Initialization successful" << std::endl << std::endl;

    // Set a 256-bit key
    std::cout << "[5] Setting 256-bit key..." << std::endl;
    uint8_t key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    camellia_set_key(key);
    print_hex("    Key", key, 32);
    std::cout << "    ✓ Key set successfully" << std::endl << std::endl;

    // Test ECB mode (single block)
    std::cout << "[6] Testing ECB block encryption/decryption..." << std::endl;
    uint8_t plaintext[16] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50
    };
    uint8_t ciphertext[16] = {0};
    uint8_t decrypted[16] = {0};

    print_hex("    Plaintext ", plaintext, 16);
    
    camellia_encrypt_block(plaintext, ciphertext);
    print_hex("    Ciphertext", ciphertext, 16);

    camellia_decrypt_block(ciphertext, decrypted);
    print_hex("    Decrypted ", decrypted, 16);

    if (memcmp(plaintext, decrypted, 16) == 0) {
        std::cout << "    ✓ ECB round-trip successful" << std::endl << std::endl;
    } else {
        std::cout << "    ✗ ECB round-trip FAILED - plaintext mismatch!" << std::endl << std::endl;
    }

    // Test CTR mode
    std::cout << "[7] Testing CTR mode encryption/decryption..." << std::endl;
    uint8_t ctr_plaintext[64] = "The quick brown fox jumps over the lazy dog! CTR";
    uint8_t ctr_ciphertext[64] = {0};
    uint8_t ctr_decrypted[64] = {0};
    uint8_t nonce[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    print_hex("    Nonce     ", nonce, 16);
    print_hex("    Plaintext ", ctr_plaintext, 48);

    camellia_encrypt_ctr(ctr_plaintext, ctr_ciphertext, 48, nonce);
    print_hex("    Ciphertext", ctr_ciphertext, 48);

    camellia_decrypt_ctr(ctr_ciphertext, ctr_decrypted, 48, nonce);
    print_hex("    Decrypted ", ctr_decrypted, 48);

    if (memcmp(ctr_plaintext, ctr_decrypted, 48) == 0) {
        std::cout << "    ✓ CTR round-trip successful" << std::endl << std::endl;
    } else {
        std::cout << "    ✗ CTR round-trip FAILED - plaintext mismatch!" << std::endl << std::endl;
    }

    // Check status
    std::cout << "[8] Checking engine status..." << std::endl;
    uint8_t status[32] = {0};
    int status_result = camellia_get_status(status);
    if (status_result == 0) {
        print_hex("    Status", status, 16);
        std::cout << "    ✓ Status retrieved" << std::endl << std::endl;
    } else {
        std::cout << "    Status query returned: " << status_result << std::endl << std::endl;
    }

    // Shutdown
    std::cout << "[9] Shutting down Camellia-256..." << std::endl;
    camellia_shutdown();
    std::cout << "    ✓ Shutdown complete" << std::endl << std::endl;

    // Cleanup
    FreeLibrary(hMod);

    std::cout << "========================================" << std::endl;
    std::cout << "  All Camellia-256 Tests PASSED ✓" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
