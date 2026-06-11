// win32app_stubs.cpp - Minimal stub implementations for RawrXD-Win32IDE link
// Contains ONLY symbols that have no real implementation in the build.

#include <string>
#include <cstdint>
#include <mutex>
#include <windows.h>

extern "C" {
    void asm_orchestrator_shutdown() {}
    bool snmalloc_library_init() { return true; }
    int asm_camellia256_init() { return 0; }
    int asm_camellia256_set_key(const uint8_t* /*key32*/) { return 0; }
    int asm_camellia256_encrypt_block(const uint8_t* /*plaintext16*/, uint8_t* /*ciphertext16*/) { return 0; }
    int asm_camellia256_decrypt_block(const uint8_t* /*ciphertext16*/, uint8_t* /*plaintext16*/) { return 0; }
    int asm_camellia256_encrypt_ctr(uint8_t* /*buffer*/, size_t /*length*/, uint8_t* /*nonce16*/) { return 0; }
    int asm_camellia256_decrypt_ctr(uint8_t* /*buffer*/, size_t /*length*/, uint8_t* /*nonce16*/) { return 0; }
    int asm_camellia256_encrypt_file(const char* /*inputPath*/, const char* /*outputPath*/) { return 0; }
    int asm_camellia256_decrypt_file(const char* /*inputPath*/, const char* /*outputPath*/) { return 0; }
    int asm_camellia256_get_status(void* /*status32*/) { return 0; }
    int asm_camellia256_shutdown() { return 0; }
    int asm_camellia256_self_test() { return 0; }
    int asm_camellia256_get_hmac_key(uint8_t* /*hmacKey32*/) { return 0; }
    void asm_selfhost_init() {}
    void asm_selfhost_read_text() {}
    void asm_selfhost_profile_region() {}
    void asm_selfhost_gen_trampoline() {}
    void asm_selfhost_micro_assemble() {}
    void asm_selfhost_atomic_swap() {}
    void asm_selfhost_verify_equiv() {}
    void asm_selfhost_measure_delta() {}
    void asm_selfhost_read_source() {}
    void asm_selfhost_write_source() {}
    void asm_selfhost_get_generation() {}
    void asm_selfhost_get_stats() {}
    void asm_selfhost_shutdown() {}
}

#include "../core/SubsystemRegistry.hpp"

namespace RawrXD {

SubsystemRegistry& SubsystemRegistry::Instance() {
    static SubsystemRegistry inst;
    return inst;
}

size_t SubsystemRegistry::Count() const {
    return 0;
}

} // namespace RawrXD