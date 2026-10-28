// AGENTIC_CAMELLIA_STUB_GATE_001 object smoke ? mirrors AgenticFeatures gate.
#include <cstdint>
#include <cstddef>
#if !defined(RAWR_HAS_MASM) || !RAWR_HAS_MASM
extern "C" {
int asm_camellia256_init() { return -1; }
int asm_camellia256_set_key(const uint8_t*) { return -1; }
int asm_camellia256_encrypt_block(const uint8_t*, uint8_t*) { return -1; }
int asm_camellia256_decrypt_block(const uint8_t*, uint8_t*) { return -1; }
int asm_camellia256_encrypt_ctr(uint8_t*, size_t, uint8_t*) { return -1; }
int asm_camellia256_decrypt_ctr(uint8_t*, size_t, uint8_t*) { return -1; }
int asm_camellia256_encrypt_file(const char*, const char*) { return -1; }
int asm_camellia256_decrypt_file(const char*, const char*) { return -1; }
int asm_camellia256_get_status(void*) { return -1; }
int asm_camellia256_shutdown() { return -1; }
int asm_camellia256_self_test() { return -1; }
int asm_camellia256_get_hmac_key(uint8_t*) { return -1; }
}
#endif
int agentic_camellia_gate_marker() { return 42; }
