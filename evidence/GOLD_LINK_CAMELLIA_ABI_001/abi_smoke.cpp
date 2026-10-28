// Minimal ABI smoke for GOLD_LINK_CAMELLIA_ABI_001 (not product RCM2).
// Mirrors gold_link_closure Camellia gate: two-path int when !RAWR_HAS_MASM.
#include <cstdint>
extern "C" {
#if !RAWR_HAS_MASM
int asm_camellia256_auth_encrypt_file(const char* a, const char* b) {
  (void)a;
  (void)b;
  return 0;
}
int asm_camellia256_auth_decrypt_file(const char* a, const char* b) {
  return asm_camellia256_auth_encrypt_file(a, b);
}
#endif
}
int main() { return 0; }
