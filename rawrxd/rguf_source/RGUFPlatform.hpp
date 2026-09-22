#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rguf {

// ============================================================================
// RGUFPlatform — OS helpers: CRC32, random bytes, AES-256-GCM via Windows CNG
// ============================================================================

uint32_t crc32(const uint8_t* data, size_t len);

void random_bytes(uint8_t* out, size_t len);

// AES-256-GCM encrypt. Returns false on error (err filled).
bool aes256gcm_encrypt(const uint8_t key[32],
                       const uint8_t nonce[12],
                       const uint8_t* plain, size_t plain_len,
                       const uint8_t* aad, size_t aad_len,
                       std::vector<uint8_t>& out_cipher,
                       uint8_t tag[16],
                       std::string& err);

// AES-256-GCM decrypt (with AAD). Returns false on error (err filled).
bool aes256gcm_decrypt(const uint8_t key[32],
                       const uint8_t nonce[12],
                       const uint8_t* cipher, size_t cipher_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t tag[16],
                       std::vector<uint8_t>& out_plain,
                       std::string& err);

// AES-256-GCM decrypt (no AAD). Returns false on error (err filled).
bool aes256gcm_decrypt(const uint8_t key[32],
                       const uint8_t nonce[12],
                       const uint8_t* cipher, size_t cipher_len,
                       const uint8_t tag[16],
                       std::vector<uint8_t>& out_plain,
                       std::string& err);

} // namespace rguf
