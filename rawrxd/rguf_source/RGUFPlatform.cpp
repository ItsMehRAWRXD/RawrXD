#include "RGUFPlatform.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <cstring>
#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace rguf {

// ============================================================================
// CRC32 (ITU-T V.42 / Ethernet / PKZIP polynomial 0xEDB88320)
// ============================================================================
static uint32_t crc32_table[256];
static bool crc32_table_ready = false;
static void init_crc32_table() {
    if (crc32_table_ready) return;
    for (int i = 0; i < 256; ++i) {
        uint32_t c = (uint32_t)i;
        for (int j = 0; j < 8; ++j) {
            c = (c >> 1) ^ ((c & 1) ? 0xEDB88320u : 0);
        }
        crc32_table[i] = c;
    }
    crc32_table_ready = true;
}

uint32_t crc32(const uint8_t* data, size_t len) {
    init_crc32_table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        c = (c >> 8) ^ crc32_table[(c ^ data[i]) & 0xFF];
    }
    return ~c;
}

// ============================================================================
// Random bytes (CryptGenRandom fallback → BCryptGenRandom)
// ============================================================================
void random_bytes(uint8_t* out, size_t len) {
    if (!out || len == 0) return;
    // Prefer BCrypt
    BCryptGenRandom(nullptr, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

// ============================================================================
// AES-256-GCM via Windows CNG
// ============================================================================
static bool cng_encrypt_decrypt(bool encrypt,
                                const uint8_t key[32],
                                const uint8_t nonce[12],
                                const uint8_t* in_data, size_t in_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t tag_in[16],
                                std::vector<uint8_t>& out_data,
                                uint8_t tag_out[16],
                                std::string& err) {
    BCRYPT_ALG_HANDLE hAes = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAes, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(status)) { err = "BCryptOpenAlgorithmProvider failed"; return false; }

    // Set GCM chaining mode
    WCHAR chaining[] = BCRYPT_CHAIN_MODE_GCM;
    status = BCryptSetProperty(hAes, BCRYPT_CHAINING_MODE, (PUCHAR)chaining, sizeof(chaining), 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAes, 0); err = "BCryptSetProperty chaining failed"; return false; }

    DWORD cbKeyObj = 0, cbData = 0;
    status = BCryptGetProperty(hAes, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAes, 0); err = "BCryptGetProperty OBJECT_LENGTH failed"; return false; }

    std::vector<BYTE> keyObj(cbKeyObj);
    BCRYPT_KEY_HANDLE hKey = nullptr;
    status = BCryptGenerateSymmetricKey(hAes, &hKey, keyObj.data(), cbKeyObj,
                                        (PUCHAR)key, 32, 0);
    if (!NT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAes, 0); err = "BCryptGenerateSymmetricKey failed"; return false; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag = encrypt ? tag_out : (PUCHAR)tag_in;
    authInfo.cbTag = 16;
    if (aad && aad_len) {
        authInfo.pbAuthData = (PUCHAR)aad;
        authInfo.cbAuthData = (ULONG)aad_len;
    }

    out_data.resize(in_len);
    DWORD cbResult = 0;
    if (encrypt) {
        status = BCryptEncrypt(hKey, (PUCHAR)in_data, (ULONG)in_len, &authInfo,
                               nullptr, 0, out_data.data(), (ULONG)out_data.size(), &cbResult, 0);
    } else {
        status = BCryptDecrypt(hKey, (PUCHAR)in_data, (ULONG)in_len, &authInfo,
                               nullptr, 0, out_data.data(), (ULONG)out_data.size(), &cbResult, 0);
    }
    bool ok = NT_SUCCESS(status);
    if (!ok) err = encrypt ? "BCryptEncrypt failed" : "BCryptDecrypt failed";

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAes, 0);
    return ok;
}

bool aes256gcm_encrypt(const uint8_t key[32],
                       const uint8_t nonce[12],
                       const uint8_t* plain, size_t plain_len,
                       const uint8_t* aad, size_t aad_len,
                       std::vector<uint8_t>& out_cipher,
                       uint8_t tag[16],
                       std::string& err) {
    return cng_encrypt_decrypt(true, key, nonce, plain, plain_len, aad, aad_len, nullptr, out_cipher, tag, err);
}

bool aes256gcm_decrypt(const uint8_t key[32],
                       const uint8_t nonce[12],
                       const uint8_t* cipher, size_t cipher_len,
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t tag[16],
                       std::vector<uint8_t>& out_plain,
                       std::string& err) {
    return cng_encrypt_decrypt(false, key, nonce, cipher, cipher_len, aad, aad_len, tag, out_plain, nullptr, err);
}

bool aes256gcm_decrypt(const uint8_t key[32],
                       const uint8_t nonce[12],
                       const uint8_t* cipher, size_t cipher_len,
                       const uint8_t tag[16],
                       std::vector<uint8_t>& out_plain,
                       std::string& err) {
    return cng_encrypt_decrypt(false, key, nonce, cipher, cipher_len, nullptr, 0, tag, out_plain, nullptr, err);
}

} // namespace rguf
