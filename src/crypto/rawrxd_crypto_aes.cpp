/**
 * AES-256-GCM Implementation
 * Authenticated Encryption with Associated Data (AEAD)
 */

#include "rawrxd_crypto.h"
#include <cstring>
#include <stdexcept>

namespace RawrXD {
namespace Crypto {

// ============================================================
// AES-256 CORE (Rijndael)
// ============================================================

// S-box
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Round constants
static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Galois field multiplication
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// Key expansion for AES-256 (14 rounds)
static void aesKeyExpansion(const uint8_t* key, uint32_t* roundKeys) {
    const int Nk = 8; // 256-bit key / 32
    const int Nr = 14; // 14 rounds
    const int Nb = 4; // 128-bit block / 32
    
    // Copy key
    for (int i = 0; i < Nk; i++) {
        roundKeys[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
                       ((uint32_t)key[4*i+2] << 8) | ((uint32_t)key[4*i+3]);
    }
    
    // Generate round keys
    for (int i = Nk; i < Nb * (Nr + 1); i++) {
        uint32_t temp = roundKeys[i - 1];
        
        if (i % Nk == 0) {
            // RotWord
            temp = (temp << 8) | (temp >> 24);
            // SubWord
            temp = (AES_SBOX[(temp >> 24) & 0xFF] << 24) |
                   (AES_SBOX[(temp >> 16) & 0xFF] << 16) |
                   (AES_SBOX[(temp >> 8) & 0xFF] << 8) |
                   (AES_SBOX[temp & 0xFF]);
            // XOR with Rcon
            temp ^= ((uint32_t)RCON[i / Nk] << 24);
        } else if (i % Nk == 4) {
            // SubWord for AES-256
            temp = (AES_SBOX[(temp >> 24) & 0xFF] << 24) |
                   (AES_SBOX[(temp >> 16) & 0xFF] << 16) |
                   (AES_SBOX[(temp >> 8) & 0xFF] << 8) |
                   (AES_SBOX[temp & 0xFF]);
        }
        
        roundKeys[i] = roundKeys[i - Nk] ^ temp;
    }
}

// SubBytes transformation
static void subBytes(uint8_t* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = AES_SBOX[state[i]];
    }
}

// ShiftRows transformation
static void shiftRows(uint8_t* state) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// MixColumns transformation
static void mixColumns(uint8_t* state) {
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = state[i*4];
        uint8_t s1 = state[i*4 + 1];
        uint8_t s2 = state[i*4 + 2];
        uint8_t s3 = state[i*4 + 3];
        
        state[i*4]     = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3;
        state[i*4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3;
        state[i*4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3);
        state[i*4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2);
    }
}

// AddRoundKey transformation
static void addRoundKey(uint8_t* state, const uint32_t* roundKey, int round) {
    for (int i = 0; i < 4; i++) {
        uint32_t k = roundKey[round * 4 + i];
        state[i*4]     ^= (k >> 24) & 0xFF;
        state[i*4 + 1] ^= (k >> 16) & 0xFF;
        state[i*4 + 2] ^= (k >> 8) & 0xFF;
        state[i*4 + 3] ^= k & 0xFF;
    }
}

void AES256GCM::aesEncryptBlock(const uint8_t* key, const uint8_t* in, uint8_t* out) {
    uint32_t roundKeys[60]; // 14 rounds + 1 = 15 * 4 = 60
    aesKeyExpansion(key, roundKeys);
    
    // Copy input to state
    uint8_t state[16];
    memcpy(state, in, 16);
    
    // Initial round
    addRoundKey(state, roundKeys, 0);
    
    // Main rounds (1-13 for AES-256)
    for (int round = 1; round < 14; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys, round);
    }
    
    // Final round (no MixColumns)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, roundKeys, 14);
    
    // Copy state to output
    memcpy(out, state, 16);
    
    // Zero sensitive data
    SecureMemory::secureZero(roundKeys, sizeof(roundKeys));
    SecureMemory::secureZero(state, sizeof(state));
}

// ============================================================
// GCM MODE OPERATIONS
// ============================================================

// GCM multiplication in GF(2^128)
static void gcmMul(const uint8_t* x, const uint8_t* y, uint8_t* result) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);
    
    for (int i = 0; i < 128; i++) {
        // If bit i of x is 1, z ^= v
        int bytePos = i / 8;
        int bitPos = 7 - (i % 8);
        if ((x[bytePos] >> bitPos) & 1) {
            for (int j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }
        
        // v = v >> 1 (in GF(2^128))
        bool lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
        }
        v[0] >>= 1;
        
        // If LSB was 1, XOR with R = 0xE1 << 120
        if (lsb) {
            v[0] ^= 0xE1;
        }
    }
    
    memcpy(result, z, 16);
}

void AES256GCM::gcmGhash(const uint8_t* h, const uint8_t* data, size_t len, uint8_t* result) {
    memset(result, 0, 16);
    
    for (size_t i = 0; i < len; i += 16) {
        // XOR with next block
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            result[j] ^= data[i + j];
        }
        
        // Multiply by H
        uint8_t temp[16];
        gcmMul(result, h, temp);
        memcpy(result, temp, 16);
    }
}

bool AES256GCM::encrypt(const uint8_t* key, const uint8_t* iv,
                         const uint8_t* plaintext, size_t ptlen,
                         const uint8_t* aad, size_t aadlen,
                         std::vector<uint8_t>& output) {
    // GCM encryption
    // 1. Compute H = AES(K, 0^128)
    uint8_t h[16] = {0};
    aesEncryptBlock(key, h, h);
    
    // 2. Initialize counter: IV || 0^31 || 1
    uint8_t counter[16];
    if (iv != nullptr) {
        memcpy(counter, iv, IV_SIZE);
        memset(counter + IV_SIZE, 0, 3);
        counter[15] = 1;
    } else {
        memset(counter, 0, 16);
        counter[15] = 1;
    }
    
    // 3. Encrypt plaintext using CTR mode
    output.resize(ptlen + TAG_SIZE);
    for (size_t i = 0; i < ptlen; i += 16) {
        uint8_t encrypted_counter[16];
        aesEncryptBlock(key, counter, encrypted_counter);
        
        // XOR with plaintext
        for (size_t j = 0; j < 16 && i + j < ptlen; j++) {
            output[i + j] = plaintext[i + j] ^ encrypted_counter[j];
        }
        
        // Increment counter
        for (int j = 15; j >= 0; j--) {
            if (++counter[j] != 0) break;
        }
    }
    
    // 4. Compute authentication tag using GHASH
    std::vector<uint8_t> ghash_input;
    ghash_input.insert(ghash_input.end(), aad, aad + aadlen);
    
    // Pad AAD to 128-bit boundary
    size_t aad_pad = (16 - (aadlen % 16)) % 16;
    ghash_input.insert(ghash_input.end(), aad_pad, 0);
    
    // Append ciphertext
    ghash_input.insert(ghash_input.end(), output.begin(), output.begin() + ptlen);
    
    // Pad ciphertext to 128-bit boundary
    size_t ct_pad = (16 - (ptlen % 16)) % 16;
    ghash_input.insert(ghash_input.end(), ct_pad, 0);
    
    // Append lengths (64-bit big-endian)
    uint64_t aad_bits = aadlen * 8;
    uint64_t ct_bits = ptlen * 8;
    for (int i = 7; i >= 0; i--) {
        ghash_input.push_back((aad_bits >> (i * 8)) & 0xFF);
    }
    for (int i = 7; i >= 0; i--) {
        ghash_input.push_back((ct_bits >> (i * 8)) & 0xFF);
    }
    
    uint8_t tag_ghash[16];
    gcmGhash(h, ghash_input.data(), ghash_input.size(), tag_ghash);
    
    // 5. Encrypt GHASH output with J0 to get tag
    uint8_t j0[16];
    if (iv != nullptr) {
        memcpy(j0, iv, IV_SIZE);
        memset(j0 + IV_SIZE, 0, 4);
    } else {
        memset(j0, 0, 16);
    }
    uint8_t encrypted_j0[16];
    aesEncryptBlock(key, j0, encrypted_j0);
    
    for (int i = 0; i < 16; i++) {
        tag_ghash[i] ^= encrypted_j0[i];
    }
    
    // Append tag to output
    memcpy(output.data() + ptlen, tag_ghash, TAG_SIZE);
    
    return true;
}

bool AES256GCM::decrypt(const uint8_t* key, const uint8_t* iv,
                         const uint8_t* ciphertext, size_t ctlen,
                         const uint8_t* tag,
                         const uint8_t* aad, size_t aadlen,
                         std::vector<uint8_t>& output) {
    // Verify minimum size
    if (ctlen < TAG_SIZE) return false;
    
    // Similar to encrypt but reverse operations and verify tag
    uint8_t h[16] = {0};
    aesEncryptBlock(key, h, h);
    
    // Compute expected tag
    std::vector<uint8_t> ghash_input;
    ghash_input.insert(ghash_input.end(), aad, aad + aadlen);
    
    size_t aad_pad = (16 - (aadlen % 16)) % 16;
    ghash_input.insert(ghash_input.end(), aad_pad, 0);
    
    ghash_input.insert(ghash_input.end(), ciphertext, ciphertext + ctlen);
    
    size_t ct_pad = (16 - (ctlen % 16)) % 16;
    ghash_input.insert(ghash_input.end(), ct_pad, 0);
    
    uint64_t aad_bits = aadlen * 8;
    uint64_t ct_bits = ctlen * 8;
    for (int i = 7; i >= 0; i--) {
        ghash_input.push_back((aad_bits >> (i * 8)) & 0xFF);
    }
    for (int i = 7; i >= 0; i--) {
        ghash_input.push_back((ct_bits >> (i * 8)) & 0xFF);
    }
    
    uint8_t expected_tag[16];
    gcmGhash(h, ghash_input.data(), ghash_input.size(), expected_tag);
    
    uint8_t j0[16];
    if (iv != nullptr) {
        memcpy(j0, iv, IV_SIZE);
        memset(j0 + IV_SIZE, 0, 4);
    } else {
        memset(j0, 0, 16);
    }
    uint8_t encrypted_j0[16];
    aesEncryptBlock(key, j0, encrypted_j0);
    
    for (int i = 0; i < 16; i++) {
        expected_tag[i] ^= encrypted_j0[i];
    }
    
    // Constant-time tag comparison
    if (SecureMemory::constantTimeCompare(expected_tag, tag, TAG_SIZE) != 0) {
        return false; // Authentication failed
    }
    
    // Decrypt ciphertext
    uint8_t counter[16];
    if (iv != nullptr) {
        memcpy(counter, iv, IV_SIZE);
        memset(counter + IV_SIZE, 0, 3);
        counter[15] = 1;
    } else {
        memset(counter, 0, 16);
        counter[15] = 1;
    }
    
    output.resize(ctlen);
    for (size_t i = 0; i < ctlen; i += 16) {
        uint8_t encrypted_counter[16];
        aesEncryptBlock(key, counter, encrypted_counter);
        
        for (size_t j = 0; j < 16 && i + j < ctlen; j++) {
            output[i + j] = ciphertext[i + j] ^ encrypted_counter[j];
        }
        
        for (int j = 15; j >= 0; j--) {
            if (++counter[j] != 0) break;
        }
    }
    
    return true;
}

} // namespace Crypto
} // namespace RawrXD
