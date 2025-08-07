#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>

// AES S-box and constants
static const uint8_t aes_sbox[256] = {
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

static const uint8_t aes_rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

class AdvancedEncryption {
private:
    std::mt19937 rng;
    
    // AES helper functions
    inline uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            bool hi_bit_set = a & 0x80;
            a <<= 1;
            if (hi_bit_set) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }
    
    void subBytes(uint8_t* state) {
        for (int i = 0; i < 16; i++) {
            state[i] = aes_sbox[state[i]];
        }
    }
    
    void shiftRows(uint8_t* state) {
        uint8_t temp;
        // Row 1: shift left by 1
        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
        
        // Row 2: shift left by 2
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        
        // Row 3: shift left by 3
        temp = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = temp;
    }
    
    void mixColumns(uint8_t* state) {
        for (int i = 0; i < 4; i++) {
            uint8_t s0 = state[i*4], s1 = state[i*4+1], s2 = state[i*4+2], s3 = state[i*4+3];
            state[i*4] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3;
            state[i*4+1] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3;
            state[i*4+2] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3);
            state[i*4+3] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3);
        }
    }
    
    void addRoundKey(uint8_t* state, const uint8_t* roundKey) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }
    
    void keyExpansion(const uint8_t* key, uint8_t* roundKeys) {
        uint8_t temp[4];
        
        // Copy the original key
        for (int i = 0; i < 16; i++) {
            roundKeys[i] = key[i];
        }
        
        for (int i = 4; i < 44; i++) {
            for (int j = 0; j < 4; j++) {
                temp[j] = roundKeys[(i-1)*4 + j];
            }
            
            if (i % 4 == 0) {
                // RotWord
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                
                // SubWord
                for (int j = 0; j < 4; j++) {
                    temp[j] = aes_sbox[temp[j]];
                }
                
                // XOR with Rcon
                temp[0] ^= aes_rcon[i/4 - 1];
            }
            
            for (int j = 0; j < 4; j++) {
                roundKeys[i*4 + j] = roundKeys[(i-4)*4 + j] ^ temp[j];
            }
        }
    }
    
    void aesEncryptBlock(const uint8_t* input, uint8_t* output, const uint8_t* roundKeys) {
        uint8_t state[16];
        
        // Copy input to state
        for (int i = 0; i < 16; i++) {
            state[i] = input[i];
        }
        
        // Initial round
        addRoundKey(state, roundKeys);
        
        // Main rounds
        for (int round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys + round * 16);
        }
        
        // Final round
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys + 10 * 16);
        
        // Copy state to output
        for (int i = 0; i < 16; i++) {
            output[i] = state[i];
        }
    }
    
    void incrementCounter(uint8_t* counter) {
        for (int i = 15; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }
    
public:
    AdvancedEncryption() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}
    
    // AES-128-CTR encryption/decryption
    void aesCtrCrypt(const uint8_t* input, uint8_t* output, size_t length, 
                     const uint8_t* key, const uint8_t* nonce) {
        uint8_t roundKeys[176]; // 11 rounds * 16 bytes
        keyExpansion(key, roundKeys);
        
        uint8_t counter[16];
        uint8_t keystream[16];
        
        // Initialize counter with nonce
        for (int i = 0; i < 16; i++) {
            counter[i] = nonce[i];
        }
        
        size_t processed = 0;
        while (processed < length) {
            // Generate keystream block
            aesEncryptBlock(counter, keystream, roundKeys);
            
            // XOR with input
            size_t blockSize = (length - processed < 16) ? length - processed : 16;
            for (size_t i = 0; i < blockSize; i++) {
                output[processed + i] = input[processed + i] ^ keystream[i];
            }
            
            processed += blockSize;
            incrementCounter(counter);
        }
    }
    
    // ChaCha20 quarter round
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }
    
    // Simplified ChaCha20 encryption
    void chacha20Encrypt(const uint8_t* input, uint8_t* output, size_t length,
                        const uint8_t* key, const uint8_t* nonce) {
        // Simplified implementation - just XOR with key-derived stream
        for (size_t i = 0; i < length; i++) {
            uint8_t keyByte = key[i % 32] ^ nonce[i % 12];
            output[i] = input[i] ^ keyByte ^ (i & 0xFF);
        }
    }
    
    // Triple-layer encryption (XOR + ChaCha20 + AES)
    std::vector<uint8_t> tripleLayerEncrypt(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& xorKey,
                                           const std::vector<uint8_t>& chachaKey,
                                           const std::vector<uint8_t>& aesKey,
                                           const std::vector<uint8_t>& nonce) {
        std::vector<uint8_t> result = data;
        
        // Layer 1: XOR encryption
        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= xorKey[i % xorKey.size()];
        }
        
        // Add micro-delay for evasion
        std::this_thread::sleep_for(std::chrono::microseconds(rng() % 100));
        
        // Layer 2: ChaCha20 encryption
        std::vector<uint8_t> chachaNonce(12, 0);
        std::copy(nonce.begin(), nonce.begin() + std::min<size_t>(12, nonce.size()), 
                  chachaNonce.begin());
        chacha20Encrypt(result.data(), result.data(), result.size(),
                       chachaKey.data(), chachaNonce.data());
        
        // Add micro-delay for evasion
        std::this_thread::sleep_for(std::chrono::microseconds(rng() % 100));
        
        // Layer 3: AES-CTR encryption
        std::vector<uint8_t> aesNonce(16, 0);
        std::copy(nonce.begin(), nonce.begin() + std::min<size_t>(16, nonce.size()), 
                  aesNonce.begin());
        aesCtrCrypt(result.data(), result.data(), result.size(),
                   aesKey.data(), aesNonce.data());
        
        return result;
    }
    
    // Triple-layer decryption (reverse order: AES + ChaCha20 + XOR)
    std::vector<uint8_t> tripleLayerDecrypt(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& xorKey,
                                           const std::vector<uint8_t>& chachaKey,
                                           const std::vector<uint8_t>& aesKey,
                                           const std::vector<uint8_t>& nonce) {
        std::vector<uint8_t> result = data;
        
        // Layer 1: AES-CTR decryption (same as encryption in CTR mode)
        std::vector<uint8_t> aesNonce(16, 0);
        std::copy(nonce.begin(), nonce.begin() + std::min<size_t>(16, nonce.size()), 
                  aesNonce.begin());
        aesCtrCrypt(result.data(), result.data(), result.size(),
                   aesKey.data(), aesNonce.data());
        
        // Add micro-delay for evasion
        std::this_thread::sleep_for(std::chrono::microseconds(rng() % 100));
        
        // Layer 2: ChaCha20 decryption (same as encryption)
        std::vector<uint8_t> chachaNonce(12, 0);
        std::copy(nonce.begin(), nonce.begin() + std::min<size_t>(12, nonce.size()), 
                  chachaNonce.begin());
        chacha20Encrypt(result.data(), result.data(), result.size(),
                       chachaKey.data(), chachaNonce.data());
        
        // Add micro-delay for evasion
        std::this_thread::sleep_for(std::chrono::microseconds(rng() % 100));
        
        // Layer 3: XOR decryption
        for (size_t i = 0; i < result.size(); i++) {
            result[i] ^= xorKey[i % xorKey.size()];
        }
        
        return result;
    }
    
    // Generate random keys
    std::vector<uint8_t> generateRandomKey(size_t length) {
        std::vector<uint8_t> key(length);
        for (size_t i = 0; i < length; i++) {
            key[i] = rng() & 0xFF;
        }
        return key;
    }
};