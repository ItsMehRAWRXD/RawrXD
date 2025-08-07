#pragma once

#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <memory>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif

class EnhancedEncryptionSystem {
private:
    std::mt19937_64 rng;
    std::mt19937 alt_rng;
    
    // Enhanced RNG initialization with multiple entropy sources
    void initializeRNG() {
        std::random_device rd;
        auto now = std::chrono::high_resolution_clock::now();
        auto duration = now.time_since_epoch();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
        
        std::seed_seq seed{
            rd(), rd(), rd(), rd(),
            static_cast<unsigned int>(std::time(nullptr)),
            static_cast<unsigned int>(std::clock()),
            static_cast<unsigned int>(millis),
            static_cast<unsigned int>(millis >> 32)
        };
        
        rng.seed(seed);
        alt_rng.seed(static_cast<uint32_t>(millis));
    }
    
    // AES-128 S-box and RCON tables
    static const uint8_t sbox[256];
    static const uint8_t rcon[11];
    
    // AES helper functions
    uint8_t gmul(uint8_t a, uint8_t b) {
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
    
    void subBytes(uint8_t state[16]) {
        for (int i = 0; i < 16; i++) {
            state[i] = sbox[state[i]];
        }
    }
    
    void shiftRows(uint8_t state[16]) {
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
    
    void mixColumns(uint8_t state[16]) {
        uint8_t temp[16];
        for (int i = 0; i < 4; i++) {
            temp[i*4] = gmul(2, state[i*4]) ^ gmul(3, state[i*4+1]) ^ state[i*4+2] ^ state[i*4+3];
            temp[i*4+1] = state[i*4] ^ gmul(2, state[i*4+1]) ^ gmul(3, state[i*4+2]) ^ state[i*4+3];
            temp[i*4+2] = state[i*4] ^ state[i*4+1] ^ gmul(2, state[i*4+2]) ^ gmul(3, state[i*4+3]);
            temp[i*4+3] = gmul(3, state[i*4]) ^ state[i*4+1] ^ state[i*4+2] ^ gmul(2, state[i*4+3]);
        }
        memcpy(state, temp, 16);
    }
    
    void keyExpansion(const uint8_t key[16], uint8_t roundKeys[176]) {
        memcpy(roundKeys, key, 16);
        
        for (int i = 4; i < 44; i++) {
            uint8_t temp[4];
            memcpy(temp, roundKeys + (i-1) * 4, 4);
            
            if (i % 4 == 0) {
                // RotWord
                uint8_t t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                
                // SubWord
                for (int j = 0; j < 4; j++) {
                    temp[j] = sbox[temp[j]];
                }
                
                // XOR with RCON
                temp[0] ^= rcon[i/4];
            }
            
            for (int j = 0; j < 4; j++) {
                roundKeys[i*4 + j] = roundKeys[(i-4)*4 + j] ^ temp[j];
            }
        }
    }
    
    void aesEncryptBlock(const uint8_t input[16], uint8_t output[16], const uint8_t roundKeys[176]) {
        uint8_t state[16];
        memcpy(state, input, 16);
        
        // AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKeys[i];
        }
        
        // 9 rounds
        for (int round = 1; round < 10; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            
            // AddRoundKey
            for (int i = 0; i < 16; i++) {
                state[i] ^= roundKeys[round*16 + i];
            }
        }
        
        // Final round
        subBytes(state);
        shiftRows(state);
        
        // AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKeys[160 + i];
        }
        
        memcpy(output, state, 16);
    }
    
    void incrementCounter(uint8_t counter[16]) {
        for (int i = 15; i >= 0; i--) {
            counter[i]++;
            if (counter[i] != 0) break;
        }
    }
    
    void aesCtrCrypt(const uint8_t* input, uint8_t* output, size_t length, 
                     const uint8_t key[16], const uint8_t nonce[12]) {
        uint8_t roundKeys[176];
        keyExpansion(key, roundKeys);
        
        uint8_t counter[16];
        memcpy(counter, nonce, 12);
        memset(counter + 12, 0, 4);
        
        uint8_t keystream[16];
        
        for (size_t i = 0; i < length; i += 16) {
            aesEncryptBlock(counter, keystream, roundKeys);
            
            size_t blockSize = (length - i < 16) ? length - i : 16;
            for (size_t j = 0; j < blockSize; j++) {
                output[i + j] = input[i + j] ^ keystream[j];
            }
            
            incrementCounter(counter);
        }
    }
    
    // ChaCha20 implementation
    void quarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = (d << 16) | (d >> 16);
        c += d; b ^= c; b = (b << 12) | (b >> 20);
        a += b; d ^= a; d = (d << 8) | (d >> 24);
        c += d; b ^= c; b = (b << 7) | (b >> 25);
    }
    
    void chachaBlock(uint32_t output[16], const uint32_t input[16]) {
        uint32_t x[16];
        for (int i = 0; i < 16; i++) {
            x[i] = input[i];
        }
        
        // 20 rounds (10 double-rounds)
        for (int i = 0; i < 10; i++) {
            // Column rounds
            quarterRound(x[0], x[4], x[8], x[12]);
            quarterRound(x[1], x[5], x[9], x[13]);
            quarterRound(x[2], x[6], x[10], x[14]);
            quarterRound(x[3], x[7], x[11], x[15]);
            
            // Diagonal rounds
            quarterRound(x[0], x[5], x[10], x[15]);
            quarterRound(x[1], x[6], x[11], x[12]);
            quarterRound(x[2], x[7], x[8], x[13]);
            quarterRound(x[3], x[4], x[9], x[14]);
        }
        
        // Add original input
        for (int i = 0; i < 16; i++) {
            output[i] = x[i] + input[i];
        }
    }
    
    void initChachaState(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Key
        for (int i = 0; i < 8; i++) {
            state[4 + i] = ((uint32_t)key[4*i]) |
                           ((uint32_t)key[4*i + 1] << 8) |
                           ((uint32_t)key[4*i + 2] << 16) |
                           ((uint32_t)key[4*i + 3] << 24);
        }
        
        // Counter
        state[12] = counter;
        
        // Nonce
        for (int i = 0; i < 3; i++) {
            state[13 + i] = ((uint32_t)nonce[4*i]) |
                            ((uint32_t)nonce[4*i + 1] << 8) |
                            ((uint32_t)nonce[4*i + 2] << 16) |
                            ((uint32_t)nonce[4*i + 3] << 24);
        }
    }
    
    void chacha20Crypt(const uint8_t* input, uint8_t* output, size_t length,
                       const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
        uint32_t state[16];
        uint32_t keystream[16];
        uint8_t* keystream_bytes = (uint8_t*)keystream;
        
        size_t processed = 0;
        while (processed < length) {
            // Initialize state for this block
            initChachaState(state, key, nonce, counter);
            
            // Generate keystream block
            chachaBlock(keystream, state);
            
            // XOR with input
            size_t blockSize = (length - processed < 64) ? length - processed : 64;
            for (size_t i = 0; i < blockSize; i++) {
                output[processed + i] = input[processed + i] ^ keystream_bytes[i];
            }
            
            processed += blockSize;
            counter++;
        }
    }
    
    void xorCrypt(const uint8_t* input, uint8_t* output, size_t length, const uint8_t* key, size_t keyLen) {
        for (size_t i = 0; i < length; i++) {
            output[i] = input[i] ^ key[i % keyLen];
        }
    }
    
    void generateRandomBytes(uint8_t* buffer, size_t length) {
        std::uniform_int_distribution<uint8_t> dist(0, 255);
        for (size_t i = 0; i < length; i++) {
            buffer[i] = dist(rng);
        }
    }
    
    std::string bytesToHex(const uint8_t* data, size_t len) {
        std::stringstream ss;
        for (size_t i = 0; i < len; i++) {
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
            if (i < len - 1) ss << ", ";
        }
        return ss.str();
    }
    
public:
    enum EncryptionMethod {
        AES_128_CTR = 0x01,
        CHACHA20 = 0x02,
        XOR_KEY = 0x03,
        TRIPLE_ENCRYPTION = 0x04
    };
    
    struct EncryptionHeader {
        uint8_t method;
        uint8_t nonceSize;
        uint8_t keySize;
        uint8_t reserved;
    };
    
    EnhancedEncryptionSystem() {
        initializeRNG();
    }
    
    // Generate encryption key and nonce
    std::vector<uint8_t> generateKey(EncryptionMethod method) {
        size_t keySize = (method == CHACHA20) ? 32 : 16;
        std::vector<uint8_t> key(keySize);
        generateRandomBytes(key.data(), keySize);
        return key;
    }
    
    std::vector<uint8_t> generateNonce(EncryptionMethod method) {
        size_t nonceSize = (method == CHACHA20) ? 12 : 16;
        std::vector<uint8_t> nonce(nonceSize);
        generateRandomBytes(nonce.data(), nonceSize);
        return nonce;
    }
    
    // Encrypt data with specified method
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, EncryptionMethod method) {
        std::vector<uint8_t> encrypted;
        
        switch (method) {
            case AES_128_CTR: {
                auto key = generateKey(method);
                auto nonce = generateNonce(method);
                
                encrypted.resize(sizeof(EncryptionHeader) + nonce.size() + data.size());
                EncryptionHeader* header = (EncryptionHeader*)encrypted.data();
                header->method = method;
                header->nonceSize = nonce.size();
                header->keySize = key.size();
                header->reserved = 0;
                
                memcpy(encrypted.data() + sizeof(EncryptionHeader), nonce.data(), nonce.size());
                
                aesCtrCrypt(data.data(), 
                           encrypted.data() + sizeof(EncryptionHeader) + nonce.size(),
                           data.size(), key.data(), nonce.data());
                break;
            }
            
            case CHACHA20: {
                auto key = generateKey(method);
                auto nonce = generateNonce(method);
                
                encrypted.resize(sizeof(EncryptionHeader) + nonce.size() + data.size());
                EncryptionHeader* header = (EncryptionHeader*)encrypted.data();
                header->method = method;
                header->nonceSize = nonce.size();
                header->keySize = key.size();
                header->reserved = 0;
                
                memcpy(encrypted.data() + sizeof(EncryptionHeader), nonce.data(), nonce.size());
                
                chacha20Crypt(data.data(),
                             encrypted.data() + sizeof(EncryptionHeader) + nonce.size(),
                             data.size(), key.data(), nonce.data(), 0);
                break;
            }
            
            case XOR_KEY: {
                auto key = generateKey(method);
                
                encrypted.resize(sizeof(EncryptionHeader) + data.size());
                EncryptionHeader* header = (EncryptionHeader*)encrypted.data();
                header->method = method;
                header->nonceSize = 0;
                header->keySize = key.size();
                header->reserved = 0;
                
                xorCrypt(data.data(),
                        encrypted.data() + sizeof(EncryptionHeader),
                        data.size(), key.data(), key.size());
                break;
            }
            
            case TRIPLE_ENCRYPTION: {
                // Triple encryption: XOR -> AES -> ChaCha20
                auto xorKey = generateKey(XOR_KEY);
                auto aesKey = generateKey(AES_128_CTR);
                auto aesNonce = generateNonce(AES_128_CTR);
                auto chachaKey = generateKey(CHACHA20);
                auto chachaNonce = generateNonce(CHACHA20);
                
                // Step 1: XOR encryption
                std::vector<uint8_t> step1(data.size());
                xorCrypt(data.data(), step1.data(), data.size(), xorKey.data(), xorKey.size());
                
                // Step 2: AES encryption
                std::vector<uint8_t> step2(step1.size());
                aesCtrCrypt(step1.data(), step2.data(), step1.size(), aesKey.data(), aesNonce.data());
                
                // Step 3: ChaCha20 encryption
                encrypted.resize(sizeof(EncryptionHeader) + chachaNonce.size() + step2.size());
                EncryptionHeader* header = (EncryptionHeader*)encrypted.data();
                header->method = method;
                header->nonceSize = chachaNonce.size();
                header->keySize = chachaKey.size();
                header->reserved = 0;
                
                memcpy(encrypted.data() + sizeof(EncryptionHeader), chachaNonce.data(), chachaNonce.size());
                
                chacha20Crypt(step2.data(),
                             encrypted.data() + sizeof(EncryptionHeader) + chachaNonce.size(),
                             step2.size(), chachaKey.data(), chachaNonce.data(), 0);
                break;
            }
        }
        
        return encrypted;
    }
    
    // Generate decryption stub code
    std::string generateDecryptionStub(EncryptionMethod method, const std::vector<uint8_t>& encryptedData) {
        std::stringstream code;
        
        code << "// Enhanced Decryption Stub\n";
        code << "#include <vector>\n";
        code << "#include <cstdint>\n";
        code << "#include <cstring>\n\n";
        
        // Embed encrypted data
        code << "static const uint8_t encrypted_data[] = {";
        for (size_t i = 0; i < encryptedData.size(); ++i) {
            if (i % 16 == 0) code << "\n    ";
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encryptedData[i];
            if (i < encryptedData.size() - 1) code << ", ";
        }
        code << "\n};\n\n";
        
        code << "static const size_t encrypted_size = " << std::dec << encryptedData.size() << ";\n\n";
        
        // Generate decryption function based on method
        switch (method) {
            case AES_128_CTR:
                code << generateAESDecryptionCode();
                break;
            case CHACHA20:
                code << generateChaCha20DecryptionCode();
                break;
            case XOR_KEY:
                code << generateXORDecryptionCode();
                break;
            case TRIPLE_ENCRYPTION:
                code << generateTripleDecryptionCode();
                break;
        }
        
        return code.str();
    }
    
private:
    std::string generateAESDecryptionCode() {
        return R"(
// AES-128 CTR Decryption
void aesDecrypt(const uint8_t* input, uint8_t* output, size_t length) {
    // Simplified AES implementation for stub
    // In real implementation, you would include full AES code
    for (size_t i = 0; i < length; i++) {
        output[i] = input[i] ^ 0xAA; // Placeholder XOR
    }
}

std::vector<uint8_t> decryptPayload() {
    std::vector<uint8_t> decrypted(encrypted_size - sizeof(EncryptionHeader) - 16);
    aesDecrypt(encrypted_data + sizeof(EncryptionHeader) + 16, 
               decrypted.data(), decrypted.size());
    return decrypted;
}
)";
    }
    
    std::string generateChaCha20DecryptionCode() {
        return R"(
// ChaCha20 Decryption
void chacha20Decrypt(const uint8_t* input, uint8_t* output, size_t length) {
    // Simplified ChaCha20 implementation for stub
    // In real implementation, you would include full ChaCha20 code
    for (size_t i = 0; i < length; i++) {
        output[i] = input[i] ^ 0xBB; // Placeholder XOR
    }
}

std::vector<uint8_t> decryptPayload() {
    std::vector<uint8_t> decrypted(encrypted_size - sizeof(EncryptionHeader) - 12);
    chacha20Decrypt(encrypted_data + sizeof(EncryptionHeader) + 12, 
                    decrypted.data(), decrypted.size());
    return decrypted;
}
)";
    }
    
    std::string generateXORDecryptionCode() {
        return R"(
// XOR Decryption
void xorDecrypt(const uint8_t* input, uint8_t* output, size_t length) {
    const uint8_t key[] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    for (size_t i = 0; i < length; i++) {
        output[i] = input[i] ^ key[i % sizeof(key)];
    }
}

std::vector<uint8_t> decryptPayload() {
    std::vector<uint8_t> decrypted(encrypted_size - sizeof(EncryptionHeader));
    xorDecrypt(encrypted_data + sizeof(EncryptionHeader), 
               decrypted.data(), decrypted.size());
    return decrypted;
}
)";
    }
    
    std::string generateTripleDecryptionCode() {
        return R"(
// Triple Decryption (ChaCha20 -> AES -> XOR)
std::vector<uint8_t> decryptPayload() {
    // Step 1: ChaCha20 decryption
    std::vector<uint8_t> step1(encrypted_size - sizeof(EncryptionHeader) - 12);
    chacha20Decrypt(encrypted_data + sizeof(EncryptionHeader) + 12, 
                    step1.data(), step1.size());
    
    // Step 2: AES decryption
    std::vector<uint8_t> step2(step1.size());
    aesDecrypt(step1.data(), step2.data(), step1.size());
    
    // Step 3: XOR decryption
    std::vector<uint8_t> decrypted(step2.size());
    xorDecrypt(step2.data(), decrypted.data(), step2.size());
    
    return decrypted;
}
)";
    }
};

// AES S-box and RCON tables
const uint8_t EnhancedEncryptionSystem::sbox[256] = {
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

const uint8_t EnhancedEncryptionSystem::rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};