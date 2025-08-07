#pragma once

// Cross-platform includes
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#else
// OpenSSL includes would go here if building on Linux
// For now, fallback to simple XOR encryption on non-Windows
#include <unistd.h>
#include <sys/stat.h>
#endif

#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>

class CrossPlatformEncryption {
private:
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::mt19937 rng;

public:
    enum class Method {
        XOR,
        AES,
        CHACHA20
    };

    CrossPlatformEncryption() : rng(std::random_device{}()) {
        generateRandomKey();
        generateRandomIV();
    }

    // Generate random 32-byte key
    void generateRandomKey() {
        key.resize(32);
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(rng() & 0xFF);
        }
    }

    // Generate random 16-byte IV
    void generateRandomIV() {
        iv.resize(16);
        for (auto& byte : iv) {
            byte = static_cast<uint8_t>(rng() & 0xFF);
        }
    }

    // Get key as hex string for embedding in code
    std::string getKeyAsHex() const {
        std::stringstream ss;
        for (size_t i = 0; i < key.size(); ++i) {
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)key[i];
            if (i < key.size() - 1) ss << ", ";
        }
        return ss.str();
    }

    // Get IV as hex string for embedding in code
    std::string getIVAsHex() const {
        std::stringstream ss;
        for (size_t i = 0; i < iv.size(); ++i) {
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)iv[i];
            if (i < iv.size() - 1) ss << ", ";
        }
        return ss.str();
    }

    // XOR Encryption (simplest, fastest)
    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encrypted = data;
        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= key[i % key.size()];
        }
        return encrypted;
    }

    // XOR Decryption (same as encryption)
    std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& data) {
        return xorEncrypt(data); // XOR is symmetric
    }

    // AES Encryption
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& data) {
#ifdef _WIN32
        return aesEncryptWindows(data);
#else
        return aesEncryptOpenSSL(data);
#endif
    }

    // AES Decryption
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& data) {
#ifdef _WIN32
        return aesDecryptWindows(data);
#else
        return aesDecryptOpenSSL(data);
#endif
    }

    // AES Decryption
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& data) {
#ifdef _WIN32
        return aesDecryptWindows(data);
#else
        return aesDecryptOpenSSL(data);
#endif
    }

    // ChaCha20 Encryption (implemented as enhanced XOR for portability)
    std::vector<uint8_t> chacha20Encrypt(const std::vector<uint8_t>& data) {
        // Simplified ChaCha20-style encryption using multiple rounds
        std::vector<uint8_t> encrypted = data;

        // Multiple rounds with different key rotations
        for (int round = 0; round < 20; ++round) {
            for (size_t i = 0; i < encrypted.size(); ++i) {
                uint8_t keyByte = key[(i + round) % key.size()];
                uint8_t ivByte = iv[(i + round) % iv.size()];
                encrypted[i] ^= keyByte ^ ivByte ^ (round & 0xFF);

                // Add some bit rotation for extra obfuscation
                encrypted[i] = ((encrypted[i] << 3) | (encrypted[i] >> 5)) & 0xFF;
            }
        }

        return encrypted;
    }

    // ChaCha20 Decryption
    std::vector<uint8_t> chacha20Decrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> decrypted = data;

        // Reverse the encryption process
        for (int round = 19; round >= 0; --round) {
            for (size_t i = 0; i < decrypted.size(); ++i) {
                // Reverse bit rotation
                decrypted[i] = ((decrypted[i] >> 3) | (decrypted[i] << 5)) & 0xFF;

                uint8_t keyByte = key[(i + round) % key.size()];
                uint8_t ivByte = iv[(i + round) % iv.size()];
                decrypted[i] ^= keyByte ^ ivByte ^ (round & 0xFF);
            }
        }

        return decrypted;
    }

    // Main encryption function
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, Method method) {
        switch (method) {
        case Method::XOR:
            return xorEncrypt(data);
        case Method::AES:
            return aesEncrypt(data);
        case Method::CHACHA20:
            return chacha20Encrypt(data);
        default:
            throw std::runtime_error("Unknown encryption method");
        }
    }

    // Main decryption function
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, Method method) {
        switch (method) {
        case Method::XOR:
            return xorDecrypt(data);
        case Method::AES:
            return aesDecrypt(data);
        case Method::CHACHA20:
            return chacha20Decrypt(data);
        default:
            throw std::runtime_error("Unknown decryption method");
        }
    }

    // Generate decryption stub code for embedding
    std::string generateDecryptionStub(Method method, const std::vector<uint8_t>& encryptedData) {
        std::stringstream code;

        code << "// Cross-platform decryption stub\n";
        code << "#include <vector>\n";
        code << "#include <cstdint>\n\n";

        // Embed the key and IV
        code << "static const uint8_t decrypt_key[] = {" << getKeyAsHex() << "};\n";
        code << "static const uint8_t decrypt_iv[] = {" << getIVAsHex() << "};\n\n";

        // Embed the encrypted data
        code << "static const uint8_t encrypted_payload[] = {";
        for (size_t i = 0; i < encryptedData.size(); ++i) {
            if (i % 16 == 0) code << "\n    ";
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)encryptedData[i];
            if (i < encryptedData.size() - 1) code << ", ";
        }
        code << "\n};\n\n";
        code << "static const size_t payload_size = " << std::dec << encryptedData.size() << ";\n\n";

        // Generate the appropriate decryption function
        switch (method) {
        case Method::XOR:
            code << generateXORDecryptionCode();
            break;
        case Method::AES:
            code << generateAESDecryptionCode();
            break;
        case Method::CHACHA20:
            code << generateChaCha20DecryptionCode();
            break;
        }

        return code.str();
    }

private:
    // Windows AES implementation
#ifdef _WIN32
    std::vector<uint8_t> aesEncryptWindows(const std::vector<uint8_t>& data) {
        HCRYPTPROV hCryptProv = 0;
        HCRYPTKEY hKey = 0;
        std::vector<uint8_t> encrypted;

        try {
            if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                throw std::runtime_error("CryptAcquireContext failed");
            }

            struct {
                BLOBHEADER hdr;
                DWORD keySize;
                BYTE keyData[32];
            } keyBlob;

            keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
            keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
            keyBlob.hdr.reserved = 0;
            keyBlob.hdr.aiKeyAlg = CALG_AES_256;
            keyBlob.keySize = 32;
            memcpy(keyBlob.keyData, key.data(), 32);

            if (!CryptImportKey(hCryptProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
                throw std::runtime_error("CryptImportKey failed");
            }

            encrypted = data;
            DWORD dataLen = static_cast<DWORD>(encrypted.size());

            if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataLen, static_cast<DWORD>(encrypted.capacity()))) {
                encrypted.resize(dataLen);
                if (!CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataLen, static_cast<DWORD>(encrypted.capacity()))) {
                    throw std::runtime_error("CryptEncrypt failed");
                }
            }

            encrypted.resize(dataLen);

        }
        catch (...) {
            if (hKey) CryptDestroyKey(hKey);
            if (hCryptProv) CryptReleaseContext(hCryptProv, 0);
            throw;
        }

        if (hKey) CryptDestroyKey(hKey);
        if (hCryptProv) CryptReleaseContext(hCryptProv, 0);

        return encrypted;
    }

    std::vector<uint8_t> aesDecryptWindows(const std::vector<uint8_t>& data) {
        // Similar implementation for decryption
        return xorDecrypt(data); // Fallback to XOR for now
    }
#else
    // Non-Windows AES implementation (fallback to XOR)
    std::vector<uint8_t> aesEncryptOpenSSL(const std::vector<uint8_t>& data) {
        // Fallback to XOR encryption on non-Windows platforms
        return xorEncrypt(data);
    }

    std::vector<uint8_t> aesDecryptOpenSSL(const std::vector<uint8_t>& data) {
        // Fallback to XOR decryption on non-Windows platforms
        return xorDecrypt(data);
    }
#endif

    // Code generation for different decryption methods
    std::string generateXORDecryptionCode() {
        return R"(
std::vector<uint8_t> xorDecrypt() {
    std::vector<uint8_t> decrypted(payload_size);
    for (size_t i = 0; i < payload_size; ++i) {
        decrypted[i] = encrypted_payload[i] ^ decrypt_key[i % 32];
    }
    return decrypted;
}

void executeDecryptedPayload() {
    std::vector<uint8_t> payload = xorDecrypt();
    // Execute payload logic here
    // For now, just verify decryption worked
    if (payload.size() > 0) {
        // Payload decrypted successfully
    }
}
)";
    }

    std::string generateAESDecryptionCode() {
        return R"(
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

std::vector<uint8_t> aesDecrypt() {
    HCRYPTPROV hCryptProv = 0;
    HCRYPTKEY hKey = 0;
    std::vector<uint8_t> decrypted(encrypted_payload, encrypted_payload + payload_size);
    
    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        struct {
            BLOBHEADER hdr;
            DWORD keySize;
            BYTE keyData[32];
        } keyBlob;
        
        keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
        keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
        keyBlob.hdr.reserved = 0;
        keyBlob.hdr.aiKeyAlg = CALG_AES_256;
        keyBlob.keySize = 32;
        memcpy(keyBlob.keyData, decrypt_key, 32);
        
        if (CryptImportKey(hCryptProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
            DWORD dataLen = payload_size;
            CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &dataLen);
            decrypted.resize(dataLen);
            CryptDestroyKey(hKey);
        }
        CryptReleaseContext(hCryptProv, 0);
    }
    return decrypted;
}
#else
// Fallback to XOR on non-Windows platforms
std::vector<uint8_t> aesDecrypt() {
    std::vector<uint8_t> decrypted(payload_size);
    for (size_t i = 0; i < payload_size; ++i) {
        decrypted[i] = encrypted_payload[i] ^ decrypt_key[i % 32];
    }
    return decrypted;
}
#endif

void executeDecryptedPayload() {
    std::vector<uint8_t> payload = aesDecrypt();
    // Execute payload logic here
}
)";
    }

    std::string generateChaCha20DecryptionCode() {
        return R"(
std::vector<uint8_t> chacha20Decrypt() {
    std::vector<uint8_t> decrypted(encrypted_payload, encrypted_payload + payload_size);
    
    // ChaCha20-style decryption (simplified)
    for (int round = 19; round >= 0; --round) {
        for (size_t i = 0; i < payload_size; ++i) {
            // Reverse bit rotation
            decrypted[i] = ((decrypted[i] >> 3) | (decrypted[i] << 5)) & 0xFF;
            
            uint8_t keyByte = decrypt_key[(i + round) % 32];
            uint8_t ivByte = decrypt_iv[(i + round) % 16];
            decrypted[i] ^= keyByte ^ ivByte ^ (round & 0xFF);
        }
    }
    
    return decrypted;
}

void executeDecryptedPayload() {
    std::vector<uint8_t> payload = chacha20Decrypt();
    // Execute payload logic here
}
)";
    }
};