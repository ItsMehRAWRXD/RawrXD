#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <random>
#include <chrono>
#include <thread>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "uniquestub.h"

int main() {
    std::cout << "=== Unique Stub Test Program ===" << std::endl;
    std::cout << "Testing unique stub generation and compilation..." << std::endl;
    
    // Create test payload
    std::vector<uint8_t> testPayload = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // NOP sled
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F,  // "Hello Wo"
        0x72, 0x6C, 0x64, 0x21, 0x00, 0x90, 0x90, 0x90   // "rld!" + NOPs
    };
    
    std::cout << "Test payload size: " << testPayload.size() << " bytes" << std::endl;
    
    // Create unique stub generator
    UniqueStubGenerator generator;
    
    // Generate unique key
    std::string uniqueKey = generator.generateUniqueKey();
    std::cout << "Generated unique key: " << uniqueKey << std::endl;
    
    // Generate unique stub
    std::cout << "Generating unique stub..." << std::endl;
    std::string uniqueStub = generator.generateUniqueStub(testPayload, uniqueKey);
    
    std::cout << "Unique stub generated successfully!" << std::endl;
    std::cout << "Stub size: " << uniqueStub.length() << " characters" << std::endl;
    
    // Save stub to file
    std::string tempStubFile = "test_unique_stub_" + std::to_string(GetTickCount()) + ".cpp";
    if (!UniqueStubUtils::saveStubToFile(uniqueStub, tempStubFile)) {
        std::cout << "ERROR: Failed to save stub to file!" << std::endl;
        return 1;
    }
    
    std::cout << "Stub saved to: " << tempStubFile << std::endl;
    
    // Test compilation
    std::string outputExe = "test_unique_stub_output.exe";
    std::cout << "Testing stub compilation..." << std::endl;
    
    bool compileSuccess = UniqueStubUtils::compileStub(tempStubFile, outputExe);
    
    if (compileSuccess) {
        std::cout << "SUCCESS: Unique stub compiled successfully!" << std::endl;
        std::cout << "Output executable: " << outputExe << std::endl;
        
        // Check if output file exists
        std::ifstream checkFile(outputExe, std::ios::binary);
        if (checkFile.good()) {
            checkFile.seekg(0, std::ios::end);
            size_t exeSize = checkFile.tellg();
            checkFile.close();
            std::cout << "Executable size: " << exeSize << " bytes" << std::endl;
        }
    } else {
        std::cout << "ERROR: Failed to compile unique stub!" << std::endl;
    }
    
    // Clean up temporary files
    std::remove(tempStubFile.c_str());
    
    std::cout << "=== Test completed ===" << std::endl;
    return compileSuccess ? 0 : 1;
}