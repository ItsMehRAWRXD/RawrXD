#!/bin/bash
# Quantum MASM System 2035 - Local File Generator
# This script recreates all files locally (like wget would)

echo "================================================================"
echo "QUANTUM MASM SYSTEM 2035 - LOCAL FILE GENERATOR"
echo "================================================================"
echo "Generating all files locally..."
echo

# Create project directory
mkdir -p quantum_masm_system_2035
cd quantum_masm_system_2035

echo "[1/8] Creating shellcode_generator.cpp..."
cat > shellcode_generator.cpp << 'EOF'
#include <fstream>
#include <vector>
#include <cstdint>

int main() {
    // Simple x64 Linux shellcode that prints "Hello!" and exits
    std::vector<uint8_t> shellcode = {
        // mov rax, 1 (sys_write)
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
        // mov rdi, 1 (stdout)
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,
        // lea rsi, [rip+0x21] (address of string)
        0x48, 0x8d, 0x35, 0x21, 0x00, 0x00, 0x00,
        // mov rdx, 28 (length)
        0x48, 0xc7, 0xc2, 0x1c, 0x00, 0x00, 0x00,
        // syscall
        0x0f, 0x05,
        // mov rax, 60 (sys_exit)
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,
        // xor rdi, rdi
        0x48, 0x31, 0xff,
        // syscall
        0x0f, 0x05,
        // String data
        'F', 'i', 'l', 'e', 'l', 'e', 's', 's', ' ',
        'p', 'a', 'y', 'l', 'o', 'a', 'd', ' ',
        'e', 'x', 'e', 'c', 'u', 't', 'e', 'd', '!', '\n', '\0'
    };
    
    std::ofstream out("test_shellcode.bin", std::ios::binary);
    out.write(reinterpret_cast<char*>(shellcode.data()), shellcode.size());
    out.close();
    
    return 0;
}
EOF
echo "✓ shellcode_generator.cpp created"

echo "[2/8] Creating data_converter.cpp..."
cat > data_converter.cpp << 'EOF'
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>

class DataConverter {
public:
    // Convert bytes to hex string
    static std::string bytesToHex(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; i++) {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Convert bytes to hex string with spaces
    static std::string bytesToHexSpaced(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; i++) {
            if (i > 0) ss << " ";
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Convert hex string to bytes
    static std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        std::string cleanHex = hex;
        
        // Remove spaces and 0x prefix if present
        cleanHex.erase(std::remove_if(cleanHex.begin(), cleanHex.end(), ::isspace), cleanHex.end());
        if (cleanHex.substr(0, 2) == "0x" || cleanHex.substr(0, 2) == "0X") {
            cleanHex = cleanHex.substr(2);
        }
        
        // Ensure even length
        if (cleanHex.length() % 2 != 0) {
            cleanHex = "0" + cleanHex;
        }
        
        for (size_t i = 0; i < cleanHex.length(); i += 2) {
            std::string byteString = cleanHex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }
    
    // Convert bytes to decimal string (as individual values)
    static std::string bytesToDecimal(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        for (size_t i = 0; i < length; i++) {
            if (i > 0) ss << " ";
            ss << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }
    
    // Convert bytes to base64
    static std::string bytesToBase64(const uint8_t* bytes, size_t length) {
        const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::string result;
        int val = 0, valb = -6;
        
        for (size_t i = 0; i < length; i++) {
            val = (val << 8) + bytes[i];
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        
        if (valb > -6) {
            result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }
        
        while (result.size() % 4) {
            result.push_back('=');
        }
        
        return result;
    }
    
    // Convert bytes to C array format
    static std::string bytesToCArray(const uint8_t* bytes, size_t length, const std::string& varName = "data") {
        std::stringstream ss;
        ss << "const unsigned char " << varName << "[" << length << "] = {\n    ";
        
        for (size_t i = 0; i < length; i++) {
            if (i > 0 && i % 16 == 0) ss << "\n    ";
            ss << "0x" << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(bytes[i]);
            if (i < length - 1) ss << ", ";
        }
        
        ss << "\n};";
        return ss.str();
    }
};

// Example usage and demonstration
int main() {
    std::cout << "=== Data Converter Utility ===" << std::endl;
    std::cout << "Converts between bytes, hex, and decimal representations\n" << std::endl;
    
    // Example data
    uint8_t testBytes[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64};
    size_t testLength = sizeof(testBytes);
    
    std::cout << "Original bytes (ASCII): ";
    for (size_t i = 0; i < testLength; i++) {
        if (testBytes[i] >= 32 && testBytes[i] <= 126) {
            std::cout << static_cast<char>(testBytes[i]);
        } else {
            std::cout << ".";
        }
    }
    std::cout << "\n\n";
    
    // Demonstrate conversions
    std::cout << "Hex string: " << DataConverter::bytesToHex(testBytes, testLength) << std::endl;
    std::cout << "Hex spaced: " << DataConverter::bytesToHexSpaced(testBytes, testLength) << std::endl;
    std::cout << "Decimal (individual): " << DataConverter::bytesToDecimal(testBytes, testLength) << std::endl;
    std::cout << "Base64: " << DataConverter::bytesToBase64(testBytes, testLength) << std::endl;
    
    std::cout << "\nC Array format:\n" << DataConverter::bytesToCArray(testBytes, testLength) << std::endl;
    
    return 0;
}
EOF
echo "✓ data_converter.cpp created"

echo "[3/8] Creating Makefile..."
cat > Makefile << 'EOF'
# Quantum MASM System 2035 - MinGW Makefile
CXX = g++
CXXFLAGS = -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++
TARGETS = shellcode_generator.exe data_converter.exe

all: $(TARGETS)
	@echo "Build complete!"

shellcode_generator.exe: shellcode_generator.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

data_converter.exe: data_converter.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

test: $(TARGETS)
	./shellcode_generator.exe
	./data_converter.exe

clean:
	rm -f $(TARGETS) *.o test_shellcode.bin

.PHONY: all test clean
EOF
echo "✓ Makefile created"

echo "[4/8] Creating build_mingw.bat..."
cat > build_mingw.bat << 'EOF'
@echo off
echo Building Quantum MASM System 2035 with MinGW...
g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o shellcode_generator.exe shellcode_generator.cpp
g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o data_converter.exe data_converter.cpp
echo Build complete!
pause
EOF
echo "✓ build_mingw.bat created"

echo "[5/8] Creating README.md..."
cat > README.md << 'EOF'
# Quantum MASM System 2035

## Quick Start

### Build with MinGW
```bash
# Windows
build_mingw.bat

# Linux/MinGW
make all
```

### Usage
```bash
./shellcode_generator.exe    # Generate test payload
./data_converter.exe         # Data format converter
```

## Original Source
Recovered from: https://github.com/ItsMehRAWRXD/RawrXD/commit/599dfa920a22909238d74eca5621639a5849f41e
EOF
echo "✓ README.md created"

echo "[6/8] Building executables..."
if command -v g++ >/dev/null 2>&1; then
    g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o shellcode_generator.exe shellcode_generator.cpp 2>/dev/null
    g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o data_converter.exe data_converter.cpp 2>/dev/null
    if [ -f "shellcode_generator.exe" ] && [ -f "data_converter.exe" ]; then
        echo "✓ Executables built successfully"
    else
        echo "⚠ Could not build executables (MinGW not available)"
    fi
else
    echo "⚠ g++ not found, skipping executable build"
fi

echo "[7/8] Testing..."
if [ -f "shellcode_generator.exe" ]; then
    ./shellcode_generator.exe 2>/dev/null
    if [ -f "test_shellcode.bin" ]; then
        echo "✓ Test payload generated"
    fi
fi

echo "[8/8] Final verification..."
echo "Files created:"
ls -la
echo
echo "================================================================"
echo "SUCCESS! Quantum MASM System 2035 Generated Locally"
echo "================================================================"
echo "Location: $(pwd)"
echo "Build with: make all  (or build_mingw.bat on Windows)"
echo "Original: https://github.com/ItsMehRAWRXD/RawrXD/commit/599dfa920a22909238d74eca5621639a5849f41e"
echo "================================================================"