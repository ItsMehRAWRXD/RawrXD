//=============================================================================
// test_compression.cpp - Unit tests for RawrXD_Compression
//=============================================================================

#include <iostream>
#include <cstring>
#include <vector>
#include <random>
#include "../asm/RawrXD_Compression.hpp"

using namespace RawrXD::Compression;

bool g_allTestsPassed = true;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] " << msg << " at line " << __LINE__ << "\n"; \
            g_allTestsPassed = false; \
        } else { \
            std::cout << "[PASS] " << msg << "\n"; \
        } \
    } while(0)

void TestVersion() {
    std::cout << "\n=== Testing Version ===\n";
    uint32_t version = Compressor::GetVersion();
    TEST_ASSERT(version != 0, "Version returns non-zero");
    std::cout << "  Version: " << std::hex << version << std::dec << "\n";
}

void TestInit() {
    std::cout << "\n=== Testing Init ===\n";
    bool result = Compressor::Initialize(1);
    TEST_ASSERT(result, "Initialize returns true");
}

void TestMaxSize() {
    std::cout << "\n=== Testing MaxSize ===\n";
    size_t maxSize = Compressor::GetMaxCompressedSize(1024);
    TEST_ASSERT(maxSize > 1024, "Max compressed size > original");
    std::cout << "  Max size for 1024 bytes: " << maxSize << "\n";
}

void TestCompressDecompressSimple() {
    std::cout << "\n=== Testing Compress/Decompress (Simple) ===\n";
    
    const char* testData = "Hello, World! This is a test of the RawrXD compression system.";
    size_t testLen = strlen(testData) + 1;
    
    // Compress
    std::vector<uint8_t> compressed(Compressor::GetMaxCompressedSize(testLen));
    size_t compressedSize = Compressor::Compress(testData, testLen, compressed.data(), compressed.size());
    
    TEST_ASSERT(compressedSize > 0, "Compression succeeded");
    TEST_ASSERT(compressedSize < testLen * 2, "Compressed size reasonable");
    
    std::cout << "  Original: " << testLen << " bytes\n";
    std::cout << "  Compressed: " << compressedSize << " bytes\n";
    std::cout << "  Ratio: " << (100.0 * compressedSize / testLen) << "%\n";
    
    // Decompress
    std::vector<uint8_t> decompressed(testLen);
    size_t decompressedSize = Compressor::Decompress(compressed.data(), compressedSize, decompressed.data(), decompressed.size());
    
    TEST_ASSERT(decompressedSize == testLen, "Decompressed size matches original");
    TEST_ASSERT(memcmp(testData, decompressed.data(), testLen) == 0, "Data matches after round-trip");
}

void TestCompressDecompressLarge() {
    std::cout << "\n=== Testing Compress/Decompress (Large) ===\n";
    
    // Generate test data with some repetition
    std::vector<uint8_t> testData(10000);
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> dist(0, 255);
    
    for (size_t i = 0; i < testData.size(); ++i) {
        // Add some patterns
        if (i % 100 < 50) {
            testData[i] = 'A' + (i % 26);
        } else {
            testData[i] = static_cast<uint8_t>(dist(rng));
        }
    }
    
    // Compress
    std::vector<uint8_t> compressed(Compressor::GetMaxCompressedSize(testData.size()));
    size_t compressedSize = Compressor::Compress(testData.data(), testData.size(), compressed.data(), compressed.size());
    
    TEST_ASSERT(compressedSize > 0, "Large compression succeeded");
    
    std::cout << "  Original: " << testData.size() << " bytes\n";
    std::cout << "  Compressed: " << compressedSize << " bytes\n";
    std::cout << "  Ratio: " << (100.0 * compressedSize / testData.size()) << "%\n";
    
    // Decompress
    std::vector<uint8_t> decompressed(testData.size());
    size_t decompressedSize = Compressor::Decompress(compressed.data(), compressedSize, decompressed.data(), decompressed.size());
    
    TEST_ASSERT(decompressedSize == testData.size(), "Large decompressed size matches");
    TEST_ASSERT(memcmp(testData.data(), decompressed.data(), testData.size()) == 0, "Large data matches");
}

void TestCompressDecompressZeros() {
    std::cout << "\n=== Testing Compress/Decompress (Zeros) ===\n";
    
    // Highly compressible data
    std::vector<uint8_t> testData(1000, 0);
    
    // Compress
    std::vector<uint8_t> compressed(Compressor::GetMaxCompressedSize(testData.size()));
    size_t compressedSize = Compressor::Compress(testData.data(), testData.size(), compressed.data(), compressed.size());
    
    TEST_ASSERT(compressedSize > 0, "Zero compression succeeded");
    
    std::cout << "  Original: " << testData.size() << " bytes\n";
    std::cout << "  Compressed: " << compressedSize << " bytes\n";
    std::cout << "  Ratio: " << (100.0 * compressedSize / testData.size()) << "%\n";
    
    // Decompress
    std::vector<uint8_t> decompressed(testData.size());
    size_t decompressedSize = Compressor::Decompress(compressed.data(), compressedSize, decompressed.data(), decompressed.size());
    
    TEST_ASSERT(decompressedSize == testData.size(), "Zero decompressed size matches");
    TEST_ASSERT(memcmp(testData.data(), decompressed.data(), testData.size()) == 0, "Zero data matches");
}

void TestEmptyInput() {
    std::cout << "\n=== Testing Empty Input ===\n";
    
    uint8_t dummy = 0;
    size_t compressedSize = Compressor::Compress(&dummy, 0, &dummy, 1);
    
    TEST_ASSERT(compressedSize == 0, "Empty input returns 0");
}

int main() {
    std::cout << "============================================================\n";
    std::cout << "RawrXD Compression Test Suite\n";
    std::cout << "============================================================\n";
    
    TestVersion();
    TestInit();
    TestMaxSize();
    TestCompressDecompressSimple();
    TestCompressDecompressLarge();
    TestCompressDecompressZeros();
    TestEmptyInput();
    
    std::cout << "\n============================================================\n";
    if (g_allTestsPassed) {
        std::cout << "ALL TESTS PASSED\n";
        return 0;
    } else {
        std::cout << "SOME TESTS FAILED\n";
        return 1;
    }
}
