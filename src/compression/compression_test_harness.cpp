// ============================================================================
// compression_test_harness.cpp - Brutal Compression System Test
// ============================================================================
// Comprehensive testing of RawrXD compression:
// - ZLIB runtime loader
// - MASM compression kernels
// - Model streaming compatibility
// - Performance benchmarks
// ============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>
#include "zlib_runtime_loader.hpp"

using namespace RawrXD::Compression;

// ============================================================================
// Test Results
// ============================================================================
struct TestResults {
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    double totalCompressionTime = 0.0;
    double totalDecompressionTime = 0.0;
    size_t totalBytesProcessed = 0;
    
    void RecordPass(const char* testName) {
        totalTests++;
        passedTests++;
        std::cout << "[PASS] " << testName << std::endl;
    }
    
    void RecordFail(const char* testName, const char* reason) {
        totalTests++;
        failedTests++;
        std::cout << "[FAIL] " << testName << ": " << reason << std::endl;
    }
    
    void PrintSummary() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Compression Test Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Total:  " << totalTests << std::endl;
        std::cout << "Passed: " << passedTests << std::endl;
        std::cout << "Failed: " << failedTests << std::endl;
        std::cout << "Total bytes processed: " << totalBytesProcessed << std::endl;
        std::cout << "Avg compression time: " << (totalCompressionTime / passedTests) << " ms" << std::endl;
        std::cout << "Avg decompression time: " << (totalDecompressionTime / passedTests) << " ms" << std::endl;
        std::cout << "========================================" << std::endl;
    }
};

static TestResults g_results;

// ============================================================================
// Test 1: ZLIB Runtime Loader
// ============================================================================
void Test_ZlibRuntimeLoader() {
    std::cout << "\n[Test] ZLIB Runtime Loader..." << std::endl;
    
    ZlibRuntimeLoader loader;
    
    // Test load
    if (!loader.Load()) {
        g_results.RecordFail("ZlibLoader", loader.GetLastError());
        return;
    }
    
    if (!loader.IsLoaded()) {
        g_results.RecordFail("ZlibLoader", "IsLoaded returned false after Load");
        return;
    }
    
    // Test version
    const char* version = loader.GetVersion();
    if (!version || strlen(version) == 0) {
        g_results.RecordFail("ZlibLoader", "Failed to get version");
        return;
    }
    
    std::cout << "  ZLIB version: " << version << std::endl;
    
    // Test unload
    loader.Unload();
    if (loader.IsLoaded()) {
        g_results.RecordFail("ZlibLoader", "IsLoaded returned true after Unload");
        return;
    }
    
    g_results.RecordPass("ZlibLoader");
}

// ============================================================================
// Test 2: Basic Compression/Decompression
// ============================================================================
void Test_BasicCompression() {
    std::cout << "\n[Test] Basic Compression..." << std::endl;
    
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        g_results.RecordFail("BasicCompression", "Failed to load ZLIB");
        return;
    }
    
    // Test data
    const char* testData = "Hello, RawrXD Compression! This is a test string for compression.";
    size_t testLen = strlen(testData);
    
    std::vector<uint8_t> compressed(testLen * 2);
    std::vector<uint8_t> decompressed(testLen + 100);
    
    uint32_t compressedLen = compressed.size();
    uint32_t decompressedLen = decompressed.size();
    
    // Compress
    auto start = std::chrono::high_resolution_clock::now();
    if (!loader.Compress(compressed.data(), &compressedLen, 
                         (const uint8_t*)testData, testLen)) {
        g_results.RecordFail("BasicCompression", "Compression failed");
        return;
    }
    auto compressTime = std::chrono::high_resolution_clock::now() - start;
    
    // Decompress
    start = std::chrono::high_resolution_clock::now();
    if (!loader.Decompress(decompressed.data(), &decompressedLen,
                           compressed.data(), compressedLen)) {
        g_results.RecordFail("BasicCompression", "Decompression failed");
        return;
    }
    auto decompressTime = std::chrono::high_resolution_clock::now() - start;
    
    // Verify
    if (decompressedLen != testLen) {
        g_results.RecordFail("BasicCompression", "Decompressed length mismatch");
        return;
    }
    
    if (memcmp(decompressed.data(), testData, testLen) != 0) {
        g_results.RecordFail("BasicCompression", "Data mismatch after round-trip");
        return;
    }
    
    double ratio = (double)compressedLen / testLen * 100.0;
    std::cout << "  Original: " << testLen << " bytes" << std::endl;
    std::cout << "  Compressed: " << compressedLen << " bytes (" << ratio << "%)" << std::endl;
    std::cout << "  Compression time: " 
              << std::chrono::duration<double, std::milli>(compressTime).count() 
              << " ms" << std::endl;
    std::cout << "  Decompression time: " 
              << std::chrono::duration<double, std::milli>(decompressTime).count() 
              << " ms" << std::endl;
    
    g_results.totalCompressionTime += std::chrono::duration<double, std::milli>(compressTime).count();
    g_results.totalDecompressionTime += std::chrono::duration<double, std::milli>(decompressTime).count();
    g_results.totalBytesProcessed += testLen;
    
    g_results.RecordPass("BasicCompression");
}

// ============================================================================
// Test 3: Large Data Compression (Model Streaming Simulation)
// ============================================================================
void Test_LargeDataCompression() {
    std::cout << "\n[Test] Large Data Compression (Model Streaming)..." << std::endl;
    
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        g_results.RecordFail("LargeDataCompression", "Failed to load ZLIB");
        return;
    }
    
    // Simulate model weights (random data with some patterns)
    const size_t dataSize = 1024 * 1024; // 1MB
    std::vector<uint8_t> data(dataSize);
    
    // Fill with semi-random data (simulating quantized weights)
    std::mt19937 rng(42);
    for (size_t i = 0; i < dataSize; i++) {
        // Create runs of similar values (typical in quantized models)
        if (i % 16 == 0) {
            data[i] = rng() % 256;
        } else {
            data[i] = data[i-1] + (rng() % 5) - 2;
        }
    }
    
    std::vector<uint8_t> compressed(dataSize);
    std::vector<uint8_t> decompressed(dataSize);
    
    uint32_t compressedLen = compressed.size();
    uint32_t decompressedLen = decompressed.size();
    
    // Compress
    auto start = std::chrono::high_resolution_clock::now();
    if (!loader.Compress(compressed.data(), &compressedLen, data.data(), dataSize, 6)) {
        g_results.RecordFail("LargeDataCompression", "Compression failed");
        return;
    }
    auto compressTime = std::chrono::high_resolution_clock::now() - start;
    
    // Decompress
    start = std::chrono::high_resolution_clock::now();
    if (!loader.Decompress(decompressed.data(), &decompressedLen,
                           compressed.data(), compressedLen)) {
        g_results.RecordFail("LargeDataCompression", "Decompression failed");
        return;
    }
    auto decompressTime = std::chrono::high_resolution_clock::now() - start;
    
    // Verify
    if (decompressedLen != dataSize) {
        g_results.RecordFail("LargeDataCompression", "Length mismatch");
        return;
    }
    
    if (memcmp(decompressed.data(), data.data(), dataSize) != 0) {
        g_results.RecordFail("LargeDataCompression", "Data mismatch");
        return;
    }
    
    double ratio = (double)compressedLen / dataSize * 100.0;
    double compressSpeed = (dataSize / 1024.0 / 1024.0) / 
                          (std::chrono::duration<double>(compressTime).count());
    double decompressSpeed = (dataSize / 1024.0 / 1024.0) / 
                            (std::chrono::duration<double>(decompressTime).count());
    
    std::cout << "  Data size: " << (dataSize / 1024 / 1024) << " MB" << std::endl;
    std::cout << "  Compressed: " << (compressedLen / 1024) << " KB (" << ratio << "%)" << std::endl;
    std::cout << "  Compression speed: " << compressSpeed << " MB/s" << std::endl;
    std::cout << "  Decompression speed: " << decompressSpeed << " MB/s" << std::endl;
    
    g_results.totalCompressionTime += std::chrono::duration<double, std::milli>(compressTime).count();
    g_results.totalDecompressionTime += std::chrono::duration<double, std::milli>(decompressTime).count();
    g_results.totalBytesProcessed += dataSize;
    
    g_results.RecordPass("LargeDataCompression");
}

// ============================================================================
// Test 4: Streaming Compression (Chunked Model Loading)
// ============================================================================
void Test_StreamingCompression() {
    std::cout << "\n[Test] Streaming Compression..." << std::endl;
    
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        g_results.RecordFail("StreamingCompression", "Failed to load ZLIB");
        return;
    }
    
    // Simulate streaming chunks (like model layer loading)
    const size_t chunkSize = 64 * 1024; // 64KB chunks
    const int numChunks = 16;
    
    std::vector<uint8_t> data(chunkSize * numChunks);
    std::mt19937 rng(12345);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = rng() % 256;
    }
    
    // Compress chunks
    ZlibStream strm = {};
    if (!loader.DeflateInit(&strm, 6, 15)) {
        g_results.RecordFail("StreamingCompression", "DeflateInit failed");
        return;
    }
    
    std::vector<uint8_t> compressed(data.size() * 2);
    strm.next_out = compressed.data();
    strm.avail_out = compressed.size();
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < numChunks; i++) {
        strm.next_in = data.data() + (i * chunkSize);
        strm.avail_in = chunkSize;
        
        int flush = (i == numChunks - 1) ? 4 : 0; // Z_FINISH on last chunk
        if (!loader.Deflate(&strm, flush)) {
            g_results.RecordFail("StreamingCompression", "Deflate failed");
            loader.DeflateEnd(&strm);
            return;
        }
    }
    
    uint32_t compressedLen = strm.total_out;
    loader.DeflateEnd(&strm);
    
    auto compressTime = std::chrono::high_resolution_clock::now() - start;
    
    // Decompress
    ZlibStream decompStrm = {};
    if (!loader.InflateInit(&decompStrm, 15)) {
        g_results.RecordFail("StreamingCompression", "InflateInit failed");
        return;
    }
    
    std::vector<uint8_t> decompressed(data.size());
    decompStrm.next_in = compressed.data();
    decompStrm.avail_in = compressedLen;
    decompStrm.next_out = decompressed.data();
    decompStrm.avail_out = decompressed.size();
    
    start = std::chrono::high_resolution_clock::now();
    if (!loader.Inflate(&decompStrm, 4)) { // Z_FINISH
        g_results.RecordFail("StreamingCompression", "Inflate failed");
        loader.InflateEnd(&decompStrm);
        return;
    }
    loader.InflateEnd(&decompStrm);
    auto decompressTime = std::chrono::high_resolution_clock::now() - start;
    
    // Verify
    if (memcmp(decompressed.data(), data.data(), data.size()) != 0) {
        g_results.RecordFail("StreamingCompression", "Data mismatch");
        return;
    }
    
    std::cout << "  Chunks: " << numChunks << " x " << (chunkSize / 1024) << " KB" << std::endl;
    std::cout << "  Total: " << (data.size() / 1024) << " KB" << std::endl;
    std::cout << "  Compressed: " << (compressedLen / 1024) << " KB" << std::endl;
    
    g_results.RecordPass("StreamingCompression");
}

// ============================================================================
// Test 5: Checksum Functions
// ============================================================================
void Test_Checksums() {
    std::cout << "\n[Test] Checksums..." << std::endl;
    
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        g_results.RecordFail("Checksums", "Failed to load ZLIB");
        return;
    }
    
    const char* testData = "RawrXD Compression Test";
    size_t len = strlen(testData);
    
    // CRC32
    uint32_t crc = loader.CRC32(0, (const uint8_t*)testData, len);
    if (crc == 0) {
        g_results.RecordFail("Checksums", "CRC32 returned 0");
        return;
    }
    
    // Adler32
    uint32_t adler = loader.Adler32(0, (const uint8_t*)testData, len);
    if (adler == 0) {
        g_results.RecordFail("Checksums", "Adler32 returned 0");
        return;
    }
    
    // Verify CRC32 is deterministic
    uint32_t crc2 = loader.CRC32(0, (const uint8_t*)testData, len);
    if (crc != crc2) {
        g_results.RecordFail("Checksums", "CRC32 not deterministic");
        return;
    }
    
    std::cout << "  CRC32: 0x" << std::hex << crc << std::dec << std::endl;
    std::cout << "  Adler32: 0x" << std::hex << adler << std::dec << std::endl;
    
    g_results.RecordPass("Checksums");
}

// ============================================================================
// Test 6: Edge Cases
// ============================================================================
void Test_EdgeCases() {
    std::cout << "\n[Test] Edge Cases..." << std::endl;
    
    ZlibRuntimeLoader loader;
    if (!loader.Load()) {
        g_results.RecordFail("EdgeCases", "Failed to load ZLIB");
        return;
    }
    
    // Test 1: Empty data
    uint8_t empty = 0;
    uint32_t len = 0;
    if (!loader.Compress(&empty, &len, &empty, 0)) {
        g_results.RecordFail("EdgeCases_Empty", "Empty compression failed");
        return;
    }
    
    // Test 2: Single byte
    uint8_t single = 42;
    uint8_t compressed[32];
    uint8_t decompressed[32];
    uint32_t compLen = sizeof(compressed);
    uint32_t decompLen = sizeof(decompressed);
    
    if (!loader.Compress(compressed, &compLen, &single, 1)) {
        g_results.RecordFail("EdgeCases_Single", "Single byte compression failed");
        return;
    }
    
    if (!loader.Decompress(decompressed, &decompLen, compressed, compLen)) {
        g_results.RecordFail("EdgeCases_Single", "Single byte decompression failed");
        return;
    }
    
    if (decompLen != 1 || decompressed[0] != 42) {
        g_results.RecordFail("EdgeCases_Single", "Single byte mismatch");
        return;
    }
    
    // Test 3: All zeros (highly compressible)
    std::vector<uint8_t> zeros(1024, 0);
    std::vector<uint8_t> comp(1024);
    std::vector<uint8_t> decomp(1024);
    compLen = comp.size();
    decompLen = decomp.size();
    
    if (!loader.Compress(comp.data(), &compLen, zeros.data(), zeros.size())) {
        g_results.RecordFail("EdgeCases_Zeros", "Zeros compression failed");
        return;
    }
    
    if (!loader.Decompress(decomp.data(), &decompLen, comp.data(), compLen)) {
        g_results.RecordFail("EdgeCases_Zeros", "Zeros decompression failed");
        return;
    }
    
    if (decompLen != zeros.size() || memcmp(decomp.data(), zeros.data(), zeros.size()) != 0) {
        g_results.RecordFail("EdgeCases_Zeros", "Zeros mismatch");
        return;
    }
    
    std::cout << "  Empty data: OK" << std::endl;
    std::cout << "  Single byte: OK" << std::endl;
    std::cout << "  All zeros (1024 bytes -> " << compLen << " bytes): OK" << std::endl;
    
    g_results.RecordPass("EdgeCases");
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Compression Test Harness" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Run all tests
    Test_ZlibRuntimeLoader();
    Test_BasicCompression();
    Test_LargeDataCompression();
    Test_StreamingCompression();
    Test_Checksums();
    Test_EdgeCases();
    
    // Print summary
    g_results.PrintSummary();
    
    // Save results
    std::ofstream file("Compression_TestResults.txt");
    if (file.is_open()) {
        file << "RawrXD Compression Test Results\n";
        file << "===============================\n\n";
        file << "Total:  " << g_results.totalTests << "\n";
        file << "Passed: " << g_results.passedTests << "\n";
        file << "Failed: " << g_results.failedTests << "\n";
        file.close();
        std::cout << "\nResults saved to Compression_TestResults.txt" << std::endl;
    }
    
    return g_results.failedTests > 0 ? 1 : 0;
}
