//=============================================================================
// RawrXD GGUF Loader Test - Verifies Production Implementation
//=============================================================================

#include "../include/gguf_loader_production.hpp"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace RawrXD;

void test_header_validation() {
    std::cout << "Test: Header Validation\n";
    
    // Create a minimal GGUF v3 file in memory
    uint8_t test_file[256];
    std::memset(test_file, 0, sizeof(test_file));
    
    // Write magic
    uint32_t magic = 0x46554747; // "GGUF"
    std::memcpy(test_file, &magic, 4);
    
    // Write version
    uint32_t version = 3;
    std::memcpy(test_file + 4, &version, 4);
    
    // Write tensor count
    uint64_t tensor_count = 0;
    std::memcpy(test_file + 8, &tensor_count, 8);
    
    // Write metadata count
    uint64_t metadata_count = 0;
    std::memcpy(test_file + 16, &metadata_count, 8);
    
    // Write to temp file
    FILE* f = fopen("test_minimal.gguf", "wb");
    assert(f);
    fwrite(test_file, 1, 24, f);
    fclose(f);
    
    // Test loading
    GGUFLoader loader;
    bool loaded = loader.Load("test_minimal.gguf");
    assert(loaded);
    assert(loader.IsLoaded());
    assert(loader.GetHeader().magic == 0x46554747);
    assert(loader.GetHeader().version == 3);
    
    std::cout << "  ✓ Header validation passed\n";
    
    // Cleanup
    loader.Unload();
    remove("test_minimal.gguf");
}

void test_memory_mapped_file() {
    std::cout << "Test: Memory-Mapped File\n";
    
    // Create test file
    const char* test_data = "Hello, GGUF!";
    FILE* f = fopen("test_mmap.bin", "wb");
    fwrite(test_data, 1, std::strlen(test_data), f);
    fclose(f);
    
    // Test memory mapping
    MemoryMappedFile mmap;
    bool opened = mmap.Open("test_mmap.bin");
    assert(opened);
    assert(mmap.IsOpen());
    assert(mmap.Size() == std::strlen(test_data));
    
    // Verify data
    const uint8_t* data = mmap.Data();
    assert(data != nullptr);
    assert(std::memcmp(data, test_data, std::strlen(test_data)) == 0);
    
    // Test ReadAt
    uint32_t val = mmap.ReadAt<uint32_t>(0);
    assert(val != 0); // Should read something
    
    mmap.Close();
    assert(!mmap.IsOpen());
    
    std::cout << "  ✓ Memory-mapped file passed\n";
    
    remove("test_mmap.bin");
}

void test_error_handling() {
    std::cout << "Test: Error Handling\n";
    
    GGUFLoader loader;
    
    std::string last_error;
    loader.SetErrorCallback([&](const std::string& msg) {
        last_error = msg;
    });
    
    // Try to load non-existent file
    bool result = loader.Load("nonexistent.gguf");
    assert(!result);
    assert(!last_error.empty());
    
    std::cout << "  ✓ Error handling passed\n";
}

void test_progress_callback() {
    std::cout << "Test: Progress Callback\n";
    
    // Create minimal valid GGUF
    uint8_t test_file[256];
    std::memset(test_file, 0, sizeof(test_file));
    uint32_t magic = 0x46554747;
    uint32_t version = 3;
    uint64_t tensor_count = 0;
    uint64_t metadata_count = 0;
    
    std::memcpy(test_file, &magic, 4);
    std::memcpy(test_file + 4, &version, 4);
    std::memcpy(test_file + 8, &tensor_count, 8);
    std::memcpy(test_file + 16, &metadata_count, 8);
    
    FILE* f = fopen("test_progress.gguf", "wb");
    fwrite(test_file, 1, 24, f);
    fclose(f);
    
    GGUFLoader loader;
    int last_progress = 0;
    loader.SetProgressCallback([&](int pct) {
        last_progress = pct;
    });
    
    loader.Load("test_progress.gguf");
    assert(last_progress == 100);
    
    std::cout << "  ✓ Progress callback passed\n";
    
    remove("test_progress.gguf");
}

int main() {
    std::cout << "==============================================\n";
    std::cout << "RawrXD GGUF Loader Production Tests\n";
    std::cout << "==============================================\n\n";
    
    try {
        test_memory_mapped_file();
        test_header_validation();
        test_error_handling();
        test_progress_callback();
        
        std::cout << "\n==============================================\n";
        std::cout << "All tests PASSED ✓\n";
        std::cout << "==============================================\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest FAILED: " << e.what() << "\n";
        return 1;
    }
}
