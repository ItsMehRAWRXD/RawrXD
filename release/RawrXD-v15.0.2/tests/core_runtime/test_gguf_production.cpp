// =============================================================================
// RawrXD-CoreRuntime: Production GGUF Loader Test Suite
// =============================================================================
// Validates zero-dependency model loading with memory-mapped streaming
// =============================================================================

#include "core_runtime/gguf_loader_production.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <chrono>

using namespace RawrXD::Core;

// Simple test framework
struct TestFramework {
    int passed = 0;
    int failed = 0;
    
    void Test(const char* name, bool result) {
        if (result) {
            printf("  [PASS] %s\n", name);
            passed++;
        } else {
            printf("  [FAIL] %s\n", name);
            failed++;
        }
    }
    
    void Summary() {
        printf("\n========================================\n");
        printf("Test Results: %d passed, %d failed\n", passed, failed);
        printf("========================================\n");
    }
};

// Create a minimal test GGUF file
bool CreateTestGGUF(const char* path) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    
    // GGUF Header
    uint32_t magic = 0x46554747; // 'GGUF'
    uint32_t version = 3;
    uint64_t tensorCount = 2;
    uint64_t metadataCount = 5;
    
    fwrite(&magic, 4, 1, f);
    fwrite(&version, 4, 1, f);
    fwrite(&tensorCount, 8, 1, f);
    fwrite(&metadataCount, 8, 1, f);
    
    // Metadata entries
    // 1. general.architecture
    {
        const char* key = "general.architecture";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, 8, 1, f);
        fwrite(key, 1, keyLen, f);
        
        uint32_t type = 11; // STRING
        fwrite(&type, 4, 1, f);
        
        const char* val = "llama";
        uint64_t valLen = strlen(val);
        fwrite(&valLen, 8, 1, f);
        fwrite(val, 1, valLen, f);
    }
    
    // 2. llama.vocab_size
    {
        const char* key = "llama.vocab_size";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, 8, 1, f);
        fwrite(key, 1, keyLen, f);
        
        uint32_t type = 4; // UINT32
        fwrite(&type, 4, 1, f);
        
        uint32_t val = 32000;
        fwrite(&val, 4, 1, f);
    }
    
    // 3. llama.hidden_size
    {
        const char* key = "llama.hidden_size";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, 8, 1, f);
        fwrite(key, 1, keyLen, f);
        
        uint32_t type = 4; // UINT32
        fwrite(&type, 4, 1, f);
        
        uint32_t val = 4096;
        fwrite(&val, 4, 1, f);
    }
    
    // 4. llama.block_count
    {
        const char* key = "llama.block_count";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, 8, 1, f);
        fwrite(key, 1, keyLen, f);
        
        uint32_t type = 4; // UINT32
        fwrite(&type, 4, 1, f);
        
        uint32_t val = 32;
        fwrite(&val, 4, 1, f);
    }
    
    // 5. tokenizer.ggml.bos_token_id
    {
        const char* key = "tokenizer.ggml.bos_token_id";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, 8, 1, f);
        fwrite(key, 1, keyLen, f);
        
        uint32_t type = 4; // UINT32
        fwrite(&type, 4, 1, f);
        
        uint32_t val = 1;
        fwrite(&val, 4, 1, f);
    }
    
    // Tensor info
    // Tensor 1: token_embd.weight
    {
        const char* name = "token_embd.weight";
        uint64_t nameLen = strlen(name);
        fwrite(&nameLen, 8, 1, f);
        fwrite(name, 1, nameLen, f);
        
        uint32_t nDims = 2;
        fwrite(&nDims, 4, 1, f);
        
        uint64_t dim0 = 32000;
        uint64_t dim1 = 4096;
        fwrite(&dim0, 8, 1, f);
        fwrite(&dim1, 8, 1, f);
        
        uint32_t type = 0; // F32
        fwrite(&type, 4, 1, f);
        
        uint64_t offset = 0;
        fwrite(&offset, 8, 1, f);
    }
    
    // Tensor 2: output_norm.weight
    {
        const char* name = "output_norm.weight";
        uint64_t nameLen = strlen(name);
        fwrite(&nameLen, 8, 1, f);
        fwrite(name, 1, nameLen, f);
        
        uint32_t nDims = 1;
        fwrite(&nDims, 4, 1, f);
        
        uint64_t dim0 = 4096;
        fwrite(&dim0, 8, 1, f);
        
        uint32_t type = 0; // F32
        fwrite(&type, 4, 1, f);
        
        uint64_t offset = 32000ULL * 4096 * 4; // After first tensor
        fwrite(&offset, 8, 1, f);
    }
    
    // Pad to alignment
    long pos = ftell(f);
    while (pos % 32 != 0) {
        uint8_t zero = 0;
        fwrite(&zero, 1, 1, f);
        pos++;
    }
    
    // Tensor data (dummy)
    std::vector<float> dummyData(32000 * 4096 + 4096, 0.0f);
    fwrite(dummyData.data(), sizeof(float), dummyData.size(), f);
    
    fclose(f);
    return true;
}

int main() {
    printf("============================================================\n");
    printf("RawrXD-CoreRuntime: Production GGUF Loader Test Suite\n");
    printf("============================================================\n\n");
    
    TestFramework framework;
    
    // Create test file
    const char* testPath = "test_model.gguf";
    printf("Creating test GGUF file...\n");
    if (!CreateTestGGUF(testPath)) {
        printf("Failed to create test file\n");
        return 1;
    }
    printf("Test file created: %s\n\n", testPath);
    
    // Test 1: Basic load
    printf("Test 1: Basic GGUF Load\n");
    {
        GGUFLoaderProduction loader;
        bool loaded = loader.Load(testPath, true);
        framework.Test("Load succeeds", loaded);
        framework.Test("IsLoaded returns true", loader.IsLoaded());
        framework.Test("Path matches", strcmp(loader.GetPath(), testPath) == 0);
        framework.Test("Version is 3", loader.GetVersion() == 3);
    }
    
    // Test 2: Metadata access
    printf("\nTest 2: Metadata Access\n");
    {
        GGUFLoaderProduction loader;
        loader.Load(testPath, true);
        
        framework.Test("Has general.architecture", 
            loader.HasMetadata("general.architecture"));
        framework.Test("Has llama.vocab_size", 
            loader.HasMetadata("llama.vocab_size"));
        framework.Test("Does not have fake.key", 
            !loader.HasMetadata("fake.key"));
        
        auto* arch = loader.GetMetadata("general.architecture");
        framework.Test("Architecture is 'llama'", 
            arch && strcmp(arch->AsString(), "llama") == 0);
        
        auto* vocab = loader.GetMetadata("llama.vocab_size");
        framework.Test("Vocab size is 32000", 
            vocab && vocab->AsUInt32() == 32000);
        
        framework.Test("Metadata count is 5", 
            loader.GetMetadataCount() == 5);
    }
    
    // Test 3: Tensor access
    printf("\nTest 3: Tensor Access\n");
    {
        GGUFLoaderProduction loader;
        loader.Load(testPath, true);
        
        framework.Test("Tensor count is 2", 
            loader.GetTensorCount() == 2);
        
        auto* tensor1 = loader.GetTensor("token_embd.weight");
        framework.Test("token_embd.weight exists", tensor1 != nullptr);
        if (tensor1) {
            framework.Test("token_embd.weight has 2 dims", 
                tensor1->dimensions.size() == 2);
            framework.Test("token_embd.weight dim[0] is 32000", 
                tensor1->dimensions[0] == 32000);
            framework.Test("token_embd.weight dim[1] is 4096", 
                tensor1->dimensions[1] == 4096);
        }
        
        auto* tensor2 = loader.GetTensor("output_norm.weight");
        framework.Test("output_norm.weight exists", tensor2 != nullptr);
        if (tensor2) {
            framework.Test("output_norm.weight has 1 dim", 
                tensor2->dimensions.size() == 1);
            framework.Test("output_norm.weight dim[0] is 4096", 
                tensor2->dimensions[0] == 4096);
        }
        
        auto* fake = loader.GetTensor("fake.tensor");
        framework.Test("fake.tensor does not exist", fake == nullptr);
    }
    
    // Test 4: Architecture extraction
    printf("\nTest 4: Architecture Extraction\n");
    {
        GGUFLoaderProduction loader;
        loader.Load(testPath, true);
        
        const auto& arch = loader.GetArchitecture();
        framework.Test("Architecture name is 'llama'", 
            arch.name == "llama");
        framework.Test("Vocab size extracted", 
            arch.vocabSize == 32000);
        framework.Test("Hidden size extracted", 
            arch.hiddenSize == 4096);
        framework.Test("Num layers extracted", 
            arch.numLayers == 32);
        framework.Test("BOS token extracted", 
            arch.bosToken == 1);
    }
    
    // Test 5: Memory-mapped access
    printf("\nTest 5: Memory-Mapped Access\n");
    {
        GGUFLoaderProduction loader;
        loader.Load(testPath, true);
        
        framework.Test("File size > 0", loader.GetTotalFileSize() > 0);
        framework.Test("Mapped size > 0", loader.GetMappedMemorySize() > 0);
        framework.Test("Mapped size equals file size", 
            loader.GetMappedMemorySize() == loader.GetTotalFileSize());
        
        auto* tensor = loader.GetTensor("token_embd.weight");
        if (tensor) {
            const void* data = loader.ReadTensorData(*tensor);
            framework.Test("Tensor data is accessible", data != nullptr);
        }
    }
    
    // Test 6: Unload and reload
    printf("\nTest 6: Unload and Reload\n");
    {
        GGUFLoaderProduction loader;
        loader.Load(testPath, true);
        framework.Test("Initially loaded", loader.IsLoaded());
        
        loader.Unload();
        framework.Test("Unloaded", !loader.IsLoaded());
        
        bool reloaded = loader.Load(testPath, true);
        framework.Test("Reloaded", reloaded && loader.IsLoaded());
    }
    
    // Test 7: Progress callback
    printf("\nTest 7: Progress Callback\n");
    {
        int progressCalls = 0;
        size_t lastCurrent = 0;
        size_t lastTotal = 0;
        
        GGUFLoaderProduction loader;
        loader.SetProgressCallback([&](size_t current, size_t total, const char* stage) {
            progressCalls++;
            lastCurrent = current;
            lastTotal = total;
        });
        
        loader.Load(testPath, true);
        framework.Test("Progress callback was called", progressCalls > 0);
        framework.Test("Progress reached 100", lastCurrent == 100);
    }
    
    // Test 8: C API
    printf("\nTest 8: C API\n");
    {
        GGUFLoaderHandle* handle = GGUFLoader_Create();
        framework.Test("C API: Handle created", handle != nullptr);
        
        int loaded = GGUFLoader_Load(handle, testPath);
        framework.Test("C API: Load succeeded", loaded == 1);
        
        int isLoaded = GGUFLoader_IsLoaded(handle);
        framework.Test("C API: IsLoaded returns true", isLoaded == 1);
        
        uint32_t tensorCount = GGUFLoader_GetTensorCount(handle);
        framework.Test("C API: Tensor count is 2", tensorCount == 2);
        
        char nameBuf[256];
        uint32_t dims[4];
        uint64_t size;
        int infoResult = GGUFLoader_GetTensorInfo(handle, 0, nameBuf, sizeof(nameBuf), 
                                                   dims, 4, &size);
        framework.Test("C API: GetTensorInfo succeeded", infoResult == 1);
        framework.Test("C API: First tensor name is token_embd.weight",
            strcmp(nameBuf, "token_embd.weight") == 0);
        
        const void* data = GGUFLoader_ReadTensorData(handle, "token_embd.weight");
        framework.Test("C API: ReadTensorData returns data", data != nullptr);
        
        GGUFLoader_Unload(handle);
        GGUFLoader_Destroy(handle);
    }
    
    // Test 9: Performance (basic timing)
    printf("\nTest 9: Performance\n");
    {
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < 10; ++i) {
            GGUFLoaderProduction loader;
            loader.Load(testPath, true);
            loader.Unload();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        printf("  10 load/unload cycles: %lld ms\n", duration.count());
        framework.Test("Performance: 10 cycles < 1000ms", duration.count() < 1000);
    }
    
    // Cleanup
    remove(testPath);
    printf("\nCleaned up test file\n");
    
    // Summary
    framework.Summary();
    
    return framework.failed == 0;
}

// Entry point for CoreRuntime test suite
bool test_gguf_production() {
    return TestGGUFProductionLoader();
}
