#include "gguf_loader.h"
#include "gguf_types.h"
#include <iostream>
#include <cstring>

using namespace RawrXD::Model;

// Create a minimal test GGUF file
bool CreateTestGGUF(const char* path) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    
    // Header
    GGUFHeader header;
    header.magic = GGUF_MAGIC;
    header.version = 3;
    header.tensorCount = 2;
    header.metadataCount = 3;
    
    fwrite(&header.magic, sizeof(header.magic), 1, f);
    fwrite(&header.version, sizeof(header.version), 1, f);
    fwrite(&header.tensorCount, sizeof(header.tensorCount), 1, f);
    fwrite(&header.metadataCount, sizeof(header.metadataCount), 1, f);
    
    // Metadata: general.architecture
    {
        const char* key = "general.architecture";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, sizeof(keyLen), 1, f);
        fwrite(key, keyLen, 1, f);
        
        uint32_t type = static_cast<uint32_t>(MetadataType::String);
        fwrite(&type, sizeof(type), 1, f);
        
        const char* val = "test";
        uint64_t valLen = strlen(val);
        fwrite(&valLen, sizeof(valLen), 1, f);
        fwrite(val, valLen, 1, f);
    }
    
    // Metadata: test.vocab_size
    {
        const char* key = "test.vocab_size";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, sizeof(keyLen), 1, f);
        fwrite(key, keyLen, 1, f);
        
        uint32_t type = static_cast<uint32_t>(MetadataType::Uint32);
        fwrite(&type, sizeof(type), 1, f);
        
        uint32_t val = 32000;
        fwrite(&val, sizeof(val), 1, f);
    }
    
    // Metadata: test.block_count
    {
        const char* key = "test.block_count";
        uint64_t keyLen = strlen(key);
        fwrite(&keyLen, sizeof(keyLen), 1, f);
        fwrite(key, keyLen, 1, f);
        
        uint32_t type = static_cast<uint32_t>(MetadataType::Uint32);
        fwrite(&type, sizeof(type), 1, f);
        
        uint32_t val = 32;
        fwrite(&val, sizeof(val), 1, f);
    }
    
    // Tensor info: token_embd.weight
    {
        const char* name = "token_embd.weight";
        uint64_t nameLen = strlen(name);
        fwrite(&nameLen, sizeof(nameLen), 1, f);
        fwrite(name, nameLen, 1, f);
        
        uint32_t nDims = 2;
        fwrite(&nDims, sizeof(nDims), 1, f);
        
        uint64_t dim0 = 32000;
        uint64_t dim1 = 4096;
        fwrite(&dim0, sizeof(dim0), 1, f);
        fwrite(&dim1, sizeof(dim1), 1, f);
        
        uint32_t type = static_cast<uint32_t>(GGMLType::F32);
        fwrite(&type, sizeof(type), 1, f);
        
        uint64_t offset = 0;
        fwrite(&offset, sizeof(offset), 1, f);
    }
    
    // Tensor info: output.weight
    {
        const char* name = "output.weight";
        uint64_t nameLen = strlen(name);
        fwrite(&nameLen, sizeof(nameLen), 1, f);
        fwrite(name, nameLen, 1, f);
        
        uint32_t nDims = 2;
        fwrite(&nDims, sizeof(nDims), 1, f);
        
        uint64_t dim0 = 32000;
        uint64_t dim1 = 4096;
        fwrite(&dim0, sizeof(dim0), 1, f);
        fwrite(&dim1, sizeof(dim1), 1, f);
        
        uint32_t type = static_cast<uint32_t>(GGMLType::F32);
        fwrite(&type, sizeof(type), 1, f);
        
        uint64_t offset = 32000ULL * 4096 * 4; // After first tensor
        fwrite(&offset, sizeof(offset), 1, f);
    }
    
    // Tensor data (dummy)
    size_t tensorDataSize = 32000ULL * 4096 * 4 * 2;
    std::vector<uint8_t> dummy(tensorDataSize, 0);
    fwrite(dummy.data(), dummy.size(), 1, f);
    
    fclose(f);
    return true;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Model Loader Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    const char* testFile = "test_model.gguf";
    
    // Create test file
    std::cout << "Creating test GGUF file..." << std::endl;
    if (!CreateTestGGUF(testFile)) {
        std::cerr << "Failed to create test file" << std::endl;
        return 1;
    }
    std::cout << "  ✓ Test file created" << std::endl;
    
    // Test GGUFLoader
    GGUFLoader loader;
    
    std::cout << "\nOpening GGUF file..." << std::endl;
    if (!loader.Open(testFile)) {
        std::cerr << "Failed to open: " << loader.GetLastError() << std::endl;
        return 1;
    }
    std::cout << "  ✓ File opened successfully" << std::endl;
    
    // Check header
    auto header = loader.GetHeader();
    std::cout << "\nHeader Info:" << std::endl;
    std::cout << "  Magic: 0x" << std::hex << header.magic << std::dec << std::endl;
    std::cout << "  Version: " << header.version << std::endl;
    std::cout << "  Tensor Count: " << header.tensorCount << std::endl;
    std::cout << "  Metadata Count: " << header.metadataCount << std::endl;
    
    if (header.magic != GGUF_MAGIC) {
        std::cerr << "ERROR: Invalid magic number" << std::endl;
        return 1;
    }
    std::cout << "  ✓ Magic number valid" << std::endl;
    
    // Check metadata
    auto metadata = loader.GetMetadata();
    std::cout << "\nMetadata:" << std::endl;
    std::cout << "  Architecture: " << metadata.GetString("general.architecture", "NOT FOUND") << std::endl;
    std::cout << "  Vocab Size: " << metadata.GetUint32("test.vocab_size", 0) << std::endl;
    std::cout << "  Block Count: " << metadata.GetUint32("test.block_count", 0) << std::endl;
    
    if (metadata.GetString("general.architecture", "") != "test") {
        std::cerr << "ERROR: Architecture mismatch" << std::endl;
        return 1;
    }
    std::cout << "  ✓ Metadata parsed correctly" << std::endl;
    
    // Check tensors
    auto tensors = loader.GetTensorInfo();
    std::cout << "\nTensors (" << tensors.size() << "):" << std::endl;
    for (const auto& t : tensors) {
        std::cout << "  " << t.name << ":" << std::endl;
        std::cout << "    Shape: [";
        for (size_t i = 0; i < t.shape.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << t.shape[i];
        }
        std::cout << "]" << std::endl;
        std::cout << "    Type: " << GGUFLoader::GGMLTypeToString(t.type) << std::endl;
        std::cout << "    Size: " << t.size << " bytes" << std::endl;
    }
    
    if (tensors.size() != 2) {
        std::cerr << "ERROR: Expected 2 tensors, got " << tensors.size() << std::endl;
        return 1;
    }
    std::cout << "  ✓ Tensor index built correctly" << std::endl;
    
    // Test tensor lookup
    TensorInfo info;
    if (!loader.FindTensor("token_embd.weight", info)) {
        std::cerr << "ERROR: Could not find token_embd.weight" << std::endl;
        return 1;
    }
    std::cout << "  ✓ Tensor lookup working" << std::endl;
    
    // Test file size
    auto fileSize = loader.GetFileSize();
    std::cout << "\nFile Size: " << fileSize << " bytes" << std::endl;
    if (fileSize == 0) {
        std::cerr << "ERROR: File size is 0" << std::endl;
        return 1;
    }
    std::cout << "  ✓ File size valid" << std::endl;
    
    // Cleanup
    loader.Close();
    std::remove(testFile);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "All tests PASSED!" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
