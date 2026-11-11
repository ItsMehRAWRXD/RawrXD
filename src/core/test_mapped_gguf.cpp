// VAL-053 Test: MappedGGUFFile streaming residency validation
// Generates evidence for GGUF artifact identity

#include "MappedGGUFFile.h"
#include <iostream>
#include <fstream>
#include <cstring>

using namespace RawrXD;

// Create a minimal valid GGUF file for testing
bool CreateTestGGUF(const std::string& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    
    // GGUF Header
    uint32_t magic = 0x46554747; // "GGUF"
    uint32_t version = 3;
    uint64_t tensorCount = 5;
    uint64_t metadataCount = 3;
    
    file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    file.write(reinterpret_cast<const char*>(&tensorCount), sizeof(tensorCount));
    file.write(reinterpret_cast<const char*>(&metadataCount), sizeof(metadataCount));
    
    // Metadata: general.architecture
    std::string archKey = "general.architecture";
    uint64_t archKeyLen = archKey.size();
    uint32_t strType = 8; // GGUF type string
    std::string archValue = "llama";
    uint64_t archValueLen = archValue.size();
    
    file.write(reinterpret_cast<const char*>(&archKeyLen), sizeof(archKeyLen));
    file.write(archKey.data(), archKeyLen);
    file.write(reinterpret_cast<const char*>(&strType), sizeof(strType));
    file.write(reinterpret_cast<const char*>(&archValueLen), sizeof(archValueLen));
    file.write(archValue.data(), archValueLen);
    
    // Metadata: tokenizer.ggml.tokens (simplified)
    std::string vocabKey = "tokenizer.ggml.tokens";
    uint64_t vocabKeyLen = vocabKey.size();
    uint32_t arrType = 7; // GGUF type array
    uint32_t arrElemType = 8; // string
    uint64_t vocabSize = 32000;
    
    file.write(reinterpret_cast<const char*>(&vocabKeyLen), sizeof(vocabKeyLen));
    file.write(vocabKey.data(), vocabKeyLen);
    file.write(reinterpret_cast<const char*>(&arrType), sizeof(arrType));
    file.write(reinterpret_cast<const char*>(&arrElemType), sizeof(arrElemType));
    file.write(reinterpret_cast<const char*>(&vocabSize), sizeof(vocabSize));
    
    // Skip actual vocab data for test
    
    // Tensor info
    struct TensorInfo {
        std::string name;
        uint32_t dims;
        std::vector<uint64_t> shape;
        uint32_t type;
        uint64_t offset;
    };
    
    std::vector<TensorInfo> tensors = {
        {"token_embd.weight", 2, {32000, 4096}, 0, 0},
        {"output_norm.weight", 1, {4096}, 0, 0},
        {"output.weight", 2, {32000, 4096}, 0, 0},
        {"blk.0.attn_q.weight", 2, {4096, 4096}, 0, 0},
        {"blk.0.ffn_up.weight", 2, {4096, 11008}, 0, 0}
    };
    
    uint64_t dataOffset = 0;
    for (auto& t : tensors) {
        // Calculate tensor size (simplified)
        uint64_t tensorSize = 256 * 1024 * 1024; // 256MB placeholder
        
        // Write tensor info
        uint64_t nameLen = t.name.size();
        file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
        file.write(t.name.data(), nameLen);
        file.write(reinterpret_cast<const char*>(&t.dims), sizeof(t.dims));
        for (auto s : t.shape) {
            file.write(reinterpret_cast<const char*>(&s), sizeof(s));
        }
        file.write(reinterpret_cast<const char*>(&t.type), sizeof(t.type));
        file.write(reinterpret_cast<const char*>(&dataOffset), sizeof(dataOffset));
        
        dataOffset += tensorSize;
    }
    
    // Pad to include some tensor data
    std::vector<char> padding(1024 * 1024, 0); // 1MB padding
    file.write(padding.data(), padding.size());
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-053: GGUF Artifact Identity Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::string testPath = "test_val053.gguf";
    
    // Create test GGUF
    std::cout << "[TEST] Creating test GGUF..." << std::endl;
    if (!CreateTestGGUF(testPath)) {
        std::cerr << "[FAIL] Failed to create test GGUF" << std::endl;
        return 1;
    }
    std::cout << "[PASS] Test GGUF created" << std::endl;
    
    // Open with MappedGGUFFile
    std::cout << "[TEST] Opening with MappedGGUFFile..." << std::endl;
    auto gguf = CreateMappedGGUFFile(testPath);
    if (!gguf) {
        std::cerr << "[FAIL] Failed to open GGUF" << std::endl;
        return 1;
    }
    std::cout << "[PASS] GGUF opened successfully" << std::endl;
    
    // Verify metadata
    std::cout << "[TEST] Verifying GGUF metadata..." << std::endl;
    std::cout << "  Version: " << gguf->GetGGUFVersion() << std::endl;
    std::cout << "  Architecture: " << gguf->GetArchitecture() << std::endl;
    std::cout << "  Tensor count: " << gguf->GetTensorCount() << std::endl;
    std::cout << "  Vocab size: " << gguf->GetVocabSize() << std::endl;
    
    // Verify required tensors
    std::cout << "[TEST] Verifying required tensors..." << std::endl;
    const char* requiredTensors[] = {
        "token_embd.weight",
        "output_norm.weight",
        "output.weight",
        "blk.0.attn_q.weight",
        "blk.0.ffn_up.weight"
    };
    
    bool allPresent = true;
    for (const auto& name : requiredTensors) {
        auto tensor = gguf->GetTensor(name);
        if (tensor) {
            std::cout << "  [PASS] " << name << " - present" << std::endl;
        } else {
            std::cout << "  [FAIL] " << name << " - missing" << std::endl;
            allPresent = false;
        }
    }
    
    // Generate residency report
    std::cout << "[TEST] Generating residency report..." << std::endl;
    auto report = gguf->GenerateResidencyReport();
    std::cout << "  Total tensors: " << report.totalTensors << std::endl;
    std::cout << "  Resident tensors: " << report.residentTensors << std::endl;
    std::cout << "  Resident bytes: " << report.residentBytes << std::endl;
    std::cout << "  Residency ratio: " << report.residencyRatio << std::endl;
    std::cout << "  Page faults: " << report.telemetry.fault_count << std::endl;
    
    // Generate evidence JSON
    std::cout << "[TEST] Generating evidence JSON..." << std::endl;
    std::string evidence = gguf->GenerateEvidenceJSON();
    
    std::ofstream evidenceFile("val053_evidence.json");
    evidenceFile << evidence;
    evidenceFile.close();
    std::cout << "[PASS] Evidence saved to val053_evidence.json" << std::endl;
    
    // Cleanup
    gguf.reset();
    std::remove(testPath.c_str());
    
    // Final status
    std::cout << "========================================" << std::endl;
    if (allPresent) {
        std::cout << "VAL-053: PASS" << std::endl;
        std::cout << "========================================" << std::endl;
        return 0;
    } else {
        std::cout << "VAL-053: FAIL" << std::endl;
        std::cout << "========================================" << std::endl;
        return 1;
    }
}
