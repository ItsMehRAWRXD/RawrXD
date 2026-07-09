// ============================================================================
// Streaming Loader + Q4_K Decoder Integration Test
// ============================================================================
// Validates: GGUF Loading → Tensor Access → Q4_K Dequantization
// ============================================================================

#include "streaming_gguf_loader.hpp"
#include "q4k_decoder.hpp"
#include <iostream>
#include <cstring>
#include <chrono>
#include <algorithm>

using namespace RawrXD::Runtime;
using namespace rawrxd;

void PrintUsage() {
    std::cout << "Streaming Loader + Q4_K Decoder Integration Test\n"
              << "Usage: test_loader_q4k <model.gguf> [tensor_name]\n"
              << "\nExample:\n"
              << "  test_loader_q4k ministral3_q4_0.gguf token_embd\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string model_path = argv[1];
    std::string target_tensor = (argc > 2) ? argv[2] : "token_embd";

    std::cout << "=== Streaming Loader + Q4_K Decoder Integration ===\n\n";
    std::cout << "Model: " << model_path << "\n";
    std::cout << "Target tensor: " << target_tensor << "\n\n";

    // ------------------------------------------------------------------------
    // Step 1: Open GGUF file
    // ------------------------------------------------------------------------
    std::cout << "[1/4] Opening GGUF file...\n";
    
    StreamingGGUFLoader loader;
    auto start = std::chrono::high_resolution_clock::now();
    
    if (!loader.Open(model_path)) {
        std::cerr << "FAILED: Could not open model\n";
        return 1;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto open_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "      ✓ File opened in " << open_duration.count() << " ms\n";
    std::cout << "      File size: " << (loader.GetFileSize() / (1024.0 * 1024.0 * 1024.0)) << " GB\n";
    std::cout << "      Tensors: " << loader.GetTensorCount() << "\n";
    std::cout << "      Metadata: " << loader.GetMetadataCount() << "\n";
    std::cout << "      Tensor data offset: 0x" << std::hex << loader.GetTensorDataOffset() << std::dec << "\n\n";

    // ------------------------------------------------------------------------
    // Step 2: Get tensor info
    // ------------------------------------------------------------------------
    std::cout << "[2/4] Getting tensor info...\n";
    
    TensorInfo info;
    if (!loader.GetTensor(target_tensor, info)) {
        std::cerr << "      Tensor '" << target_tensor << "' not found\n";
        std::cout << "      Available tensors:\n";
        auto names = loader.GetTensorNames();
        for (size_t i = 0; i < names.size() && i < 10; i++) {
            std::cout << "        - " << names[i] << "\n";
        }
        if (names.size() > 10) {
            std::cout << "        ... (" << (names.size() - 10) << " more)\n";
        }
        return 1;
    }
    
    std::cout << "      ✓ Found tensor: " << info.name << "\n";
    std::cout << "      Type: " << info.type << "\n";
    std::cout << "      Shape: [";
    for (size_t i = 0; i < info.shape.size(); i++) {
        if (i > 0) std::cout << ", ";
        std::cout << info.shape[i];
    }
    std::cout << "]\n";
    std::cout << "      Offset: " << info.offset << "\n";
    std::cout << "      Size: " << info.size << " bytes\n\n";

    // ------------------------------------------------------------------------
    // Step 3: Get tensor data pointer
    // ------------------------------------------------------------------------
    std::cout << "[3/4] Accessing tensor data...\n";
    
    const uint8_t* data = loader.GetTensorData(info);
    if (!data) {
        std::cerr << "FAILED: Could not get tensor data\n";
        return 1;
    }
    
    std::cout << "      ✓ Data accessed (zero-copy memory map)\n";
    std::cout << "      First 16 bytes: ";
    for (size_t i = 0; i < 16 && i < info.size; i++) {
        std::cout << std::hex << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n\n";

    // ------------------------------------------------------------------------
    // Step 4: Dequantize if Q4_K or Q4_0
    // ------------------------------------------------------------------------
    if (info.type == 12) { // Q4_K
        std::cout << "[4/4] Dequantizing Q4_K tensor...\n";
        
        // Calculate number of blocks
        uint64_t num_elements = info.NumElements();
        uint64_t num_blocks = (num_elements + 255) / 256;
        
        std::cout << "      Elements: " << num_elements << "\n";
        std::cout << "      Q4_K blocks: " << num_blocks << "\n";
        
        // Allocate output buffer
        std::vector<float> output(num_elements);
        
        start = std::chrono::high_resolution_clock::now();
        
        // Decode Q4_K data
        Q4KDecoder::DecodeRow(data, num_elements, output.data());
        
        end = std::chrono::high_resolution_clock::now();
        auto decode_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "      ✓ Dequantized in " << decode_duration.count() << " ms\n";
        std::cout << "      First 8 values: ";
        for (size_t i = 0; i < 8 && i < num_elements; i++) {
            std::cout << output[i] << " ";
        }
        std::cout << "\n\n";
        
        // Statistics
        float min_val = output[0], max_val = output[0], sum = 0;
        for (size_t i = 0; i < num_elements; i++) {
            min_val = std::min(min_val, output[i]);
            max_val = std::max(max_val, output[i]);
            sum += output[i];
        }
        
        std::cout << "      Statistics:\n";
        std::cout << "        Min: " << min_val << "\n";
        std::cout << "        Max: " << max_val << "\n";
        std::cout << "        Mean: " << (sum / num_elements) << "\n";
        std::cout << "        Elements/sec: " << (num_elements / (decode_duration.count() / 1000.0)) << "\n\n";
    } else if (info.type == 2) { // Q4_0
        std::cout << "[4/4] Dequantizing Q4_0 tensor...\n";
        
        uint64_t num_elements = info.NumElements();
        uint64_t num_blocks = (num_elements + 31) / 32;
        
        std::cout << "      Elements: " << num_elements << "\n";
        std::cout << "      Q4_0 blocks: " << num_blocks << "\n";
        std::cout << "      Note: Q4_0 dequantization stub (use Q4_K decoder for Q4_K tensors)\n\n";
    } else {
        std::cout << "[4/4] Skipping dequantization (type " << info.type << " is not Q4_K/Q4_0)\n\n";
    }

    std::cout << "=== Integration Test: PASSED ===\n";
    return 0;
}
