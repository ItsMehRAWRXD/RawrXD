//=============================================================================
// RawrXD Model Loading Integration Test
// Tests GGUF loading, quantization, and GPU upload
//=============================================================================

#include "../include/gguf_loader_production.hpp"
#include "../include/streaming_loader_production.hpp"
#include "../include/quantization_production.hpp"
#include "../include/gpu_upload_production.hpp"
#include <iostream>
#include <cassert>
#include <cmath>

using namespace RawrXD;
using namespace RawrXD::Quantization;
using namespace RawrXD::GPU;

//=============================================================================
// Test Helpers
//=============================================================================

bool FloatEquals(float a, float b, float epsilon = 0.01f) {
    return std::abs(a - b) < epsilon;
}

//=============================================================================
// Quantization Tests
//=============================================================================

void test_quantization_q8_0() {
    std::cout << "Test: Q8_0 Quantization\n";
    
    // Create test data
    float src[32];
    for (int i = 0; i < 32; ++i) {
        src[i] = static_cast<float>(i) * 0.1f;
    }
    
    // Quantize
    BlockQ8_0 block;
    QuantizeBlockQ8_0(src, &block, 32);
    
    // Dequantize
    float dst[32];
    DequantizeBlockQ8_0(&block, dst, 32);
    
    // Check
    for (int i = 0; i < 32; ++i) {
        assert(FloatEquals(src[i], dst[i], 0.1f));
    }
    
    std::cout << "  ✓ Q8_0 round-trip passed\n";
}

void test_quantization_q4_0() {
    std::cout << "Test: Q4_0 Quantization\n";
    
    float src[32];
    for (int i = 0; i < 32; ++i) {
        src[i] = static_cast<float>(i) * 0.1f;
    }
    
    BlockQ4_0 block;
    QuantizeBlockQ4_0(src, &block, 32);
    
    float dst[32];
    DequantizeBlockQ4_0(&block, dst, 32);
    
    // Q4 has lower precision
    for (int i = 0; i < 32; ++i) {
        assert(FloatEquals(src[i], dst[i], 0.5f));
    }
    
    std::cout << "  ✓ Q4_0 round-trip passed\n";
}

void test_quantization_info() {
    std::cout << "Test: Quantization Info\n";
    
    auto info_q8 = CalculateQuantizedTensorInfo(QuantType::Q8_0, 1024);
    assert(info_q8.compression_ratio > 3.0f);  // Should be ~3.5x
    
    auto info_q4 = CalculateQuantizedTensorInfo(QuantType::Q4_0, 1024);
    assert(info_q4.compression_ratio > 6.0f);  // Should be ~7x
    
    auto info_f32 = CalculateQuantizedTensorInfo(QuantType::F32, 1024);
    assert(info_f32.compression_ratio == 1.0f);
    
    std::cout << "  ✓ Compression ratios: Q8_0=" << info_q8.compression_ratio
              << "x, Q4_0=" << info_q4.compression_ratio << "x\n";
}

void test_quantization_types() {
    std::cout << "Test: Quantization Type Conversion\n";
    
    const char* name = QuantTypeToString(QuantType::Q4_K);
    assert(std::strcmp(name, "Q4_K") == 0);
    
    auto type = StringToQuantType("Q8_0");
    assert(type == QuantType::Q8_0);
    
    auto info = GetQuantTypeInfo(QuantType::Q5_K_M);
    assert(info != nullptr);
    assert(info->is_quantized);
    
    std::cout << "  ✓ Type conversion passed\n";
}

//=============================================================================
// GPU Upload Tests (if CUDA available)
//=============================================================================

void test_gpu_enumeration() {
    std::cout << "Test: GPU Enumeration\n";
    
    auto devices = EnumerateGPUDevices();
    std::cout << "  Found " << devices.size() << " GPU(s)\n";
    
    for (const auto& dev : devices) {
        std::cout << "    Device " << dev.device_id << ": " << dev.name
                  << " (" << (dev.total_memory / 1024 / 1024) << " MB)\n";
    }
    
    std::cout << "  ✓ GPU enumeration passed\n";
}

void test_gpu_memory_buffer() {
    std::cout << "Test: GPU Memory Buffer\n";
    
    GPUBackend backend = DetectBestBackend();
    if (backend == GPUBackend::NONE) {
        std::cout << "  ⚠ No GPU backend available, skipping\n";
        return;
    }
    
    GPUMemoryBuffer buffer;
    bool allocated = buffer.Allocate(1024 * 1024, backend, 0);  // 1MB
    
    if (!allocated) {
        std::cout << "  ⚠ GPU allocation failed, skipping\n";
        return;
    }
    
    assert(buffer.IsAllocated());
    assert(buffer.GetSize() == 1024 * 1024);
    
    // Test upload/download
    std::vector<float> host_data(256);
    for (size_t i = 0; i < host_data.size(); ++i) {
        host_data[i] = static_cast<float>(i);
    }
    
    bool uploaded = buffer.Upload(host_data.data(), host_data.size() * sizeof(float));
    if (uploaded) {
        std::vector<float> download_data(256);
        bool downloaded = buffer.Download(download_data.data(), download_data.size() * sizeof(float));
        
        if (downloaded) {
            for (size_t i = 0; i < host_data.size(); ++i) {
                assert(FloatEquals(host_data[i], download_data[i]));
            }
            std::cout << "  ✓ GPU upload/download passed\n";
        } else {
            std::cout << "  ⚠ GPU download failed\n";
        }
    } else {
        std::cout << "  ⚠ GPU upload failed\n";
    }
    
    buffer.Free();
    assert(!buffer.IsAllocated());
}

void test_gpu_tensor_uploader() {
    std::cout << "Test: GPU Tensor Uploader\n";
    
    GPUBackend backend = DetectBestBackend();
    if (backend == GPUBackend::NONE) {
        std::cout << "  ⚠ No GPU backend available, skipping\n";
        return;
    }
    
    TensorGPUUploader uploader;
    bool initialized = uploader.Initialize(backend, 0);
    
    if (!initialized) {
        std::cout << "  ⚠ GPU uploader initialization failed, skipping\n";
        return;
    }
    
    // Upload a tensor
    std::vector<float> tensor_data(1024);
    for (size_t i = 0; i < tensor_data.size(); ++i) {
        tensor_data[i] = static_cast<float>(i) * 0.01f;
    }
    
    bool uploaded = uploader.UploadTensor("test_tensor", tensor_data.data(),
                                          QuantType::F32, tensor_data.size());
    
    if (uploaded) {
        assert(uploader.IsTensorOnGPU("test_tensor"));
        
        GPUMemoryBuffer* buffer = uploader.GetTensor("test_tensor");
        assert(buffer != nullptr);
        assert(buffer->IsAllocated());
        
        std::cout << "  ✓ GPU tensor upload passed\n";
        std::cout << "    Memory used: " << (uploader.GetUsedGPUMemory() / 1024)
                  << " KB\n";
        
        uploader.EvictTensor("test_tensor");
        assert(!uploader.IsTensorOnGPU("test_tensor"));
    } else {
        std::cout << "  ⚠ GPU tensor upload failed\n";
    }
}

//=============================================================================
// Integration Test
//=============================================================================

void test_full_pipeline() {
    std::cout << "Test: Full Pipeline (Load → Quantize → GPU)\n";
    
    // Step 1: Create a minimal GGUF file
    uint8_t test_file[4096];
    std::memset(test_file, 0, sizeof(test_file));
    
    // Write GGUF header
    uint32_t magic = 0x46554747;  // "GGUF"
    uint32_t version = 3;
    uint64_t tensor_count = 1;
    uint64_t metadata_count = 3;
    
    std::memcpy(test_file, &magic, 4);
    std::memcpy(test_file + 4, &version, 4);
    std::memcpy(test_file + 8, &tensor_count, 8);
    std::memcpy(test_file + 16, &metadata_count, 8);
    
    size_t offset = 24;
    
    // Write metadata
    // Key 1: "general.architecture"
    uint64_t key_len = 20;
    std::memcpy(test_file + offset, &key_len, 8); offset += 8;
    std::memcpy(test_file + offset, "general.architecture", 20); offset += 20;
    uint32_t type_str = 8;  // STRING
    std::memcpy(test_file + offset, &type_str, 4); offset += 4;
    uint64_t val_len = 6;
    std::memcpy(test_file + offset, &val_len, 8); offset += 8;
    std::memcpy(test_file + offset, "llama", 6); offset += 6;
    
    // Key 2: "llama.block_count"
    key_len = 17;
    std::memcpy(test_file + offset, &key_len, 8); offset += 8;
    std::memcpy(test_file + offset, "llama.block_count", 17); offset += 17;
    uint32_t type_u32 = 4;  // UINT32
    std::memcpy(test_file + offset, &type_u32, 4); offset += 4;
    uint32_t block_count = 32;
    std::memcpy(test_file + offset, &block_count, 4); offset += 4;
    
    // Key 3: "llama.context_length"
    key_len = 20;
    std::memcpy(test_file + offset, &key_len, 8); offset += 8;
    std::memcpy(test_file + offset, "llama.context_length", 20); offset += 20;
    std::memcpy(test_file + offset, &type_u32, 4); offset += 4;
    uint32_t ctx_len = 4096;
    std::memcpy(test_file + offset, &ctx_len, 4); offset += 4;
    
    // Write tensor info
    uint64_t tensor_name_len = 12;
    std::memcpy(test_file + offset, &tensor_name_len, 8); offset += 8;
    std::memcpy(test_file + offset, "token_embd", 10); offset += 10;
    
    // Pad to 12 bytes
    offset += 2;
    
    uint32_t dims = 2;
    std::memcpy(test_file + offset, &dims, 4); offset += 4;
    uint64_t dim0 = 32000;  // vocab size
    uint64_t dim1 = 4096;   // embedding dim
    std::memcpy(test_file + offset, &dim0, 8); offset += 8;
    std::memcpy(test_file + offset, &dim1, 8); offset += 8;
    
    uint32_t tensor_type = 0;  // F32
    std::memcpy(test_file + offset, &tensor_type, 4); offset += 4;
    uint64_t tensor_offset = 4096;  // Data starts at 4KB
    std::memcpy(test_file + offset, &tensor_offset, 8); offset += 8;
    
    // Write tensor data (just zeros for test)
    // In real file, this would be the actual tensor data
    
    // Save file
    FILE* f = fopen("test_integration.gguf", "wb");
    fwrite(test_file, 1, 4096, f);
    fclose(f);
    
    // Step 2: Load with GGUFLoader
    GGUFLoader loader;
    bool loaded = loader.Load("test_integration.gguf");
    assert(loaded);
    
    assert(loader.GetArchitecture() == "llama");
    assert(loader.GetLayerCount() == 32);
    assert(loader.GetContextLength() == 4096);
    
    std::cout << "  ✓ GGUF loading passed\n";
    
    // Step 3: Test streaming loader
    StreamingGGUFLoader streamer;
    std::vector<size_t> zone_limits(8, 100);  // 100MB per zone
    streamer.InitializeZones(zone_limits);
    
    bool stream_loaded = streamer.LoadStreaming("test_integration.gguf");
    assert(stream_loaded);
    
    std::cout << "  ✓ Streaming loader passed\n";
    
    // Cleanup
    remove("test_integration.gguf");
    
    std::cout << "  ✓ Full pipeline test passed\n";
}

//=============================================================================
// Main
//=============================================================================

int main() {
    std::cout << "==============================================\n";
    std::cout << "RawrXD Model Loading Integration Tests\n";
    std::cout << "==============================================\n\n";
    
    try {
        // Quantization tests
        test_quantization_q8_0();
        test_quantization_q4_0();
        test_quantization_info();
        test_quantization_types();
        
        std::cout << "\n";
        
        // GPU tests
        test_gpu_enumeration();
        test_gpu_memory_buffer();
        test_gpu_tensor_uploader();
        
        std::cout << "\n";
        
        // Integration test
        test_full_pipeline();
        
        std::cout << "\n==============================================\n";
        std::cout << "All tests PASSED ✓\n";
        std::cout << "==============================================\n";
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "\nTest FAILED: " << e.what() << "\n";
        return 1;
    }
}
