// ============================================================================
// RawrXD Model Loader - Standalone Implementation (No External Dependencies)
// ============================================================================
// Loads GGUF models and provides tensor access for inference
// Zero external dependencies - pure C++ implementation
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <fstream>
#include <iostream>

namespace rawrxd {
namespace model {

// ============================================================================
// GGUF Format Definitions
// ============================================================================

#pragma pack(push, 1)

struct GGUFHeader {
    uint32_t magic;              // 'GGUF'
    uint32_t version;
    uint64_t tensor_count;
    uint64_t metadata_kv_count;
};

#pragma pack(pop)

enum class GGMLType : uint32_t {
    F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7, Q8_0 = 8, Q8_1 = 9,
    Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13, Q6_K = 14, Q8_K = 15
};

// Tensor information
struct TensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> dimensions;
    uint64_t offset;
    uint64_t size;
    
    uint64_t num_elements() const {
        uint64_t n = 1;
        for (auto d : dimensions) n *= d;
        return n;
    }
    
    bool is_quantized() const {
        return type != GGMLType::F32 && type != GGMLType::F16;
    }
};

// Model architecture info
struct ModelArchitecture {
    std::string name;
    uint32_t vocab_size = 0;
    uint32_t hidden_size = 0;
    uint32_t num_layers = 0;
    uint32_t num_heads = 0;
    uint32_t num_kv_heads = 0;
    uint32_t intermediate_size = 0;
    uint32_t max_position = 0;
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
};

// ============================================================================
// Model Loader Class
// ============================================================================

class ModelLoader {
public:
    ModelLoader();
    ~ModelLoader();
    
    // Load model from GGUF file
    bool Load(const std::string& path);
    
    // Check if model is loaded
    bool IsLoaded() const { return is_loaded_; }
    
    // Get architecture info
    const ModelArchitecture& GetArchitecture() const { return arch_; }
    
    // Get tensor info
    const std::vector<TensorInfo>& GetTensors() const { return tensors_; }
    
    // Get tensor by name
    const TensorInfo* GetTensor(const std::string& name) const;
    
    // Load tensor data as float32 (auto-dequantizes if needed)
    std::vector<float> LoadTensorData(const std::string& name);
    
    // Load raw tensor data
    std::vector<uint8_t> LoadRawTensorData(const TensorInfo& info);
    
    // Get last error
    const std::string& GetLastError() const { return last_error_; }
    
    // Print model info
    void PrintInfo() const;
    
private:
    bool ParseHeader();
    bool ParseMetadata();
    bool ParseTensorInfo();
    uint64_t CalculateTensorSize(const TensorInfo& info) const;
    
    // Dequantization
    void DequantizeQ4_0(const uint8_t* src, float* dst, size_t n);
    void DequantizeQ4_1(const uint8_t* src, float* dst, size_t n);
    void DequantizeQ8_0(const uint8_t* src, float* dst, size_t n);
    float FP16ToFP32(uint16_t h) const;
    
    std::ifstream file_;
    std::string path_;
    std::string last_error_;
    bool is_loaded_ = false;
    
    ModelArchitecture arch_;
    std::vector<TensorInfo> tensors_;
    std::unordered_map<std::string, size_t> tensor_map_;
    
    size_t data_offset_ = 0;
    uint32_t version_ = 0;
};

// ============================================================================
// Simple Tokenizer (BPE-based, minimal implementation)
// ============================================================================

class SimpleTokenizer {
public:
    SimpleTokenizer();
    
    // Load vocabulary from file
    bool LoadVocabulary(const std::string& path);
    
    // Encode text to token IDs
    std::vector<int> Encode(const std::string& text) const;
    
    // Decode token IDs to text
    std::string Decode(const std::vector<int>& tokens) const;
    
    // Get vocab size
    size_t GetVocabSize() const { return vocab_.size(); }
    
private:
    std::vector<std::string> vocab_;
    std::unordered_map<std::string, int> token_to_id_;
};

// ============================================================================
// Inference Context
// ============================================================================

struct InferenceConfig {
    float temperature = 0.7f;
    float top_p = 0.9f;
    int top_k = 40;
    int max_tokens = 256;
    float repetition_penalty = 1.0f;
};

class InferenceContext {
public:
    InferenceContext(ModelLoader* model);
    
    // Initialize for inference
    bool Initialize();
    
    // Run inference
    std::vector<int> Generate(const std::vector<int>& input_tokens, 
                               const InferenceConfig& config);
    
    // Get last error
    const std::string& GetLastError() const { return last_error_; }
    
private:
    ModelLoader* model_;
    std::string last_error_;
    
    // KV cache
    std::vector<float> k_cache_;
    std::vector<float> v_cache_;
    
    // Working buffers
    std::vector<float> hidden_states_;
    std::vector<float> attention_output_;
    
    // Sampling
    int SampleToken(const std::vector<float>& logits, float temperature, 
                    float top_p, int top_k);
    void Softmax(std::vector<float>& values);
    void TopKFilter(std::vector<float>& logits, int k);
    void TopPFilter(std::vector<float>& logits, float p);
};

} // namespace model
} // namespace rawrxd
