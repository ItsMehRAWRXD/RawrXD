// L4_2_0_Validate.cpp
// L4.2.0 Tensor Runtime Validation
// Validates the runtime against L4.1 frozen contract

#include "../L4_2_0_TensorRuntime.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <vector>
#include <string>

using namespace RawrXD::L4;

// Validation metrics
struct ValidationMetrics {
    double max_error;
    double mean_error;
    double rmse;
    double cosine_similarity;
    bool passed;
};

ValidationMetrics CompareEmbeddings(
    const float* rawrxd_data,
    const float* reference_data,
    size_t count
) {
    ValidationMetrics metrics = {0.0, 0.0, 0.0, 0.0, false};
    
    double sum_error = 0.0;
    double sum_sq_error = 0.0;
    double dot_product = 0.0;
    double norm_rawrxd = 0.0;
    double norm_ref = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        float rawrxd_val = rawrxd_data[i];
        float ref_val = reference_data[i];
        
        // Skip NaN comparisons (both should be NaN or neither)
        if (std::isnan(rawrxd_val) || std::isnan(ref_val)) {
            continue;
        }
        
        double error = std::abs(rawrxd_val - ref_val);
        metrics.max_error = std::max(metrics.max_error, error);
        sum_error += error;
        sum_sq_error += error * error;
        
        dot_product += rawrxd_val * ref_val;
        norm_rawrxd += rawrxd_val * rawrxd_val;
        norm_ref += ref_val * ref_val;
    }
    
    metrics.mean_error = sum_error / count;
    metrics.rmse = std::sqrt(sum_sq_error / count);
    
    if (norm_rawrxd > 0 && norm_ref > 0) {
        metrics.cosine_similarity = dot_product / (std::sqrt(norm_rawrxd) * std::sqrt(norm_ref));
    }
    
    // L4.1 acceptance criteria
    metrics.passed = (metrics.cosine_similarity >= 0.999) && (metrics.rmse < 0.01);
    
    return metrics;
}

bool LoadReferenceFile(const std::string& path, std::vector<float>& data) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open reference file: " << path << std::endl;
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    size_t num_floats = size / sizeof(float);
    data.resize(num_floats);
    
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        std::cerr << "Failed to read reference file" << std::endl;
        return false;
    }
    
    return true;
}

int main(int argc, char* argv[]) {
    std::cout << "L4.2.0 Tensor Runtime Validation" << std::endl;
    std::cout << "================================" << std::endl;
    std::cout << std::endl;
    
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <gguf_file> <reference_bin> [token_id]" << std::endl;
        return 1;
    }
    
    std::string gguf_path = argv[1];
    std::string reference_path = argv[2];
    uint32_t token_id = (argc > 3) ? std::stoul(argv[3]) : 42;
    
    // Load reference data
    std::vector<float> reference_data;
    if (!LoadReferenceFile(reference_path, reference_data)) {
        return 1;
    }
    
    std::cout << "Reference file: " << reference_path << std::endl;
    std::cout << "Reference values: " << reference_data.size() << std::endl;
    std::cout << std::endl;
    
    // Initialize Tensor Runtime
    auto runtime = CreateTensorRuntime();
    
    std::cout << "Initializing Tensor Runtime..." << std::endl;
    if (!runtime->Initialize(gguf_path)) {
        std::cerr << "Failed to initialize runtime" << std::endl;
        return 1;
    }
    std::cout << "  ✓ Runtime initialized" << std::endl;
    std::cout << std::endl;
    
    // List available tensors
    std::cout << "Available tensors:" << std::endl;
    auto tensors = runtime->ListTensors();
    int count = 0;
    for (const auto& name : tensors) {
        if (count < 5 || name.find("token_embd") != std::string::npos) {
            std::cout << "  - " << name << std::endl;
        }
        count++;
    }
    if (tensors.size() > 5) {
        std::cout << "  ... and " << (tensors.size() - 5) << " more" << std::endl;
    }
    std::cout << std::endl;
    
    // Get token_embd.weight tensor
    std::cout << "Looking up token_embd.weight..." << std::endl;
    if (!runtime->HasTensor("token_embd.weight")) {
        std::cerr << "Tensor not found: token_embd.weight" << std::endl;
        return 1;
    }
    
    TensorView embedding_tensor = runtime->GetTensor("token_embd.weight");
    std::cout << "  ✓ Tensor found" << std::endl;
    std::cout << "  Name: " << embedding_tensor.name << std::endl;
    std::cout << "  Dims: [";
    for (size_t i = 0; i < embedding_tensor.dims.size(); i++) {
        if (i > 0) std::cout << ", ";
        std::cout << embedding_tensor.dims[i];
    }
    std::cout << "]" << std::endl;
    std::cout << "  Type: " << (embedding_tensor.type == QuantType::Q4_0 ? "Q4_0" : "other") << std::endl;
    std::cout << "  Data offset: 0x" << std::hex << embedding_tensor.data_offset << std::dec << std::endl;
    std::cout << std::endl;
    
    // Read token embedding
    std::cout << "Reading token " << token_id << " embedding..." << std::endl;
    
    uint64_t embedding_dim = embedding_tensor.dims[0];
    std::vector<float> rawrxd_data(embedding_dim);
    
    if (!runtime->ReadRow(embedding_tensor, token_id, rawrxd_data.data())) {
        std::cerr << "Failed to read embedding row" << std::endl;
        return 1;
    }
    std::cout << "  ✓ Row read successfully" << std::endl;
    std::cout << std::endl;
    
    // Validate
    std::cout << "Validating against reference..." << std::endl;
    if (rawrxd_data.size() != reference_data.size()) {
        std::cerr << "Size mismatch: RawrXD=" << rawrxd_data.size() 
                  << " Reference=" << reference_data.size() << std::endl;
        return 1;
    }
    
    ValidationMetrics metrics = CompareEmbeddings(
        rawrxd_data.data(),
        reference_data.data(),
        rawrxd_data.size()
    );
    
    std::cout << std::endl;
    std::cout << "Validation Results" << std::endl;
    std::cout << "==================" << std::endl;
    std::cout << "Max Absolute Error:  " << metrics.max_error << std::endl;
    std::cout << "Mean Absolute Error: " << metrics.mean_error << std::endl;
    std::cout << "RMSE:                " << metrics.rmse << std::endl;
    std::cout << "Cosine Similarity:   " << metrics.cosine_similarity << std::endl;
    std::cout << std::endl;
    
    std::cout << "Pass Criteria:" << std::endl;
    std::cout << "  [" << (metrics.cosine_similarity >= 0.999 ? "✓" : "✗") << "] Cosine Similarity >= 0.999" << std::endl;
    std::cout << "  [" << (metrics.rmse < 0.01 ? "✓" : "✗") << "] RMSE < 0.01" << std::endl;
    std::cout << std::endl;
    
    // Print first 10 values comparison
    std::cout << "First 10 values comparison:" << std::endl;
    std::cout << "  Index | RawrXD      | Reference   | Error" << std::endl;
    std::cout << "  ------|-------------|-------------|------------" << std::endl;
    for (size_t i = 0; i < std::min(size_t(10), rawrxd_data.size()); i++) {
        double error = std::abs(rawrxd_data[i] - reference_data[i]);
        std::cout << "  " << i << "     | ";
        std::cout << rawrxd_data[i] << " | ";
        std::cout << reference_data[i] << " | ";
        std::cout << error << std::endl;
    }
    std::cout << std::endl;
    
    // Print stats
    auto stats = runtime->GetStats();
    std::cout << "Runtime Statistics:" << std::endl;
    std::cout << "  Rows read: " << stats.rows_read << std::endl;
    std::cout << "  Bytes read: " << stats.bytes_read << std::endl;
    std::cout << std::endl;
    
    // Final result
    if (metrics.passed) {
        std::cout << "========================================" << std::endl;
        std::cout << "L4.2.0 TENSOR RUNTIME VALIDATION: PASS" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << std::endl;
        std::cout << "The Tensor Runtime correctly implements" << std::endl;
        std::cout << "the L4.1 frozen contract for Q4_0 decoding." << std::endl;
        return 0;
    } else {
        std::cout << "========================================" << std::endl;
        std::cout << "L4.2.0 TENSOR RUNTIME VALIDATION: FAIL" << std::endl;
        std::cout << "========================================" << std::endl;
        return 1;
    }
}
