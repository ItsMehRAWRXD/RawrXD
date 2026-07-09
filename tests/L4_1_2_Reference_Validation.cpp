// RawrXD_L4_1_2_Reference_Validation.cpp
// L4.1.2 Numerical Reference Validation
// Compare RawrXD Q4_0 decoder output against llama.cpp reference

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <cmath>
#include <iomanip>

// Validation metrics
struct ValidationMetrics {
    float max_abs_error;
    float mean_abs_error;
    float rmse;
    float cosine_similarity;
    bool passed;
};

// Compute validation metrics between two vectors
ValidationMetrics compute_metrics(const std::vector<float>& a, const std::vector<float>& b) {
    if (a.size() != b.size() || a.empty()) {
        throw std::runtime_error("Vectors must be same non-zero size");
    }
    
    ValidationMetrics metrics = {0.0f, 0.0f, 0.0f, 0.0f, false};
    
    double sum_abs_error = 0.0;
    double sum_sq_error = 0.0;
    double dot_product = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (size_t i = 0; i < a.size(); i++) {
        float error = std::abs(a[i] - b[i]);
        metrics.max_abs_error = std::max(metrics.max_abs_error, error);
        sum_abs_error += error;
        sum_sq_error += error * error;
        
        dot_product += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    
    metrics.mean_abs_error = static_cast<float>(sum_abs_error / a.size());
    metrics.rmse = static_cast<float>(std::sqrt(sum_sq_error / a.size()));
    
    double cos_sim = 0.0;
    if (norm_a > 0 && norm_b > 0) {
        cos_sim = dot_product / (std::sqrt(norm_a) * std::sqrt(norm_b));
    }
    metrics.cosine_similarity = static_cast<float>(cos_sim);
    
    // Pass criteria: high cosine similarity and low RMSE
    metrics.passed = (metrics.cosine_similarity >= 0.999f) && 
                     (metrics.rmse < 0.01f);
    
    return metrics;
}

// Load reference output from file (produced by llama.cpp)
std::vector<float> load_reference(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open reference file: " + path);
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    // Each float is 4 bytes
    size_t num_floats = size / sizeof(float);
    std::vector<float> data(num_floats);
    
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw std::runtime_error("Failed to read reference data");
    }
    
    return data;
}

// Save RawrXD output for comparison
void save_output(const std::string& path, const std::vector<float>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to create output file: " + path);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size() * sizeof(float));
}

void print_report(const ValidationMetrics& metrics, 
                  const std::vector<float>& rawrxd_output,
                  const std::vector<float>& reference_output) {
    std::cout << "\n";
    std::cout << "L4.1.2 Numerical Reference Validation Report" << std::endl;
    std::cout << "=============================================" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Vector Size: " << rawrxd_output.size() << std::endl;
    std::cout << std::endl;
    
    std::cout << "Error Metrics:" << std::endl;
    std::cout << "  Max Absolute Error:  " << std::scientific << metrics.max_abs_error << std::fixed << std::endl;
    std::cout << "  Mean Absolute Error: " << std::scientific << metrics.mean_abs_error << std::fixed << std::endl;
    std::cout << "  RMSE:                " << std::scientific << metrics.rmse << std::fixed << std::endl;
    std::cout << std::endl;
    
    std::cout << "Similarity:" << std::endl;
    std::cout << "  Cosine Similarity:   " << std::setprecision(6) << metrics.cosine_similarity << std::endl;
    std::cout << std::endl;
    
    std::cout << "Pass Criteria:" << std::endl;
    std::cout << "  [ " << (metrics.cosine_similarity >= 0.999f ? "✓" : "✗") << " ] Cosine Similarity >= 0.999" << std::endl;
    std::cout << "  [ " << (metrics.rmse < 0.01f ? "✓" : "✗") << " ] RMSE < 0.01" << std::endl;
    std::cout << std::endl;
    
    std::cout << "First 10 values comparison:" << std::endl;
    std::cout << "  Index | RawrXD      | Reference   | Error" << std::endl;
    std::cout << "  ------|-------------|-------------|------------" << std::endl;
    for (size_t i = 0; i < std::min(size_t(10), rawrxd_output.size()); i++) {
        float err = std::abs(rawrxd_output[i] - reference_output[i]);
        std::cout << "  " << std::setw(5) << i << " | "
                  << std::setw(11) << std::setprecision(6) << rawrxd_output[i] << " | "
                  << std::setw(11) << reference_output[i] << " | "
                  << std::setw(10) << std::scientific << err << std::fixed << std::endl;
    }
    std::cout << std::endl;
    
    std::cout << "Status: " << (metrics.passed ? "PASS" : "FAIL") << std::endl;
    
    if (!metrics.passed) {
        std::cout << "\nNOTE: To generate reference output, run:" << std::endl;
        std::cout << "  llama.cpp: ./embedding_extract model.gguf token_id reference.bin" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "RawrXD L4.1.2 Numerical Reference Validation" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << std::endl;
    
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <rawrxd_output.bin> <reference_output.bin>" << std::endl;
        std::cerr << std::endl;
        std::cerr << "This tool compares RawrXD Q4_0 decoder output against llama.cpp reference." << std::endl;
        std::cerr << "Generate reference with: llama.cpp embedding extraction" << std::endl;
        return 1;
    }
    
    const char* rawrxd_path = argv[1];
    const char* reference_path = argv[2];
    
    try {
        std::cout << "Loading RawrXD output: " << rawrxd_path << std::endl;
        std::vector<float> rawrxd_output = load_reference(rawrxd_path);
        std::cout << "  Loaded " << rawrxd_output.size() << " values" << std::endl;
        
        std::cout << "Loading reference output: " << reference_path << std::endl;
        std::vector<float> reference_output = load_reference(reference_path);
        std::cout << "  Loaded " << reference_output.size() << " values" << std::endl;
        
        if (rawrxd_output.size() != reference_output.size()) {
            std::cerr << "ERROR: Vector sizes don't match!" << std::endl;
            return 1;
        }
        
        std::cout << "\nComputing validation metrics..." << std::endl;
        ValidationMetrics metrics = compute_metrics(rawrxd_output, reference_output);
        
        print_report(metrics, rawrxd_output, reference_output);
        
        return metrics.passed ? 0 : 1;
        
    } catch (const std::exception& e) {
        std::cerr << "\nERROR: " << e.what() << std::endl;
        return 1;
    }
}
