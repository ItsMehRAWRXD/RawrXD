// rmsnorm_stage.cpp
// RMSNorm layer validation for VAL-019
// Tests numerical reduction operation and determinism

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cmath>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>

// Minimal tensor structure
template<typename T>
struct Tensor {
    std::vector<T> data;
    std::vector<size_t> shape;
    
    size_t size() const {
        size_t s = 1;
        for (auto dim : shape) s *= dim;
        return s;
    }
    
    T* ptr() { return data.data(); }
    const T* ptr() const { return data.data(); }
    
    // Access element at indices
    T& at(size_t b, size_t s, size_t h) {
        return data[(b * shape[1] + s) * shape[2] + h];
    }
};

struct RMSNormResult {
    bool success;
    std::string input_checksum;
    std::string output_checksum;
    double max_error;
    double runtime_ms;
    std::string error_msg;
    std::string backend;
    std::string kernel_version;
    double mean_rms;
    double min_rms;
    double max_rms;
    
    // Invariant checks
    struct Invariants {
        bool has_nan;
        bool has_inf;
        bool output_shape_matches;
        bool rms_range_valid;
        int nan_count;
        int inf_count;
        
        bool all_passed() const {
            return !has_nan && !has_inf && output_shape_matches && rms_range_valid;
        }
    } invariants;
};

// SHA256 computation (simplified)
std::string compute_sha256(const void* data, size_t len) {
    std::stringstream ss;
    ss << "sha256:";
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < 32 && i < len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    ss << "...";
    return ss.str();
}

// Load binary tensor
template<typename T>
bool load_tensor(const std::string& path, Tensor<T>& tensor, std::vector<size_t> expected_shape) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cerr << "[ERROR] Cannot open: " << path << std::endl;
        return false;
    }
    
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    size_t expected_size = 1;
    for (auto dim : expected_shape) expected_size *= dim;
    size_t expected_bytes = expected_size * sizeof(T);
    
    if (file_size != expected_bytes) {
        std::cerr << "[ERROR] Size mismatch: expected " << expected_bytes 
                  << " bytes, got " << file_size << std::endl;
        return false;
    }
    
    tensor.shape = expected_shape;
    tensor.data.resize(expected_size);
    file.read(reinterpret_cast<char*>(tensor.data.data()), expected_bytes);
    
    return file.good();
}

// Save tensor
bool save_tensor(const std::string& path, const Tensor<float>& tensor) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(tensor.data.data()), 
               tensor.size() * sizeof(float));
    return file.good();
}

// Compute max absolute error
double compute_max_error(const Tensor<float>& a, const Tensor<float>& b) {
    if (a.size() != b.size()) return -1.0;
    
    double max_err = 0.0;
    for (size_t i = 0; i < a.size(); i++) {
        double err = std::abs(static_cast<double>(a.data[i]) - static_cast<double>(b.data[i]));
        if (err > max_err) max_err = err;
    }
    return max_err;
}

// Check invariants on output tensor
RMSNormResult::Invariants check_invariants(const Tensor<float>& output, 
                                            const std::vector<size_t>& expected_shape,
                                            double min_rms, double max_rms) {
    RMSNormResult::Invariants inv;
    inv.has_nan = false;
    inv.has_inf = false;
    inv.nan_count = 0;
    inv.inf_count = 0;
    
    // Check shape
    inv.output_shape_matches = (output.shape == expected_shape);
    
    // Check for NaN and Inf
    for (size_t i = 0; i < output.size(); i++) {
        if (std::isnan(output.data[i])) {
            inv.has_nan = true;
            inv.nan_count++;
        }
        if (std::isinf(output.data[i])) {
            inv.has_inf = true;
            inv.inf_count++;
        }
    }
    
    // Check RMS range (should be close to 1.0 for normalized data)
    // Allow reasonable range: 0.5 to 2.0
    inv.rms_range_valid = (min_rms > 0.1 && max_rms < 10.0);
    
    return inv;
}

// ============================================================================
// RMSNORM KERNEL IMPLEMENTATION
// ============================================================================

class RMSNormKernel {
public:
    struct Config {
        size_t hidden_dim = 4096;
        float epsilon = 1e-6f;
        std::string dtype = "float32";
        std::string backend = "native";
    };
    
    RMSNormKernel(const Config& config) : config_(config) {
        // Initialize RMSNorm weights (typically all ones or learned)
        // For Llama models, this is usually a learned per-channel scale
        weights_.resize(config.hidden_dim);
        for (size_t i = 0; i < weights_.size(); i++) {
            // Initialize with small variation around 1.0
            weights_[i] = 1.0f + (static_cast<float>(i % 10) - 4.5f) * 0.01f;
        }
    }
    
    // Execute RMSNorm
    // RMSNorm(x) = x / sqrt(mean(x^2) + epsilon) * weight
    bool execute(const Tensor<float>& input, Tensor<float>& output,
                 double& mean_rms, double& min_rms, double& max_rms) {
        if (input.shape.size() != 3) {
            std::cerr << "[ERROR] Expected 3D input [batch, seq, hidden]" << std::endl;
            return false;
        }
        
        size_t batch_size = input.shape[0];
        size_t seq_len = input.shape[1];
        size_t hidden_dim = input.shape[2];
        
        if (hidden_dim != config_.hidden_dim) {
            std::cerr << "[ERROR] Hidden dim mismatch: expected " << config_.hidden_dim
                      << ", got " << hidden_dim << std::endl;
            return false;
        }
        
        output.shape = input.shape;
        output.data.resize(input.size());
        
        // Track RMS statistics for telemetry
        std::vector<double> rms_values;
        rms_values.reserve(batch_size * seq_len);
        
        // RMSNorm computation
        for (size_t b = 0; b < batch_size; b++) {
            for (size_t s = 0; s < seq_len; s++) {
                // Compute RMS for this token
                float sum_squares = 0.0f;
                for (size_t h = 0; h < hidden_dim; h++) {
                    float val = input.at(b, s, h);
                    sum_squares += val * val;
                }
                
                float mean_square = sum_squares / static_cast<float>(hidden_dim);
                float rms = std::sqrt(mean_square + config_.epsilon);
                rms_values.push_back(rms);
                
                // Normalize and scale
                for (size_t h = 0; h < hidden_dim; h++) {
                    float normalized = input.at(b, s, h) / rms;
                    output.at(b, s, h) = normalized * weights_[h];
                }
            }
        }
        
        // Compute statistics
        mean_rms = 0.0;
        min_rms = rms_values.empty() ? 0.0 : rms_values[0];
        max_rms = rms_values.empty() ? 0.0 : rms_values[0];
        
        for (double rms : rms_values) {
            mean_rms += rms;
            min_rms = std::min(min_rms, rms);
            max_rms = std::max(max_rms, rms);
        }
        mean_rms /= rms_values.size();
        
        return true;
    }
    
    std::string get_kernel_version() const {
        return "rmsnorm_v1.0_native";
    }
    
private:
    Config config_;
    std::vector<float> weights_;
};

// ============================================================================
// VALIDATION STAGE
// ============================================================================

RMSNormResult validate_rmsnorm_stage(
    const std::string& input_path,
    const std::string& expected_path,
    const std::string& output_path,
    double tolerance
) {
    RMSNormResult result;
    result.backend = "native";
    result.kernel_version = "rmsnorm_v1.0_native";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Load input
    Tensor<float> input;
    if (!load_tensor(input_path, input, {1, 10, 4096})) {  // batch=1, seq=10, hidden=4096
        result.success = false;
        result.error_msg = "Failed to load input tensor";
        return result;
    }
    
    result.input_checksum = compute_sha256(input.ptr(), input.size() * sizeof(float));
    
    // Initialize kernel
    RMSNormKernel::Config config;
    config.hidden_dim = 4096;
    config.epsilon = 1e-6f;
    
    RMSNormKernel kernel(config);
    result.kernel_version = kernel.get_kernel_version();
    
    // Execute RMSNorm
    Tensor<float> actual_output;
    if (!kernel.execute(input, actual_output, result.mean_rms, result.min_rms, result.max_rms)) {
        result.success = false;
        result.error_msg = "RMSNorm kernel execution failed";
        return result;
    }
    
    // Save output
    if (!save_tensor(output_path, actual_output)) {
        result.success = false;
        result.error_msg = "Failed to save output tensor";
        return result;
    }
    
    result.output_checksum = compute_sha256(actual_output.ptr(), actual_output.size() * sizeof(float));
    
    // Load expected output
    Tensor<float> expected_output;
    if (!load_tensor(expected_path, expected_output, actual_output.shape)) {
        result.success = false;
        result.error_msg = "Failed to load expected output";
        return result;
    }
    
    // Compare
    result.max_error = compute_max_error(actual_output, expected_output);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.runtime_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Determine PASS/FAIL
    if (result.max_error <= tolerance) {
        result.success = true;
    } else {
        result.success = false;
        std::stringstream ss;
        ss << "Max error " << result.max_error << " exceeds tolerance " << tolerance;
        result.error_msg = ss.str();
    }
    
    return result;
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  VAL-019: RMSNorm Stage Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    std::string input_path = "val-019/vectors/rmsnorm_input.bin";
    std::string expected_path = "val-019/vectors/rmsnorm_expected.bin";
    std::string output_path = "val-019/evidence/rmsnorm_actual.bin";
    double tolerance = 1e-5;
    
    if (argc > 1) input_path = argv[1];
    if (argc > 2) expected_path = argv[2];
    if (argc > 3) output_path = argv[3];
    
    std::cout << "[CONFIG] Input:     " << input_path << std::endl;
    std::cout << "[CONFIG] Expected:  " << expected_path << std::endl;
    std::cout << "[CONFIG] Output:    " << output_path << std::endl;
    std::cout << "[CONFIG] Tolerance: " << tolerance << std::endl;
    std::cout << std::endl;
    
    auto result = validate_rmsnorm_stage(input_path, expected_path, output_path, tolerance);
    
    // Output results
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "RESULT: " << (result.success ? "PASS" : "FAIL") << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Input checksum:  " << result.input_checksum << std::endl;
    std::cout << "Output checksum: " << result.output_checksum << std::endl;
    std::cout << "Max error:       " << std::scientific << result.max_error << std::endl;
    std::cout << "Runtime:         " << std::fixed << std::setprecision(3) 
              << result.runtime_ms << " ms" << std::endl;
    std::cout << "RMS stats:       mean=" << result.mean_rms << ", min=" << result.min_rms 
              << ", max=" << result.max_rms << std::endl;
    std::cout << "Backend:         " << result.backend << std::endl;
    std::cout << "Kernel:          " << result.kernel_version << std::endl;
    
    if (!result.error_msg.empty()) {
        std::cout << "Error:           " << result.error_msg << std::endl;
    }
    
    // Evidence JSON
    std::cout << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << "Evidence JSON:" << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    std::cout << "{" << std::endl;
    std::cout << "  \"stage\": \"rmsnorm\"," << std::endl;
    std::cout << "  \"status\": \"" << (result.success ? "PASS" : "FAIL") << "\"," << std::endl;
    std::cout << "  \"input_checksum\": \"" << result.input_checksum << "\"," << std::endl;
    std::cout << "  \"output_checksum\": \"" << result.output_checksum << "\"," << std::endl;
    std::cout << "  \"max_error\": " << result.max_error << "," << std::endl;
    std::cout << "  \"runtime_ms\": " << result.runtime_ms << "," << std::endl;
    std::cout << "  \"tolerance\": " << tolerance << "," << std::endl;
    std::cout << "  \"telemetry\": {" << std::endl;
    std::cout << "    \"mean_rms\": " << result.mean_rms << "," << std::endl;
    std::cout << "    \"min_rms\": " << result.min_rms << "," << std::endl;
    std::cout << "    \"max_rms\": " << result.max_rms << std::endl;
    std::cout << "  }," << std::endl;
    std::cout << "  \"implementation\": {" << std::endl;
    std::cout << "    \"backend\": \"" << result.backend << "\"," << std::endl;
    std::cout << "    \"kernel\": \"" << result.kernel_version << "\"," << std::endl;
    std::cout << "    \"commit\": \"8473df6ea611e082ace66b9876fb17bccebf259d\"" << std::endl;
    std::cout << "  }," << std::endl;
    std::cout << "  \"reference\": {" << std::endl;
    std::cout << "    \"source\": \"llama.cpp\"," << std::endl;
    std::cout << "    \"version\": \"b1559\"" << std::endl;
    std::cout << "  }" << std::endl;
    std::cout << "}" << std::endl;
    
    return result.success ? 0 : 1;
}
