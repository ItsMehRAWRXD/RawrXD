// ============================================================================
// Test Vulkan Backend Implementation
// ============================================================================

#include "vulkan_backend_implementation.hpp"
#include <iostream>
#include <vector>
#include <cmath>

using namespace transformer;

bool TestRMSNorm() {
    std::cout << "\n=== Test: RMSNorm ===" << std::endl;
    
    auto backend = CreateVulkanBackendComplete();
    if (!backend->Initialize()) {
        std::cerr << "Failed to initialize Vulkan backend" << std::endl;
        return false;
    }
    
    // Test data
    const uint32_t size = 4096;
    std::vector<float> input(size, 1.0f);
    std::vector<float> weights(size, 1.0f);
    std::vector<float> output(size, 0.0f);
    
    // Allocate GPU buffers
    void* d_input = nullptr;
    void* d_weights = nullptr;
    void* d_output = nullptr;
    
    backend->AllocateBuffer(size * sizeof(float), &d_input);
    backend->AllocateBuffer(size * sizeof(float), &d_weights);
    backend->AllocateBuffer(size * sizeof(float), &d_output);
    
    // Upload
    backend->CopyHostToDevice(input.data(), d_input, size * sizeof(float));
    backend->CopyHostToDevice(weights.data(), d_weights, size * sizeof(float));
    
    // Execute (currently CPU fallback)
    backend->RMSNorm(d_input, d_output, d_weights, size, 1e-6f);
    
    // Download
    backend->CopyDeviceToHost(d_output, output.data(), size * sizeof(float));
    
    // Verify
    float expected = 1.0f;  // RMS of all 1s is 1, so output = 1 * 1 * 1 = 1
    bool pass = true;
    for (uint32_t i = 0; i < size; i++) {
        if (std::abs(output[i] - expected) > 1e-5f) {
            std::cerr << "Mismatch at " << i << ": " << output[i] << " vs " << expected << std::endl;
            pass = false;
            break;
        }
    }
    
    if (pass) {
        std::cout << "✅ RMSNorm test PASSED" << std::endl;
    } else {
        std::cout << "❌ RMSNorm test FAILED" << std::endl;
    }
    
    backend->Cleanup();
    return pass;
}

bool TestMatMul() {
    std::cout << "\n=== Test: MatMul ===" << std::endl;
    
    auto backend = CreateVulkanBackendComplete();
    if (!backend->Initialize()) {
        return false;
    }
    
    // Small test: [2, 3] @ [3, 4] = [2, 4]
    const uint32_t m = 2, k = 3, n = 4;
    std::vector<float> A = {1, 2, 3, 4, 5, 6};  // [2, 3]
    std::vector<float> B = {1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1};  // [3, 4]
    std::vector<float> C(m * n, 0.0f);
    
    // Expected: [[4, 2, 1, 5], [10, 5, 4, 11]]
    std::vector<float> expected = {4, 2, 1, 5, 10, 5, 4, 11};
    
    void* d_A = nullptr;
    void* d_B = nullptr;
    void* d_C = nullptr;
    
    backend->AllocateBuffer(A.size() * sizeof(float), &d_A);
    backend->AllocateBuffer(B.size() * sizeof(float), &d_B);
    backend->AllocateBuffer(C.size() * sizeof(float), &d_C);
    
    backend->CopyHostToDevice(A.data(), d_A, A.size() * sizeof(float));
    backend->CopyHostToDevice(B.data(), d_B, B.size() * sizeof(float));
    
    backend->MatMul(d_A, d_B, d_C, m, k, n);
    
    backend->CopyDeviceToHost(d_C, C.data(), C.size() * sizeof(float));
    
    bool pass = true;
    for (size_t i = 0; i < C.size(); i++) {
        if (std::abs(C[i] - expected[i]) > 1e-5f) {
            std::cerr << "Mismatch at " << i << ": " << C[i] << " vs " << expected[i] << std::endl;
            pass = false;
        }
    }
    
    if (pass) {
        std::cout << "✅ MatMul test PASSED" << std::endl;
    } else {
        std::cout << "❌ MatMul test FAILED" << std::endl;
    }
    
    backend->Cleanup();
    return pass;
}

bool TestSoftmax() {
    std::cout << "\n=== Test: Softmax ===" << std::endl;
    
    auto backend = CreateVulkanBackendComplete();
    if (!backend->Initialize()) {
        return false;
    }
    
    std::vector<float> input = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    std::vector<float> output(input.size(), 0.0f);
    
    void* d_input = nullptr;
    void* d_output = nullptr;
    
    backend->AllocateBuffer(input.size() * sizeof(float), &d_input);
    backend->AllocateBuffer(output.size() * sizeof(float), &d_output);
    
    backend->CopyHostToDevice(input.data(), d_input, input.size() * sizeof(float));
    
    backend->Softmax(d_input, d_output, input.size());
    
    backend->CopyDeviceToHost(d_output, output.data(), output.size() * sizeof(float));
    
    // Verify sum = 1
    float sum = 0.0f;
    for (auto v : output) sum += v;
    
    bool pass = std::abs(sum - 1.0f) < 1e-5f;
    
    if (pass) {
        std::cout << "✅ Softmax test PASSED (sum = " << sum << ")" << std::endl;
    } else {
        std::cout << "❌ Softmax test FAILED (sum = " << sum << ")" << std::endl;
    }
    
    backend->Cleanup();
    return pass;
}

int main() {
    std::cout << "================================================================================" << std::endl;
    std::cout << "Vulkan Backend Implementation Test" << std::endl;
    std::cout << "================================================================================" << std::endl;
    
    int passed = 0;
    int total = 0;
    
    total++; if (TestRMSNorm()) passed++;
    total++; if (TestMatMul()) passed++;
    total++; if (TestSoftmax()) passed++;
    
    std::cout << "\n================================================================================" << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "================================================================================" << std::endl;
    
    return (passed == total) ? 0 : 1;
}
