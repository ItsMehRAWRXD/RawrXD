// ============================================================================
// Basic Test - MASM x64 Vulkan Implementation
// ============================================================================
// Demonstrates basic usage of the MASM Vulkan implementation
// ============================================================================

#include <iostream>
#include <cstring>

// External MASM functions
extern "C" {
    // Vulkan Core
    int vkCreateInstanceMASM(void* pCreateInfo, void* pAllocator, void** pInstance);
    int vkEnumeratePhysicalDevicesMASM(void* instance, int* pCount, void** pDevices);
    int vkCreateDeviceMASM(void* physicalDevice, void* pCreateInfo, void* pAllocator, void** pDevice);
    void vkGetDeviceQueueMASM(void* device, int queueFamilyIndex, int queueIndex, void** pQueue);
    
    // Memory Management
    int vkCreateBufferMASM(void* device, void* pCreateInfo, void* pAllocator, void** pBuffer);
    int vkAllocateMemoryMASM(void* device, void* pAllocateInfo, void* pAllocator, void** pMemory);
    int vkBindBufferMemoryMASM(void* device, void* buffer, void* memory, size_t offset);
    
    // Matrix Operations
    int MatMulF32(float* A, float* B, float* C, int M, int K, int N);
    int VectorAdd(float* A, float* B, float* C, int count);
    int VectorScale(float* A, float* B, int count, float scale);
    
    // Activation Functions
    int ReLU(float* input, float* output, int count);
    int GELU(float* input, float* output, int count);
    int Softmax(float* input, float* output, int count);
}

void print_separator(const char* title) {
    std::cout << "\n========================================\n";
    std::cout << title << "\n";
    std::cout << "========================================\n";
}

bool test_vulkan_instance() {
    print_separator("Test 1: Vulkan Instance Creation");
    
    void* instance = nullptr;
    int result = vkCreateInstanceMASM(nullptr, nullptr, &instance);
    
    if (result == 0 && instance != nullptr) {
        std::cout << "✓ Instance created successfully\n";
        std::cout << "  Handle: 0x" << std::hex << (size_t)instance << std::dec << "\n";
        
        // Enumerate devices
        int deviceCount = 0;
        result = vkEnumeratePhysicalDevicesMASM(instance, &deviceCount, nullptr);
        
        if (result == 0) {
            std::cout << "✓ Device enumeration successful\n";
            std::cout << "  Device count: " << deviceCount << "\n";
            return true;
        }
    }
    
    std::cout << "✗ Instance creation failed\n";
    return false;
}

bool test_matrix_multiply() {
    print_separator("Test 2: Matrix Multiplication");
    
    // Test: 2x3 * 3x2 = 2x2
    float A[6] = {1, 2, 3,    // Row 1: [1, 2, 3]
                  4, 5, 6};   // Row 2: [4, 5, 6]
    
    float B[6] = {7, 8,       // Row 1: [7, 8]
                  9, 10,      // Row 2: [9, 10]
                  11, 12};    // Row 3: [11, 12]
    
    float C[4] = {0};
    
    int result = MatMulF32(A, B, C, 2, 3, 2);
    
    if (result == 0) {
        std::cout << "✓ Matrix multiplication successful\n";
        std::cout << "  Result matrix (2x2):\n";
        std::cout << "  [" << C[0] << ", " << C[1] << "]\n";
        std::cout << "  [" << C[2] << ", " << C[3] << "]\n";
        
        // Expected: [58, 64, 139, 154]
        // 1*7 + 2*9 + 3*11 = 7 + 18 + 33 = 58
        // 1*8 + 2*10 + 3*12 = 8 + 20 + 36 = 64
        // 4*7 + 5*9 + 6*11 = 28 + 45 + 66 = 139
        // 4*8 + 5*10 + 6*12 = 32 + 50 + 72 = 154
        
        bool correct = (C[0] == 58.0f && C[1] == 64.0f && 
                       C[2] == 139.0f && C[3] == 154.0f);
        
        if (correct) {
            std::cout << "✓ Results are correct!\n";
            return true;
        } else {
            std::cout << "✗ Results are incorrect\n";
            std::cout << "  Expected: [58, 64, 139, 154]\n";
        }
    }
    
    std::cout << "✗ Matrix multiplication failed\n";
    return false;
}

bool test_vector_operations() {
    print_separator("Test 3: Vector Operations");
    
    float A[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float B[4] = {5.0f, 6.0f, 7.0f, 8.0f};
    float C[4] = {0};
    
    // Test addition
    int result = VectorAdd(A, B, C, 4);
    
    if (result == 0) {
        std::cout << "✓ Vector addition successful\n";
        std::cout << "  A + B = [" << C[0] << ", " << C[1] << ", " 
                  << C[2] << ", " << C[3] << "]\n";
        
        // Expected: [6, 8, 10, 12]
        bool correct = (C[0] == 6.0f && C[1] == 8.0f && 
                       C[2] == 10.0f && C[3] == 12.0f);
        
        if (!correct) {
            std::cout << "✗ Addition results incorrect\n";
            return false;
        }
    } else {
        std::cout << "✗ Vector addition failed\n";
        return false;
    }
    
    // Test scaling
    float scale = 2.0f;
    result = VectorScale(A, C, 4, scale);
    
    if (result == 0) {
        std::cout << "✓ Vector scaling successful\n";
        std::cout << "  A * 2 = [" << C[0] << ", " << C[1] << ", " 
                  << C[2] << ", " << C[3] << "]\n";
        
        // Expected: [2, 4, 6, 8]
        bool correct = (C[0] == 2.0f && C[1] == 4.0f && 
                       C[2] == 6.0f && C[3] == 8.0f);
        
        if (correct) {
            std::cout << "✓ All vector operations passed!\n";
            return true;
        }
    }
    
    std::cout << "✗ Vector scaling failed\n";
    return false;
}

bool test_activation_functions() {
    print_separator("Test 4: Activation Functions");
    
    float input[5] = {-2.0f, -1.0f, 0.0f, 1.0f, 2.0f};
    float output[5] = {0};
    
    // Test ReLU
    int result = ReLU(input, output, 5);
    
    if (result == 0) {
        std::cout << "✓ ReLU activation successful\n";
        std::cout << "  Input:  [" << input[0] << ", " << input[1] << ", " 
                  << input[2] << ", " << input[3] << ", " << input[4] << "]\n";
        std::cout << "  Output: [" << output[0] << ", " << output[1] << ", " 
                  << output[2] << ", " << output[3] << ", " << output[4] << "]\n";
        
        // Expected: [0, 0, 0, 1, 2]
        bool correct = (output[0] == 0.0f && output[1] == 0.0f && 
                       output[2] == 0.0f && output[3] == 1.0f && 
                       output[4] == 2.0f);
        
        if (!correct) {
            std::cout << "✗ ReLU results incorrect\n";
            return false;
        }
    } else {
        std::cout << "✗ ReLU activation failed\n";
        return false;
    }
    
    // Test Softmax
    float softmax_input[3] = {1.0f, 2.0f, 3.0f};
    float softmax_output[3] = {0};
    
    result = Softmax(softmax_input, softmax_output, 3);
    
    if (result == 0) {
        std::cout << "✓ Softmax activation successful\n";
        std::cout << "  Input:  [" << softmax_input[0] << ", " 
                  << softmax_input[1] << ", " << softmax_input[2] << "]\n";
        std::cout << "  Output: [" << softmax_output[0] << ", " 
                  << softmax_output[1] << ", " << softmax_output[2] << "]\n";
        
        // Sum should be approximately 1.0
        float sum = softmax_output[0] + softmax_output[1] + softmax_output[2];
        std::cout << "  Sum: " << sum << " (should be ~1.0)\n";
        
        if (sum > 0.99f && sum < 1.01f) {
            std::cout << "✓ All activation functions passed!\n";
            return true;
        }
    }
    
    std::cout << "✗ Softmax activation failed\n";
    return false;
}

int main() {
    std::cout << "MASM x64 Vulkan Implementation - Test Suite\n";
    std::cout << "============================================\n";
    
    int passed = 0;
    int total = 4;
    
    if (test_vulkan_instance()) passed++;
    if (test_matrix_multiply()) passed++;
    if (test_vector_operations()) passed++;
    if (test_activation_functions()) passed++;
    
    print_separator("Test Results");
    std::cout << "Tests passed: " << passed << "/" << total << "\n";
    
    if (passed == total) {
        std::cout << "\n✓ All tests passed!\n\n";
        return 0;
    } else {
        std::cout << "\n✗ Some tests failed\n\n";
        return 1;
    }
}
