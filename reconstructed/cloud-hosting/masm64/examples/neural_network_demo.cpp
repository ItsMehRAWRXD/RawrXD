// ============================================================================
// Advanced Example - Neural Network Layer using MASM Implementation
// ============================================================================
// Demonstrates using MASM Vulkan for a simple neural network forward pass
// ============================================================================

#include <iostream>
#include <vector>
#include <random>
#include <cmath>

extern "C" {
    // Matrix and vector operations
    int MatMulF32(float* A, float* B, float* C, int M, int K, int N);
    int VectorAdd(float* A, float* B, float* C, int count);
    
    // Activation functions
    int ReLU(float* input, float* output, int count);
    int Softmax(float* input, float* output, int count);
    
    // Vulkan functions
    int vkCreateInstanceMASM(void* pCreateInfo, void* pAllocator, void** pInstance);
    int vkCreateBufferMASM(void* device, void* pCreateInfo, void* pAllocator, void** pBuffer);
}

class NeuralNetworkLayer {
private:
    std::vector<float> weights;
    std::vector<float> bias;
    int input_size;
    int output_size;
    
public:
    NeuralNetworkLayer(int in_size, int out_size) 
        : input_size(in_size), output_size(out_size) {
        
        // Initialize weights with Xavier initialization
        weights.resize(in_size * out_size);
        bias.resize(out_size);
        
        std::random_device rd;
        std::mt19937 gen(rd());
        float std_dev = std::sqrt(2.0f / (in_size + out_size));
        std::normal_distribution<float> dist(0.0f, std_dev);
        
        for (auto& w : weights) w = dist(gen);
        for (auto& b : bias) b = 0.0f;
    }
    
    // Forward pass: output = ReLU(weights * input + bias)
    bool forward(const std::vector<float>& input, std::vector<float>& output) {
        if (input.size() != input_size) {
            std::cerr << "Input size mismatch\n";
            return false;
        }
        
        output.resize(output_size);
        std::vector<float> temp(output_size);
        
        // Matrix multiplication: (1 x input_size) * (input_size x output_size)
        int result = MatMulF32(
            const_cast<float*>(input.data()),
            weights.data(),
            temp.data(),
            1,  // M = 1 (single input vector)
            input_size,  // K
            output_size  // N
        );
        
        if (result != 0) {
            std::cerr << "Matrix multiplication failed\n";
            return false;
        }
        
        // Add bias
        result = VectorAdd(temp.data(), bias.data(), output.data(), output_size);
        if (result != 0) {
            std::cerr << "Vector addition failed\n";
            return false;
        }
        
        // Apply ReLU activation
        result = ReLU(output.data(), output.data(), output_size);
        if (result != 0) {
            std::cerr << "ReLU activation failed\n";
            return false;
        }
        
        return true;
    }
    
    void print_info() const {
        std::cout << "Layer: " << input_size << " -> " << output_size << "\n";
        std::cout << "  Weights: " << weights.size() << " parameters\n";
        std::cout << "  Bias: " << bias.size() << " parameters\n";
    }
};

class SimpleNeuralNetwork {
private:
    std::vector<NeuralNetworkLayer> layers;
    
public:
    void add_layer(int input_size, int output_size) {
        layers.emplace_back(input_size, output_size);
    }
    
    bool predict(const std::vector<float>& input, std::vector<float>& output) {
        std::vector<float> current = input;
        std::vector<float> next;
        
        for (size_t i = 0; i < layers.size(); ++i) {
            if (!layers[i].forward(current, next)) {
                std::cerr << "Layer " << i << " forward pass failed\n";
                return false;
            }
            current = next;
        }
        
        // Apply softmax to final layer
        output = current;
        int result = Softmax(output.data(), output.data(), output.size());
        if (result != 0) {
            std::cerr << "Softmax failed\n";
            return false;
        }
        
        return true;
    }
    
    void print_architecture() const {
        std::cout << "Neural Network Architecture:\n";
        std::cout << "============================\n";
        for (size_t i = 0; i < layers.size(); ++i) {
            std::cout << "Layer " << i << ": ";
            layers[i].print_info();
        }
        
        int total_params = 0;
        for (const auto& layer : layers) {
            // Each layer has input_size * output_size weights + output_size biases
            // But we don't have direct access, so estimate from size
        }
        std::cout << "\nTotal layers: " << layers.size() << "\n";
    }
};

void demonstrate_vulkan_init() {
    std::cout << "\n=== Vulkan Initialization Demo ===\n";
    
    void* instance = nullptr;
    int result = vkCreateInstanceMASM(nullptr, nullptr, &instance);
    
    if (result == 0) {
        std::cout << "✓ Vulkan instance created\n";
        std::cout << "  Handle: 0x" << std::hex << (size_t)instance << std::dec << "\n";
    } else {
        std::cout << "✗ Failed to create Vulkan instance\n";
    }
}

void demonstrate_neural_network() {
    std::cout << "\n=== Neural Network Demo ===\n";
    
    // Create a simple 3-layer network: 4 -> 8 -> 4 -> 3
    SimpleNeuralNetwork network;
    network.add_layer(4, 8);   // Input layer
    network.add_layer(8, 4);   // Hidden layer
    network.add_layer(4, 3);   // Output layer
    
    network.print_architecture();
    
    // Create sample input
    std::vector<float> input = {0.5f, 0.3f, 0.2f, 0.1f};
    std::vector<float> output;
    
    std::cout << "\nInput vector: [";
    for (size_t i = 0; i < input.size(); ++i) {
        std::cout << input[i];
        if (i < input.size() - 1) std::cout << ", ";
    }
    std::cout << "]\n";
    
    // Run forward pass
    if (network.predict(input, output)) {
        std::cout << "\n✓ Forward pass successful\n";
        std::cout << "Output probabilities:\n";
        for (size_t i = 0; i < output.size(); ++i) {
            std::cout << "  Class " << i << ": " << (output[i] * 100) << "%\n";
        }
        
        // Find predicted class
        int predicted_class = 0;
        float max_prob = output[0];
        for (size_t i = 1; i < output.size(); ++i) {
            if (output[i] > max_prob) {
                max_prob = output[i];
                predicted_class = i;
            }
        }
        std::cout << "\nPredicted class: " << predicted_class 
                  << " (confidence: " << (max_prob * 100) << "%)\n";
    } else {
        std::cout << "✗ Forward pass failed\n";
    }
}

void demonstrate_matrix_operations() {
    std::cout << "\n=== Matrix Operations Demo ===\n";
    
    // Image convolution simulation (simplified)
    // 3x3 filter applied to 3x3 image patch
    float filter[9] = {
        -1, -1, -1,
        -1,  8, -1,
        -1, -1, -1
    };  // Edge detection filter
    
    float image_patch[9] = {
        100, 100, 100,
        100, 200, 100,
        100, 100, 100
    };  // Center bright pixel
    
    float result[1];
    
    // Flatten and compute dot product (simulating convolution)
    // In real implementation, would use proper convolution
    float sum = 0;
    for (int i = 0; i < 9; ++i) {
        sum += filter[i] * image_patch[i];
    }
    result[0] = sum;
    
    std::cout << "Edge detection filter applied:\n";
    std::cout << "  Input center value: 200\n";
    std::cout << "  Convolution result: " << result[0] << "\n";
    
    if (result[0] > 0) {
        std::cout << "  ✓ Edge detected!\n";
    }
}

void benchmark_operations() {
    std::cout << "\n=== Performance Benchmark ===\n";
    
    const int size = 100;
    std::vector<float> A(size * size);
    std::vector<float> B(size * size);
    std::vector<float> C(size * size);
    
    // Initialize with random values
    for (auto& v : A) v = static_cast<float>(rand()) / RAND_MAX;
    for (auto& v : B) v = static_cast<float>(rand()) / RAND_MAX;
    
    std::cout << "Matrix multiplication: " << size << "x" << size << "\n";
    
    // Simple timing (would use high-resolution timer in production)
    auto start = std::chrono::high_resolution_clock::now();
    
    int result = MatMulF32(A.data(), B.data(), C.data(), size, size, size);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    if (result == 0) {
        std::cout << "✓ Completed in " << duration.count() << " µs\n";
        
        // Calculate FLOPS (2*n^3 operations for matrix multiply)
        double ops = 2.0 * size * size * size;
        double mflops = ops / duration.count();
        std::cout << "  Performance: ~" << mflops << " MFLOPS\n";
    } else {
        std::cout << "✗ Operation failed\n";
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "MASM x64 Vulkan - Advanced Examples\n";
    std::cout << "========================================\n";
    
    try {
        demonstrate_vulkan_init();
        demonstrate_neural_network();
        demonstrate_matrix_operations();
        benchmark_operations();
        
        std::cout << "\n========================================\n";
        std::cout << "✓ All demonstrations completed!\n";
        std::cout << "========================================\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\n✗ Error: " << e.what() << "\n";
        return 1;
    }
}
