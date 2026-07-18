// generate_test_vectors.cpp
// Generate test vectors for VAL-019 embedding validation

#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <cstring>
#include <cstdint>

int main() {
    // Create embedding_input.bin with test tokens (5 int32 values)
    {
        std::ofstream file("val-019/vectors/embedding_input.bin", std::ios::binary);
        if (!file) {
            std::cerr << "Failed to create embedding_input.bin" << std::endl;
            return 1;
        }
        
        // Write 5 int32 tokens (batch=1, seq=5)
        int32_t tokens[] = {1, 2, 3, 4, 5};
        file.write(reinterpret_cast<const char*>(tokens), sizeof(tokens));
        std::cout << "Created embedding_input.bin (5 tokens)" << std::endl;
    }
    
    // Create embedding_expected.bin with expected embeddings
    // 5 tokens * 4096 dimensions = 20480 float32 values
    // Must match embedding kernel output exactly
    {
        std::ofstream file("val-019/vectors/embedding_expected.bin", std::ios::binary);
        if (!file) {
            std::cerr << "Failed to create embedding_expected.bin" << std::endl;
            return 1;
        }
        
        // Replicate embedding kernel's deterministic weight generation
        // weights[i] = ((seed / 4294967295.0) - 0.5) * 0.02
        // where seed evolves as: seed = seed * 1103515245 + 12345
        const size_t vocab_size = 32000;
        const size_t hidden_dim = 4096;
        std::vector<float> weights(vocab_size * hidden_dim);
        
        uint32_t seed = 42;
        for (size_t i = 0; i < weights.size(); i++) {
            seed = seed * 1103515245 + 12345;
            float r = static_cast<float>(seed) / 4294967295.0f;
            weights[i] = (r - 0.5f) * 0.02f;
        }
        
        // Token IDs: 1, 2, 3, 4, 5
        // Output: 5 * 4096 floats
        int32_t tokens[] = {1, 2, 3, 4, 5};
        const size_t num_tokens = 5;
        std::vector<float> expected_output(num_tokens * hidden_dim);
        
        for (size_t t = 0; t < num_tokens; t++) {
            int32_t token_id = tokens[t];
            size_t weight_offset = token_id * hidden_dim;
            size_t output_offset = t * hidden_dim;
            std::memcpy(&expected_output[output_offset], 
                       &weights[weight_offset], 
                       hidden_dim * sizeof(float));
        }
        
        file.write(reinterpret_cast<const char*>(expected_output.data()), 
                   expected_output.size() * sizeof(float));
        std::cout << "Created embedding_expected.bin (" << expected_output.size() << " floats)" << std::endl;
    }
    
    // Create rmsnorm_input.bin (1 batch, 10 sequence, 4096 hidden)
    // Must match rmsnorm_stage.cpp expected shape: {1, 10, 4096}
    {
        std::ofstream file("val-019/vectors/rmsnorm_input.bin", std::ios::binary);
        if (!file) {
            std::cerr << "Failed to create rmsnorm_input.bin" << std::endl;
            return 1;
        }
        
        // Generate input with small values around 0
        std::mt19937 gen(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        
        const size_t batch = 1;
        const size_t seq = 10;
        const size_t hidden = 4096;
        const size_t num_values = batch * seq * hidden;
        std::vector<float> input_data(num_values);
        
        for (size_t i = 0; i < num_values; i++) {
            input_data[i] = dist(gen);
        }
        
        file.write(reinterpret_cast<const char*>(input_data.data()), 
                   input_data.size() * sizeof(float));
        std::cout << "Created rmsnorm_input.bin (" << num_values << " floats)" << std::endl;
    }
    
    // Create rmsnorm_expected.bin by computing RMSNorm on the input
    {
        std::ofstream file("val-019/vectors/rmsnorm_expected.bin", std::ios::binary);
        if (!file) {
            std::cerr << "Failed to create rmsnorm_expected.bin" << std::endl;
            return 1;
        }
        
        // Replicate RMSNorm kernel computation
        const size_t batch = 1;
        const size_t seq = 10;
        const size_t hidden = 4096;
        const float epsilon = 1e-6f;
        
        // Regenerate input data (same seed as above)
        std::mt19937 gen(42);
        std::normal_distribution<float> dist(0.0f, 0.02f);
        std::vector<float> input_data(batch * seq * hidden);
        for (size_t i = 0; i < input_data.size(); i++) {
            input_data[i] = dist(gen);
        }
        
        // Initialize weights (same as kernel: 1.0 + (i%10 - 4.5) * 0.01)
        std::vector<float> weights(hidden);
        for (size_t i = 0; i < hidden; i++) {
            weights[i] = 1.0f + (static_cast<float>(i % 10) - 4.5f) * 0.01f;
        }
        
        // Compute RMSNorm
        std::vector<float> output_data(batch * seq * hidden);
        for (size_t b = 0; b < batch; b++) {
            for (size_t s = 0; s < seq; s++) {
                // Compute RMS for this token
                float sum_squares = 0.0f;
                for (size_t h = 0; h < hidden; h++) {
                    size_t idx = (b * seq + s) * hidden + h;
                    float val = input_data[idx];
                    sum_squares += val * val;
                }
                
                float mean_square = sum_squares / static_cast<float>(hidden);
                float rms = std::sqrt(mean_square + epsilon);
                
                // Normalize and scale
                for (size_t h = 0; h < hidden; h++) {
                    size_t idx = (b * seq + s) * hidden + h;
                    float normalized = input_data[idx] / rms;
                    output_data[idx] = normalized * weights[h];
                }
            }
        }
        
        file.write(reinterpret_cast<const char*>(output_data.data()), 
                   output_data.size() * sizeof(float));
        std::cout << "Created rmsnorm_expected.bin (" << output_data.size() << " floats)" << std::endl;
    }
    
    std::cout << "All test vectors generated successfully!" << std::endl;
    return 0;
}
