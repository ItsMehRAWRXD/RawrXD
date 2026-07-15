#include <iostream>
#include <cstdint>

// Forward declaration of Forward_QKV assembly function
extern "C" int Forward_QKV(
    const float* input,
    const float* Wq,
    const float* Wk,
    const float* Wv,
    float* Q_out,
    float* K_out,
    float* V_out,
    size_t seq_len,
    size_t d_model
);

int main() {
    std::cout << "Testing Forward_QKV assembly router..." << std::endl;
    
    // Simple test: seq_len=2, d_model=2
    const size_t seq_len = 2;
    const size_t d_model = 2;
    
    float input[seq_len * d_model] = {1.0f, 2.0f, 3.0f, 4.0f};          // [2, 2]
    float Wq[d_model * d_model] = {1.0f, 0.0f, 0.0f, 1.0f};            // Identity
    float Wk[d_model * d_model] = {1.0f, 0.0f, 0.0f, 1.0f};           // Identity
    float Wv[d_model * d_model] = {1.0f, 0.0f, 0.0f, 1.0f};           // Identity
    
    float Q_out[seq_len * d_model] = {0};
    float K_out[seq_len * d_model] = {0};
    float V_out[seq_len * d_model] = {0};
    
    int result = Forward_QKV(input, Wq, Wk, Wv, Q_out, K_out, V_out, seq_len, d_model);
    
    std::cout << "Forward_QKV result: " << result << std::endl;
    std::cout << "Q_out: [" << Q_out[0] << ", " << Q_out[1] << ", " << Q_out[2] << ", " << Q_out[3] << "]" << std::endl;
    std::cout << "K_out: [" << K_out[0] << ", " << K_out[1] << ", " << K_out[2] << ", " << K_out[3] << "]" << std::endl;
    std::cout << "V_out: [" << V_out[0] << ", " << V_out[1] << ", " << V_out[2] << ", " << V_out[3] << "]" << std::endl;
    
    return 0;
}