// Debug FAST_EXP2 macro
#include <iostream>
#include <cmath>
#include <immintrin.h>
#include <fstream>
#include <cstdint>
#include <cstring>

// Manual implementation of FAST_EXP2 for debugging
void debug_fast_exp2(float* input, float* output, size_t count) {
    std::ofstream log("fast_exp2_debug.txt");
    log << "Debugging FAST_EXP2 macro..." << std::endl;
    
    for (size_t i = 0; i < count && i < 10; ++i) {
        float x = input[i];
        log << "Input x[" << i << "] = " << x << std::endl;
        
        // Step 1: Range reduction
        float I = std::floor(x);
        float F = x - I;
        log << "  I = floor(x) = " << I << std::endl;
        log << "  F = x - I = " << F << std::endl;
        
        // Step 2: Polynomial approximation
        float p4 = 0.00961813f;
        float p3 = 0.05550411f;
        float p2 = 0.24022650f;
        float p1 = 0.69314718f;
        
        float poly = (((p4*F + p3)*F + p2)*F + p1)*F + 1.0f;
        log << "  P(F) = " << poly << std::endl;
        
        // Step 3: Exponent reconstruction
        int I_int = static_cast<int>(I);
        log << "  I_int = " << I_int << std::endl;
        
        // IEEE 754 exponent manipulation
        uint32_t exp_bits = static_cast<uint32_t>(I_int + 127) << 23;
        float two_pow_I;
        memcpy(&two_pow_I, &exp_bits, sizeof(float));
        log << "  2^I = " << two_pow_I << std::endl;
        
        // Step 4: Combine
        float result = poly * two_pow_I;
        log << "  Result = P(F) * 2^I = " << result << std::endl;
        
        // Compare with true exp
        float true_exp = std::exp(x);
        log << "  True exp(x) = " << true_exp << std::endl;
        log << "  Error = " << std::abs(result - true_exp) << std::endl;
        log << std::endl;
        
        output[i] = result;
    }
    
    log.close();
}

int main() {
    std::cout << "Debugging FAST_EXP2 macro..." << std::endl;
    
    // Test values
    const size_t count = 10;
    float input[count] = {-5.0f, -4.0f, -3.0f, -2.0f, -1.0f, 0.0f, 1.0f, 2.0f, 3.0f, 4.0f};
    float output[count];
    
    debug_fast_exp2(input, output, count);
    
    std::cout << "Debug output written to fast_exp2_debug.txt" << std::endl;
    
    std::cout << "\nResults:" << std::endl;
    for (size_t i = 0; i < count; ++i) {
        std::cout << "  input[" << i << "] = " << input[i] << ", output[" << i << "] = " << output[i] << std::endl;
    }
    
    return 0;
}