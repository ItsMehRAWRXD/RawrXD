// Test Minimax polynomial for SiLU activation
#include <iostream>
#include <cmath>
#include <iomanip>

int main() {
    std::cout << "Testing Minimax polynomial for SiLU (7th-degree):" << std::endl;
    std::cout << "S(x) = 0.5 + 0.23725*x - 0.01633*x^3 + 0.00043*x^5 - 0.000005*x^7" << std::endl;
    std::cout << "SiLU(x) = x * S(x)" << std::endl;
    std::cout << std::endl;
    
    // Minimax coefficients for sigmoid on [-3, 3]
    const float c0 = 0.5f;
    const float a1 = 0.23725f;
    const float a3 = -0.01633f;
    const float a5 = 0.00043f;
    const float a7 = -0.000005f;
    
    // Test values across the range
    float test_values[] = {-5.0f, -4.0f, -3.5f, -3.0f, -2.5f, -2.0f, -1.5f, -1.0f, -0.5f, 
                           0.0f, 0.5f, 1.0f, 1.5f, 2.0f, 2.5f, 3.0f, 3.5f, 4.0f, 5.0f};
    
    std::cout << "x\t\tSigmoid_true\tSigmoid_poly\tError_sig\tSiLU_true\tSiLU_poly\tError_silu\tStatus" << std::endl;
    std::cout << "----\t\t----------\t-------------\t---------\t--------\t---------\t----------\t------" << std::endl;
    
    double max_error_sigmoid = 0.0;
    double max_error_silu = 0.0;
    
    for (float x : test_values) {
        // True sigmoid
        float sigmoid_true = 1.0f / (1.0f + std::exp(-x));
        
        // Minimax polynomial approximation
        float x2 = x * x;
        float x3 = x2 * x;
        float x5 = x3 * x2;
        float x7 = x5 * x2;
        
        float sigmoid_poly = c0 + a1*x + a3*x3 + a5*x5 + a7*x7;
        
        // SiLU
        float silu_true = x * sigmoid_true;
        float silu_poly = x * sigmoid_poly;
        
        // Errors
        double error_sigmoid = std::abs(sigmoid_true - sigmoid_poly);
        double error_silu = std::abs(silu_true - silu_poly);
        
        // Track max errors
        if (error_sigmoid > max_error_sigmoid) max_error_sigmoid = error_sigmoid;
        if (error_silu > max_error_silu) max_error_silu = error_silu;
        
        // Status
        std::string status = (error_silu < 1e-5) ? "✓" : "✗";
        
        std::cout << std::fixed << std::setprecision(4) << x << "\t\t" 
                  << std::setprecision(6) << sigmoid_true << "\t" 
                  << sigmoid_poly << "\t" 
                  << error_sigmoid << "\t"
                  << silu_true << "\t" 
                  << silu_poly << "\t" 
                  << error_silu << "\t"
                  << status << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "Max error (sigmoid): " << std::scientific << max_error_sigmoid << std::endl;
    std::cout << "Max error (SiLU):    " << std::scientific << max_error_silu << std::endl;
    std::cout << "Target:              1.000000e-05" << std::endl;
    std::cout << "Status:              " << ((max_error_silu < 1e-5) ? "✓ PASS" : "✗ FAIL") << std::endl;
    
    return 0;
}